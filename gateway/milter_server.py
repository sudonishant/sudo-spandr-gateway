"""
High-Throughput Postfix / Sendmail Milter Protocol Server for SUDO SPANDR ESG.
Implements the binary Milter wire protocol over TCP and Unix Domain sockets with zero C-dependencies.
"""

from __future__ import annotations
import asyncio
import logging
import os
import struct
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from gateway.config import settings
from gateway.engine.inspector import GatewayInspector, InspectionResult
from gateway.quarantine import QuarantineVault, vault
from gateway.smtp_proxy import metrics
from gateway.webhook import async_dispatch_webhook

logger = logging.getLogger("sudospandr.gateway.milter")

# Milter Command Constants (Sendmail / Postfix wire protocol)
SMFIC_OPTNEG = b"O"
SMFIC_MACRO = b"D"
SMFIC_CONNECT = b"C"
SMFIC_HELO = b"H"
SMFIC_MAIL = b"M"
SMFIC_RCPT = b"R"
SMFIC_HEADER = b"L"
SMFIC_EOH = b"N"
SMFIC_BODY = b"B"
SMFIC_EOM = b"E"
SMFIC_ABORT = b"A"
SMFIC_QUIT = b"Q"

# Milter Response Codes
SMFIS_CONTINUE = b"c"
SMFIS_REJECT = b"r"
SMFIS_DISCARD = b"d"
SMFIS_ACCEPT = b"a"
SMFIS_TEMPFAIL = b"t"

# Milter Action Codes
SMFIR_ADDHEADER = b"h"
SMFIR_CHGHEADER = b"m"
SMFIR_QUARANTINE = b"q"


class MilterProtocolSession:
    """Handles an individual binary Milter connection from Postfix."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        inspector: GatewayInspector,
        vault_ref: QuarantineVault
    ):
        self.reader = reader
        self.writer = writer
        self.inspector = inspector
        self.vault = vault_ref
        peer = writer.get_extra_info("peername")
        self.client_ip = peer[0] if isinstance(peer, tuple) and peer else "127.0.0.1"

        self.sender: str = ""
        self.recipients: List[str] = []
        self.headers: Dict[str, str] = {}
        self.raw_headers_list: List[tuple] = []
        self.body_chunks: List[bytes] = []
        self.subject: str = ""

    async def _send_packet(self, cmd: bytes, payload: bytes = b""):
        packet_len = len(cmd) + len(payload)
        header = struct.pack("!I", packet_len)
        self.writer.write(header + cmd + payload)
        await self.writer.drain()

    async def _read_packet(self) -> Optional[tuple[bytes, bytes]]:
        try:
            len_bytes = await self.reader.readexactly(4)
            packet_len = struct.unpack("!I", len_bytes)[0]
            if packet_len == 0:
                return None
            data = await self.reader.readexactly(packet_len)
            cmd = data[0:1]
            payload = data[1:]
            return cmd, payload
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None

    async def handle(self):
        try:
            while True:
                packet = await self._read_packet()
                if not packet:
                    break

                cmd, payload = packet

                if cmd == SMFIC_OPTNEG:
                    # Negotiate options with Postfix
                    # Version (4 bytes) + Actions (4 bytes) + Protocol Steps (4 bytes)
                    # Actions: SMFIF_ADDHDRS (0x01) | SMFIF_CHGHDRS (0x02) | SMFIF_QUARANTINE (0x20)
                    actions = 0x01 | 0x02 | 0x20
                    # Steps: All standard steps enabled
                    steps = 0x00
                    resp_payload = struct.pack("!III", 6, actions, steps)
                    await self._send_packet(SMFIC_OPTNEG, resp_payload)

                elif cmd == SMFIC_CONNECT:
                    # Connection metadata
                    await self._send_packet(SMFIS_CONTINUE)

                elif cmd == SMFIC_HELO:
                    await self._send_packet(SMFIS_CONTINUE)

                elif cmd == SMFIC_MAIL:
                    # Sender address null-terminated
                    parts = payload.split(b"\x00")
                    if parts:
                        self.sender = parts[0].decode("utf-8", errors="ignore").strip("<>")
                    await self._send_packet(SMFIS_CONTINUE)

                elif cmd == SMFIC_RCPT:
                    # Recipient address null-terminated
                    parts = payload.split(b"\x00")
                    if parts:
                        rcpt = parts[0].decode("utf-8", errors="ignore").strip("<>")
                        self.recipients.append(rcpt)
                    await self._send_packet(SMFIS_CONTINUE)

                elif cmd == SMFIC_HEADER:
                    # Header name \0 value \0
                    parts = payload.split(b"\x00")
                    if len(parts) >= 2:
                        h_name = parts[0].decode("utf-8", errors="ignore")
                        h_val = parts[1].decode("utf-8", errors="ignore")
                        self.headers[h_name.lower()] = h_val
                        self.raw_headers_list.append((h_name, h_val))
                        if h_name.lower() == "subject":
                            self.subject = h_val
                    await self._send_packet(SMFIS_CONTINUE)

                elif cmd == SMFIC_EOH:
                    await self._send_packet(SMFIS_CONTINUE)

                elif cmd == SMFIC_BODY:
                    self.body_chunks.append(payload)
                    await self._send_packet(SMFIS_CONTINUE)

                elif cmd == SMFIC_EOM:
                    # End of message - run full triage!
                    body_text = b"".join(self.body_chunks).decode("utf-8", errors="ignore")
                    rcpt_str = ", ".join(self.recipients)

                    inspection = self.inspector.inspect(
                        sender=self.sender,
                        recipient=rcpt_str,
                        subject=self.subject,
                        body=body_text,
                        headers=self.headers,
                        client_ip=self.client_ip
                    )

                    # Update operational metrics
                    metrics.record(inspection, self.client_ip, self.sender, rcpt_str)

                    # Webhook alert if threshold met
                    if inspection.threat_score >= settings.WEBHOOK_MIN_SCORE:
                        asyncio.create_task(async_dispatch_webhook(asdict(inspection)))

                    # Policy Enforcement via Milter Protocol
                    if inspection.policy_action == "REJECT":
                        if settings.AUTO_QUARANTINE_HIGH_RISK:
                            raw_reconstructed = f"From: {self.sender}\nTo: {rcpt_str}\nSubject: {self.subject}\n\n{body_text}".encode("utf-8")
                            self.vault.store(
                                case_id=inspection.case_id,
                                raw_eml_bytes=raw_reconstructed,
                                sender=self.sender,
                                recipient=rcpt_str,
                                subject=self.subject,
                                threat_score=inspection.threat_score,
                                category=inspection.category,
                                findings=inspection.findings,
                                auth_summary=inspection.auth_summary,
                                client_ip=self.client_ip
                            )
                        # Hard reject in Postfix Milter
                        await self._send_packet(SMFIS_REJECT)

                    elif inspection.policy_action == "QUARANTINE":
                        raw_reconstructed = f"From: {self.sender}\nTo: {rcpt_str}\nSubject: {self.subject}\n\n{body_text}".encode("utf-8")
                        self.vault.store(
                            case_id=inspection.case_id,
                            raw_eml_bytes=raw_reconstructed,
                            sender=self.sender,
                            recipient=rcpt_str,
                            subject=self.subject,
                            threat_score=inspection.threat_score,
                            category=inspection.category,
                            findings=inspection.findings,
                            auth_summary=inspection.auth_summary,
                            client_ip=self.client_ip
                        )
                        # Milter quarantine action
                        quar_reason = f"Quarantined by SUDO SPANDR ESG: Score {inspection.threat_score}/100\x00".encode("utf-8")
                        await self._send_packet(SMFIR_QUARANTINE, quar_reason)
                        await self._send_packet(SMFIS_CONTINUE)

                    elif inspection.policy_action == "TAG_SUBJECT":
                        # Add headers
                        for hk, hv in inspection.headers_to_add.items():
                            hdr_payload = f"{hk}\x00{hv}\x00".encode("utf-8")
                            await self._send_packet(SMFIR_ADDHEADER, hdr_payload)

                        # Quarantine tag reason
                        quar_reason = f"Suspicious threat score {inspection.threat_score}/100\x00".encode("utf-8")
                        await self._send_packet(SMFIR_QUARANTINE, quar_reason)
                        await self._send_packet(SMFIS_CONTINUE)

                    else:  # ACCEPT / Clean
                        # Inject clean forensic headers
                        for hk, hv in inspection.headers_to_add.items():
                            hdr_payload = f"{hk}\x00{hv}\x00".encode("utf-8")
                            await self._send_packet(SMFIR_ADDHEADER, hdr_payload)
                        await self._send_packet(SMFIS_CONTINUE)

                    # Reset buffers for next message
                    self.sender = ""
                    self.recipients = []
                    self.headers = {}
                    self.body_chunks = []
                    self.subject = ""

                elif cmd in [SMFIC_ABORT, SMFIC_QUIT]:
                    break
        except Exception as e:
            logger.error(f"Milter protocol error from {self.client_ip}: {e}")
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass


class AsyncMilterServer:
    """Asynchronous Postfix Milter Protocol Server."""

    def __init__(
        self,
        host: str = settings.MILTER_LISTEN_HOST,
        port: int = settings.MILTER_LISTEN_PORT,
        socket_path: Optional[str] = None,
        inspector: Optional[GatewayInspector] = None,
        vault_ref: Optional[QuarantineVault] = None
    ):
        self.host = host
        self.port = port
        self.socket_path = socket_path or settings.MILTER_SOCKET_PATH
        self.inspector = inspector or GatewayInspector()
        self.vault = vault_ref or vault
        self.tcp_server: Optional[asyncio.Server] = None
        self.unix_server: Optional[asyncio.Server] = None

    async def _client_cb(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session = MilterProtocolSession(reader, writer, self.inspector, self.vault)
        await session.handle()

    async def start(self):
        # Start TCP Socket Server
        self.tcp_server = await asyncio.start_server(
            self._client_cb,
            self.host,
            self.port
        )
        logger.info(f"[SUDO SPANDR Milter] Listening on TCP {self.host}:{self.port} (Postfix: inet:localhost:{self.port})")

    async def stop(self):
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            logger.info("[SUDO SPANDR Milter] TCP server stopped.")
