"""
Asynchronous RFC 5321 Transparent SMTP Proxy / MTA Mail Flow Interceptor for Cyber Squad ESG.
Built on Python asyncio for ultra-high throughput without external C-extensions.
"""

from __future__ import annotations
import asyncio
import collections
import email
import email.policy
import logging
import smtplib
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Set

from gateway.config import settings
from gateway.engine.inspector import GatewayInspector, InspectionResult
from gateway.quarantine import QuarantineVault, vault
from gateway.webhook import async_dispatch_webhook

logger = logging.getLogger("cybersquad.gateway.smtp")


class GatewayMetrics:
    """Thread-safe real-time operational and threat metrics."""
    def __init__(self):
        self.total_scanned: int = 0
        self.clean_count: int = 0
        self.tagged_count: int = 0
        self.quarantined_count: int = 0
        self.rejected_count: int = 0
        self.total_latency_ms: float = 0.0
        self.recent_events: Deque[Dict[str, Any]] = collections.deque(maxlen=100)
        self.event_subscribers: Set[asyncio.Queue] = set()

    def record(self, inspection: InspectionResult, client_ip: str, sender: str, recipient: str):
        self.total_scanned += 1
        self.total_latency_ms += inspection.scan_time_ms

        if inspection.policy_action == "REJECT":
            self.rejected_count += 1
        elif inspection.policy_action == "QUARANTINE":
            self.quarantined_count += 1
        elif inspection.policy_action == "TAG_SUBJECT":
            self.tagged_count += 1
        else:
            self.clean_count += 1

        event = {
            "case_id": inspection.case_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip,
            "sender": sender,
            "recipient": recipient,
            "subject": inspection.original_subject,
            "threat_score": inspection.threat_score,
            "verdict": inspection.verdict,
            "policy_action": inspection.policy_action,
            "category": inspection.category,
            "scan_time_ms": inspection.scan_time_ms,
            "evaluator": inspection.evaluated_by,
            "findings_count": len(inspection.findings)
        }
        self.recent_events.appendleft(event)

        # Notify active WebSocket / SSE subscribers
        for q in list(self.event_subscribers):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def get_stats(self) -> Dict[str, Any]:
        avg_latency = round(self.total_latency_ms / max(1, self.total_scanned), 2)
        return {
            "total_scanned": self.total_scanned,
            "clean_count": self.clean_count,
            "tagged_count": self.tagged_count,
            "quarantined_count": self.quarantined_count,
            "rejected_count": self.rejected_count,
            "avg_latency_ms": avg_latency,
            "recent_events": list(self.recent_events)
        }


metrics = GatewayMetrics()


class SMTPProxySession:
    """Handles an individual inbound SMTP client connection."""

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
        self.client_ip = peer[0] if peer else "127.0.0.1"

        self.helo_name: str = ""
        self.mail_from: str = ""
        self.rcpt_to: List[str] = []
        self.in_data_mode: bool = False

    async def send_line(self, line: str):
        self.writer.write(f"{line}\r\n".encode("utf-8"))
        await self.writer.drain()

    def _modify_and_relay(self, raw_eml_bytes: bytes, inspection: InspectionResult) -> bool:
        """Injects forensic headers and relays message to downstream MTA."""
        try:
            msg = email.message_from_bytes(raw_eml_bytes, policy=email.policy.default)

            # Inject forensic headers
            for hdr_k, hdr_v in inspection.headers_to_add.items():
                msg[hdr_k] = hdr_v

            # Modify subject if tagged
            if inspection.modified_subject:
                if "Subject" in msg:
                    del msg["Subject"]
                msg["Subject"] = inspection.modified_subject

            modified_bytes = msg.as_bytes()

            # Async relay to downstream mail server
            with smtplib.SMTP(settings.SMTP_RELAY_HOST, settings.SMTP_RELAY_PORT, timeout=10.0) as relay_client:
                relay_client.sendmail(self.mail_from, self.rcpt_to, modified_bytes)
            return True
        except Exception as e:
            logger.warning(f"Downstream relay to {settings.SMTP_RELAY_HOST}:{settings.SMTP_RELAY_PORT} unavailable or failed: {e}")
            return False

    async def handle(self):
        try:
            await self.send_line(settings.SMTP_BANNER)

            while True:
                line_bytes = await self.reader.readline()
                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="ignore").rstrip("\r\n")
                cmd = line.split(" ", 1)[0].upper() if line else ""
                arg = line.split(" ", 1)[1] if " " in line else ""

                if cmd == "QUIT":
                    await self.send_line("221 2.0.0 Cyber Squad ESG closing connection. Bye.")
                    break
                elif cmd in ["HELO", "EHLO"]:
                    self.helo_name = arg.strip()
                    await self.send_line("250-cybersquad-esg.local Hello")
                    await self.send_line("250-SIZE 26214400")
                    await self.send_line("250-8BITMIME")
                    await self.send_line("250 ENHANCEDSTATUSCODES")
                elif cmd == "MAIL":
                    # e.g. MAIL FROM:<user@domain.com>
                    m = line.replace("MAIL FROM:", "").replace("mail from:", "").strip().strip("<>")
                    self.mail_from = m
                    self.rcpt_to = []
                    await self.send_line("250 2.1.0 Sender OK")
                elif cmd == "RCPT":
                    # e.g. RCPT TO:<user@domain.com>
                    r = line.replace("RCPT TO:", "").replace("rcpt to:", "").strip().strip("<>")
                    self.rcpt_to.append(r)
                    await self.send_line("250 2.1.5 Recipient OK")
                elif cmd == "RSET":
                    self.mail_from = ""
                    self.rcpt_to = []
                    await self.send_line("250 2.0.0 OK Reset")
                elif cmd == "NOOP":
                    await self.send_line("250 2.0.0 OK")
                elif cmd == "DATA":
                    if not self.mail_from:
                        await self.send_line("503 5.5.1 Error: need MAIL command")
                        continue
                    if not self.rcpt_to:
                        await self.send_line("503 5.5.1 Error: need RCPT command")
                        continue

                    await self.send_line("354 End data with <CR><LF>.<CR><LF>")

                    # Read message content until '.' on its own line
                    data_lines = []
                    while True:
                        dline_bytes = await self.reader.readline()
                        if not dline_bytes:
                            break
                        if dline_bytes == b".\r\n" or dline_bytes == b".\n":
                            break
                        # Handle dot unstuffing
                        if dline_bytes.startswith(b".."):
                            dline_bytes = dline_bytes[1:]
                        data_lines.append(dline_bytes)

                    raw_eml_bytes = b"".join(data_lines)

                    # Execute Inspection Engine
                    recipient_str = ", ".join(self.rcpt_to)
                    inspection = self.inspector.inspect(
                        sender=self.mail_from,
                        recipient=recipient_str,
                        subject="",
                        body="",
                        client_ip=self.client_ip,
                        raw_eml_bytes=raw_eml_bytes
                    )

                    # Update Operational Metrics
                    metrics.record(inspection, self.client_ip, self.mail_from, recipient_str)

                    # Asynchronously dispatch webhook if alert threshold met
                    if inspection.threat_score >= settings.WEBHOOK_MIN_SCORE:
                        asyncio.create_task(async_dispatch_webhook(asdict(inspection)))

                    # Policy Enforcement Actions
                    if inspection.policy_action == "REJECT":
                        if settings.AUTO_QUARANTINE_HIGH_RISK:
                            self.vault.store(
                                case_id=inspection.case_id,
                                raw_eml_bytes=raw_eml_bytes,
                                sender=self.mail_from,
                                recipient=recipient_str,
                                subject=inspection.original_subject,
                                threat_score=inspection.threat_score,
                                category=inspection.category,
                                findings=inspection.findings,
                                auth_summary=inspection.auth_summary,
                                client_ip=self.client_ip
                            )
                        await self.send_line(inspection.smtp_reply)

                    elif inspection.policy_action == "QUARANTINE":
                        self.vault.store(
                            case_id=inspection.case_id,
                            raw_eml_bytes=raw_eml_bytes,
                            sender=self.mail_from,
                            recipient=recipient_str,
                            subject=inspection.original_subject,
                            threat_score=inspection.threat_score,
                            category=inspection.category,
                            findings=inspection.findings,
                            auth_summary=inspection.auth_summary,
                            client_ip=self.client_ip
                        )
                        await self.send_line("250 2.0.0 Message queued for administrative review (Quarantined in Vault)")

                    elif inspection.policy_action == "TAG_SUBJECT":
                        relayed = self._modify_and_relay(raw_eml_bytes, inspection)
                        await self.send_line("250 2.0.0 Message tagged and relayed successfully")

                    else:  # ACCEPT / Clean
                        relayed = self._modify_and_relay(raw_eml_bytes, inspection)
                        await self.send_line("250 2.0.0 Message accepted and delivered cleanly")

                    # Reset session state for subsequent message in same SMTP connection
                    self.mail_from = ""
                    self.rcpt_to = []
                else:
                    await self.send_line(f"500 5.5.2 Error: command '{cmd}' unrecognized")

        except Exception as e:
            logger.error(f"Error in SMTP session from {self.client_ip}: {e}")
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass


class AsyncSMTPProxyServer:
    """Asynchronous SMTP Transparent Gateway Service."""

    def __init__(
        self,
        host: str = settings.SMTP_LISTEN_HOST,
        port: int = settings.SMTP_LISTEN_PORT,
        inspector: Optional[GatewayInspector] = None,
        vault_ref: Optional[QuarantineVault] = None
    ):
        self.host = host
        self.port = port
        self.inspector = inspector or GatewayInspector()
        self.vault = vault_ref or vault
        self.server: Optional[asyncio.Server] = None

    async def _client_connected_cb(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session = SMTPProxySession(reader, writer, self.inspector, self.vault)
        await session.handle()

    async def start(self):
        self.server = await asyncio.start_server(
            self._client_connected_cb,
            self.host,
            self.port
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"[Cyber Squad SMTP Gateway] Serving on {addrs}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("[Cyber Squad SMTP Gateway] Stopped.")
