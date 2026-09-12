#!/usr/bin/env python3
"""
SUDO SPANDR Mail Flow Gateway Agent (Postfix Milter / Daemon)
SIH 2026 Problem Statement #26106

Enterprise Next-Gen Mail Flow Interceptor & Milter Protocol Server.
Supports both backward-compatible API querying and native asynchronous Wire Milter daemon.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import sys
from typing import Any, Dict, Optional

from gateway.config import settings
from gateway.engine.inspector import GatewayInspector, InspectionResult
from gateway.milter_server import AsyncMilterServer
from gateway.archiver import archiver
from gateway.notifier import notifier



class SudoSpandrMilterDaemon:
    """
    High-Throughput Policy Enforcement Milter Agent.
    Evaluates inbound email headers and MIME body streams in real-time.
    """

    def __init__(self, backend_url: Optional[str] = None):
        self.inspector = GatewayInspector()
        self.backend_url = backend_url or settings.WEB_BACKEND_URL
        print(f"[SUDO SPANDR Gateway] Initialized Next-Gen Milter Daemon (v{settings.VERSION})")
        print(f"[SUDO SPANDR Gateway] Heuristics: Active | DNS Auth: Active | Backend Fallback: {self.backend_url}")

    def process_incoming_mail(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Intercepts incoming mail stream and evaluates against policy engine.
        Returns detailed forensic verdict and Postfix action code.
        """
        try:
            res: InspectionResult = self.inspector.inspect(
                sender=sender,
                recipient=recipient,
                subject=subject,
                body=body,
                headers=headers or {},
                client_ip=client_ip
            )

            print(f"[Milter Daemon] Result: {res.postfix_code} (Threat Score: {res.threat_score}%) -> Action: {res.policy_action} [{res.category}]")

            # Continuous Intercepted Email Archival
            if settings.ENABLE_ALL_MAIL_ARCHIVE:
                raw_bytes = f"From: {sender}\nTo: {recipient}\nSubject: {subject}\n\n{body}".encode("utf-8")
                try:
                    archiver.archive_message(
                        case_id=res.case_id,
                        raw_eml_bytes=raw_bytes,
                        sender=sender,
                        recipient=recipient,
                        subject=subject,
                        threat_score=res.threat_score,
                        verdict=res.verdict,
                        policy_action=res.policy_action,
                        category=res.category,
                        findings=res.findings,
                        auth_summary=res.auth_summary,
                        client_ip=client_ip,
                        autopsy_dossier=res.autopsy_dossier
                    )
                except Exception as ex:
                    print(f"[Milter Daemon] Warning: Archival failed for {res.case_id}: {ex}")

            # Automated Analyst Alerting for High Threat Emails
            if res.threat_score >= settings.ALERT_ANALYST_MIN_SCORE:
                summary_txt = archiver.get_summary_text(res.case_id) or ""
                notifier.notify_analyst(
                    case_id=res.case_id,
                    score=res.threat_score,
                    verdict=res.verdict,
                    category=res.category,
                    sender=sender,
                    recipient=recipient,
                    subject=subject,
                    findings=res.findings,
                    summary_text=summary_txt
                )

            return {

                "status": "success",
                "case_id": res.case_id,
                "threat_score": res.threat_score,
                "policy_action": res.policy_action,
                "postfix_code": res.postfix_code,
                "smtp_reply": res.smtp_reply,
                "category": res.category,
                "findings": res.findings,
                "auth_summary": res.auth_summary,
                "headers_to_add": res.headers_to_add,
                "modified_subject": res.modified_subject,
                "evidence_sha256": res.evidence_sha256,
                "scan_time_ms": res.scan_time_ms,
                "evaluated_by": res.evaluated_by,
                "autopsy_dossier": res.autopsy_dossier
            }
        except Exception as e:
            print(f"[Milter Daemon] Error during mail inspection: {e}. Falling back to default CONTINUE.")
            return {
                "status": "fallback",
                "policy_action": "ACCEPT",
                "postfix_code": "Milter.CONTINUE",
                "threat_score": 0,
                "error": str(e)
            }


# Backward-compatible alias
CyberSquadMilterDaemon = SudoSpandrMilterDaemon


async def run_milter_service(host: str, port: int):
    server = AsyncMilterServer(host=host, port=port)
    await server.start()
    print(f"[*] Postfix Milter Wire Protocol Server active on {host}:{port}")
    print("[*] Press Ctrl+C to terminate.")
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await server.stop()


def main():
    parser = argparse.ArgumentParser(description="SUDO SPANDR Enterprise Milter Daemon (SIH #26106)")
    parser.add_argument("--serve", action="store_true", help="Start the Async Milter Wire Protocol Server")
    parser.add_argument("--host", default=settings.MILTER_LISTEN_HOST, help="Bind host for Milter TCP server")
    parser.add_argument("--port", type=int, default=settings.MILTER_LISTEN_PORT, help="Bind port for Milter TCP server")
    parser.add_argument("--test", action="store_true", help="Run test interception simulation")

    args = parser.parse_args()

    if args.serve:
        try:
            asyncio.run(run_milter_service(args.host, args.port))
        except KeyboardInterrupt:
            print("\n[*] Milter Daemon stopped.")
    else:
        # Default: Run Interception Simulation
        daemon = SudoSpandrMilterDaemon()
        print("\n" + "="*70)
        print("⚡ RUNNING ZERO-DAY INTERCEPTION TEST SIMULATION")
        print("="*70)

        test_result = daemon.process_incoming_mail(
            sender="attacker@b0b-security-update.in",
            recipient="user@company.com",
            subject="URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)",
            body="Please wire $25.6M immediately to our external bank account. Do not disclose. Sent from my iPhone in a meeting.",
            headers={"received-spf": "fail (ip=185.220.101.5)", "reply-to": "drop@attacker-mail.ru"}
        )

        print("\n[+] Final Policy Decision Payload:")
        print(json.dumps(test_result, indent=2))
        print("="*70)


if __name__ == "__main__":
    main()
