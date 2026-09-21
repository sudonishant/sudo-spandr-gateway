"""
Real-time Gmail / Google Workspace IMAP Live Interceptor & Mail Synchronizer.
Connects directly to imap.gmail.com over TLS (Port 993) using a Google App Password.
Intercepts live unread / recent emails, runs them through the SUDO SPANDR Forensic Autopsy Engine,
archives them with Section 63 BSA compliance, and notifies SOC analysts on high-threat scores.
"""

from __future__ import annotations
import asyncio
import email
import email.policy
import imaplib
import logging
import ssl
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from gateway.config import settings
from gateway.engine.inspector import GatewayInspector, InspectionResult
from gateway.quarantine import vault
from gateway.archiver import archiver
from gateway.notifier import notifier
from gateway.smtp_proxy import metrics

logger = logging.getLogger("sudospandr.gateway.gmail")


class GmailSyncService:
    def __init__(self):
        self.inspector = GatewayInspector()
        self.is_running: bool = False
        self.current_email: Optional[str] = None
        self.current_app_password: Optional[str] = None
        self.sync_task: Optional[asyncio.Task] = None
        self.last_sync_time: Optional[float] = None
        self.synced_count: int = 0
        self.last_error: Optional[str] = None
        self.processed_uids: set = set()

    def test_connection(self, email_address: str, app_password: str) -> Dict[str, Any]:
        """Validates Gmail IMAP credentials synchronously."""
        clean_pwd = app_password.replace(" ", "").strip()
        clean_email = email_address.strip()

        try:
            context = ssl.create_default_context()
            mail = imaplib.IMAP4_SSL(settings.GMAIL_IMAP_SERVER, settings.GMAIL_IMAP_PORT, ssl_context=context)
            mail.login(clean_email, clean_pwd)
            status, folders = mail.list()
            mail.select("INBOX", readonly=True)
            res, count_data = mail.search(None, "ALL")
            total_emails = len(count_data[0].split()) if count_data and count_data[0] else 0
            mail.logout()

            return {
                "status": "success",
                "message": f"Successfully connected to Gmail mailbox ({clean_email}).",
                "total_inbox_messages": total_emails
            }
        except imaplib.IMAP4.error as e:
            err_msg = str(e)
            if "AUTHENTICATIONFAILED" in err_msg or "Application-specific password required" in err_msg:
                return {
                    "status": "error",
                    "message": "Gmail authentication failed. Please make sure 2-Step Verification is enabled in Google Account and generate a 16-character 'App Password'."
                }
            return {"status": "error", "message": f"IMAP Error: {err_msg}"}
        except Exception as e:
            return {"status": "error", "message": f"Connection failed: {e}"}

    def fetch_and_inspect_recent(
        self,
        email_address: str,
        app_password: str,
        max_messages: int = 10,
        unread_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Fetches up to `max_messages` from Gmail INBOX, processes them through
        the SUDO SPANDR forensic pipeline, archives them, and triggers alerts on high score.
        """
        clean_pwd = app_password.replace(" ", "").strip()
        clean_email = email_address.strip()
        results: List[Dict[str, Any]] = []

        try:
            context = ssl.create_default_context()
            mail = imaplib.IMAP4_SSL(settings.GMAIL_IMAP_SERVER, settings.GMAIL_IMAP_PORT, ssl_context=context)
            mail.login(clean_email, clean_pwd)
            mail.select("INBOX", readonly=False)

            search_crit = "UNSEEN" if unread_only else "ALL"
            res, data = mail.search(None, search_crit)

            if not data or not data[0]:
                mail.logout()
                return []

            msg_ids = data[0].split()
            # Pick latest messages
            latest_ids = msg_ids[-max_messages:]

            for mid in reversed(latest_ids):
                uid_str = mid.decode("utf-8")
                if uid_str in self.processed_uids and not unread_only:
                    continue

                fetch_res, msg_data = mail.fetch(mid, "(RFC822)")
                if fetch_res != "OK" or not msg_data:
                    continue

                raw_eml_bytes = None
                for part in msg_data:
                    if isinstance(part, tuple) and len(part) >= 2:
                        raw_eml_bytes = part[1]
                        break

                if not raw_eml_bytes:
                    continue

                # Run full forensic autopsy inspection
                inspection: InspectionResult = self.inspector.inspect(
                    sender="",
                    recipient="",
                    subject="",
                    body="",
                    client_ip="imap.gmail.com",
                    raw_eml_bytes=raw_eml_bytes
                )

                # Record metrics
                sender_val = inspection.original_subject or "Unknown"
                metrics.record(inspection, "imap.gmail.com", inspection.case_id, clean_email)

                # Continuous Archival of every incoming Gmail
                if settings.ENABLE_ALL_MAIL_ARCHIVE:
                    try:
                        archiver.archive_message(
                            case_id=inspection.case_id,
                            raw_eml_bytes=raw_eml_bytes,
                            sender=inspection.original_subject,  # parsed sender in autopsy
                            recipient=clean_email,
                            subject=inspection.original_subject,
                            threat_score=inspection.threat_score,
                            verdict=inspection.verdict,
                            policy_action=inspection.policy_action,
                            category=inspection.category,
                            findings=inspection.findings,
                            auth_summary=inspection.auth_summary,
                            client_ip="imap.gmail.com",
                            autopsy_dossier=inspection.autopsy_dossier
                        )
                    except Exception as ex:
                        logger.error(f"[GmailSync] Archive error: {ex}")

                # Auto Quarantine High Threat Mails
                if inspection.threat_score >= settings.REJECT_THRESHOLD and settings.AUTO_QUARANTINE_HIGH_RISK:
                    vault.store(
                        case_id=inspection.case_id,
                        raw_eml_bytes=raw_eml_bytes,
                        sender=inspection.original_subject,
                        recipient=clean_email,
                        subject=inspection.original_subject,
                        threat_score=inspection.threat_score,
                        category=inspection.category,
                        findings=inspection.findings,
                        auth_summary=inspection.auth_summary,
                        client_ip="imap.gmail.com",
                        autopsy_dossier=inspection.autopsy_dossier
                    )

                # Automated SOC Analyst Alerting on High Threat Score
                if inspection.threat_score >= settings.ALERT_ANALYST_MIN_SCORE:
                    summary_txt = archiver.get_summary_text(inspection.case_id) or ""
                    notifier.notify_analyst(
                        case_id=inspection.case_id,
                        score=inspection.threat_score,
                        verdict=inspection.verdict,
                        category=inspection.category,
                        sender=clean_email,
                        recipient="SOC Team",
                        subject=inspection.original_subject,
                        findings=inspection.findings,
                        summary_text=summary_txt,
                        full_inspection=asdict(inspection)
                    )

                self.processed_uids.add(uid_str)
                self.synced_count += 1

                results.append({
                    "case_id": inspection.case_id,
                    "gmail_uid": uid_str,
                    "threat_score": inspection.threat_score,
                    "verdict": inspection.verdict,
                    "policy_action": inspection.policy_action,
                    "category": inspection.category,
                    "subject": inspection.original_subject,
                    "scan_time_ms": inspection.scan_time_ms
                })

            mail.logout()
            self.last_sync_time = time.time()
            self.last_error = None
            return results

        except Exception as e:
            self.last_error = str(e)
            logger.error(f"[GmailSync] Sync error: {e}")
            raise e

    async def _continuous_polling_loop(self):
        """Background asynchronous polling worker for real Gmail live feed."""
        logger.info(f"[GmailSync] Background live polling started for {self.current_email}")
        while self.is_running:
            try:
                if self.current_email and self.current_app_password:
                    # Fetch new unread emails
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        self.fetch_and_inspect_recent,
                        self.current_email,
                        self.current_app_password,
                        5,
                        True
                    )
            except Exception as e:
                logger.warning(f"[GmailSync] Background poll iteration failed: {e}")

            await asyncio.sleep(settings.GMAIL_POLL_INTERVAL_SECONDS)

    def start_live_sync(self, email_address: str, app_password: str) -> Dict[str, Any]:
        """Validates credentials and starts background continuous live monitoring."""
        test_res = self.test_connection(email_address, app_password)
        if test_res.get("status") != "success":
            return test_res

        self.current_email = email_address.strip()
        self.current_app_password = app_password.replace(" ", "").strip()
        self.is_running = True

        if self.sync_task and not self.sync_task.done():
            self.sync_task.cancel()

        self.sync_task = asyncio.create_task(self._continuous_polling_loop())

        # Perform initial pull of 5 recent messages
        try:
            initial_inspected = self.fetch_and_inspect_recent(self.current_email, self.current_app_password, 5, False)
        except Exception:
            initial_inspected = []

        return {
            "status": "success",
            "message": f"Live Gmail protection active for {self.current_email}. Scanning every {settings.GMAIL_POLL_INTERVAL_SECONDS}s.",
            "email": self.current_email,
            "initial_inspected_count": len(initial_inspected),
            "recent_inspections": initial_inspected
        }

    def stop_live_sync(self) -> Dict[str, Any]:
        """Stops background Gmail monitoring."""
        self.is_running = False
        if self.sync_task:
            self.sync_task.cancel()
            self.sync_task = None
        em = self.current_email
        self.current_email = None
        self.current_app_password = None
        return {"status": "success", "message": f"Gmail live sync stopped for {em or 'account'}."}

    def get_status(self) -> Dict[str, Any]:
        """Returns current sync status."""
        return {
            "is_active": self.is_running,
            "connected_email": self.current_email,
            "synced_count": self.synced_count,
            "last_sync_timestamp": self.last_sync_time,
            "poll_interval_seconds": settings.GMAIL_POLL_INTERVAL_SECONDS,
            "last_error": self.last_error
        }


# Global Gmail Service instance
gmail_service = GmailSyncService()
