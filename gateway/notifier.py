"""
Automated SOC Analyst Alerting Engine for SUDO SPANDR ESG.
Dispatches real-time incident notifications across multiple analyst channels:
  1. Desktop Notifications (`notify-send` / Linux GUI pop-up)
  2. Telegram Bot API (Instant mobile alerts)
  3. Discord / Slack SOC channel Webhooks
  4. SMTP Analyst Email Alerts
"""

from __future__ import annotations
import asyncio
import logging
import os
import shutil
import smtplib
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional
import requests

from gateway.config import settings

logger = logging.getLogger("sudospandr.gateway.notifier")


class AnalystNotifier:
    def __init__(self):
        self.settings = settings

    def send_desktop_notification(self, title: str, message: str, urgency: str = "critical") -> bool:
        """
        Triggers a native Linux desktop notification via `notify-send`.
        Visible instantly on SOC analyst workstation.
        """
        if not self.settings.ENABLE_DESKTOP_NOTIFICATIONS:
            return False

        notify_bin = shutil.which("notify-send")
        if not notify_bin:
            logger.debug("[Notifier] notify-send binary not found on host.")
            return False

        try:
            # -u urgency: low, normal, critical
            # -a app name
            # -i icon
            subprocess.run(
                [
                    notify_bin,
                    f"-u", urgency,
                    f"-a", "SUDO SPANDR ESG",
                    f"-i", "security-high",
                    title,
                    message
                ],
                timeout=2.0,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logger.info(f"[Notifier] Desktop alert fired: {title}")
            return True
        except Exception as e:
            logger.warning(f"[Notifier] Failed to fire desktop notification: {e}")
            return False

    def send_telegram_alert(
        self,
        case_id: str,
        score: int,
        verdict: str,
        category: str,
        sender: str,
        recipient: str,
        subject: str,
        top_findings: List[Dict[str, Any]],
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None
    ) -> bool:
        """Sends rich formatted alert to Telegram bot/group."""
        token = bot_token or self.settings.TELEGRAM_BOT_TOKEN
        chat = chat_id or self.settings.TELEGRAM_CHAT_ID

        if not token or not chat:
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"

        finding_str = "\n".join([f"• <b>{f.get('title', 'Rule')}</b> (+{f.get('score', 0)})" for f in top_findings[:3]])

        text = (
            f"🚨 <b>[SUDO SPANDR ESG - THREAT ALERT]</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<b>Case ID:</b> <code>{case_id}</code>\n"
            f"<b>Threat Score:</b> <b>{score}/100</b> ({verdict})\n"
            f"<b>Category:</b> {category}\n"
            f"<b>From:</b> {sender}\n"
            f"<b>To:</b> {recipient}\n"
            f"<b>Subject:</b> {subject}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<b>Top Threat Indicators:</b>\n{finding_str or 'None'}\n\n"
            f"🛡️ <i>Immediate SOC Analyst Investigation Advised.</i>"
        )

        try:
            resp = requests.post(
                url,
                json={"chat_id": chat, "text": text, "parse_mode": "HTML"},
                timeout=4.0
            )
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"[Notifier] Telegram dispatch failed: {e}")
            return False

    def send_analyst_webhook(
        self,
        inspection_data: Dict[str, Any],
        webhook_url: Optional[str] = None
    ) -> bool:
        """Sends structured alert payload or Slack/Discord embed to SOC webhook."""
        url = webhook_url or self.settings.ANALYST_WEBHOOK_URL or self.settings.WEBHOOK_URL
        if not url:
            return False

        case_id = inspection_data.get("case_id", "UNKNOWN")
        score = inspection_data.get("threat_score", 0)
        verdict = inspection_data.get("verdict", "MALICIOUS")
        category = inspection_data.get("category", "Cyber Attack")
        sender = inspection_data.get("sender", "")
        recipient = inspection_data.get("recipient", "")
        subject = inspection_data.get("subject", "")

        try:
            # Discord Webhook payload
            if "discord.com/api/webhooks" in url:
                payload = {
                    "username": "SUDO SPANDR ESG Guard",
                    "embeds": [{
                        "title": f"🚨 High-Threat Intercepted: {case_id}",
                        "color": 0xFF0033 if score >= 75 else 0xFFA500,
                        "fields": [
                            {"name": "Threat Score", "value": f"**{score}/100**", "inline": True},
                            {"name": "Verdict", "value": verdict, "inline": True},
                            {"name": "Category", "value": category, "inline": False},
                            {"name": "Sender", "value": f"`{sender}`", "inline": True},
                            {"name": "Recipient", "value": f"`{recipient}`", "inline": True},
                            {"name": "Subject", "value": subject or "(No Subject)", "inline": False}
                        ],
                        "footer": {"text": "SUDO SPANDR ESG v4.0 • BSA Sec 63 Sealed"}
                    }]
                }
            # Slack Webhook payload
            elif "hooks.slack.com" in url:
                payload = {
                    "text": f"🚨 [SUDO SPANDR ESG] High-Threat Intercepted: {case_id} (Score: {score}/100)",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": f"🚨 ESG Incident: {verdict} ({score}/100)"}
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Case ID:*\n`{case_id}`"},
                                {"type": "mrkdwn", "text": f"*Category:*\n{category}"},
                                {"type": "mrkdwn", "text": f"*From:*\n`{sender}`"},
                                {"type": "mrkdwn", "text": f"*To:*\n`{recipient}`"}
                            ]
                        }
                    ]
                }
            # Generic JSON SIEM endpoint
            else:
                payload = {
                    "event": "HIGH_SCORE_EMAIL_ALERT",
                    "case_id": case_id,
                    "threat_score": score,
                    "verdict": verdict,
                    "category": category,
                    "data": inspection_data
                }

            resp = requests.post(url, json=payload, timeout=4.0)
            return resp.status_code in [200, 201, 204]
        except Exception as e:
            logger.warning(f"[Notifier] Webhook dispatch failed: {e}")
            return False

    def send_analyst_email(
        self,
        case_id: str,
        score: int,
        verdict: str,
        category: str,
        sender: str,
        recipient: str,
        subject: str,
        summary_text: str,
        analyst_email: Optional[str] = None
    ) -> bool:
        """Sends email alert to SOC incident response address."""
        target_email = analyst_email or self.settings.ANALYST_EMAIL
        if not target_email:
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.settings.SMTP_ALERT_FROM
            msg["To"] = target_email
            msg["Subject"] = f"🚨 [ESG ALERT] High Threat Intercepted: {case_id} (Score: {score}/100 - {category})"

            body = (
                f"SUDO SPANDR Enterprise Email Security Gateway Alert\n"
                f"====================================================\n\n"
                f"A high-threat email has been intercepted at the network boundary.\n\n"
                f"Case ID      : {case_id}\n"
                f"Threat Score : {score}/100 [{verdict}]\n"
                f"Category     : {category}\n"
                f"Sender       : {sender}\n"
                f"Recipient    : {recipient}\n"
                f"Subject      : {subject}\n\n"
                f"--- Forensic Autopsy Summary ---\n"
                f"{summary_text}\n"
            )
            msg.attach(MIMEText(body, "plain", "utf-8"))

            with smtplib.SMTP(self.settings.SMTP_ALERT_HOST, self.settings.SMTP_ALERT_PORT, timeout=3.0) as server:
                server.send_message(msg)
            logger.info(f"[Notifier] Alert email delivered to {target_email}")
            return True
        except Exception as e:
            logger.warning(f"[Notifier] Failed to send analyst alert email: {e}")
            return False

    def notify_analyst(
        self,
        case_id: str,
        score: int,
        verdict: str,
        category: str,
        sender: str,
        recipient: str,
        subject: str,
        findings: List[Dict[str, Any]],
        summary_text: str = "",
        full_inspection: Optional[Dict[str, Any]] = None
    ) -> Dict[str, bool]:
        """
        Executes multi-channel notification synchronously.
        """
        results = {}

        # 1. Desktop GUI Alert
        desktop_title = f"🚨 SUDO SPANDR: Threat {score}/100 [{verdict}]"
        desktop_msg = f"Case: {case_id}\nFrom: {sender}\nSubject: {subject[:40]}\nCategory: {category}"
        results["desktop"] = self.send_desktop_notification(desktop_title, desktop_msg)

        # 2. Telegram Alert
        results["telegram"] = self.send_telegram_alert(
            case_id=case_id,
            score=score,
            verdict=verdict,
            category=category,
            sender=sender,
            recipient=recipient,
            subject=subject,
            top_findings=findings
        )

        # 3. Webhook (Slack / Discord / SIEM)
        if full_inspection:
            results["webhook"] = self.send_analyst_webhook(full_inspection)
        else:
            results["webhook"] = self.send_analyst_webhook({
                "case_id": case_id,
                "threat_score": score,
                "verdict": verdict,
                "category": category,
                "sender": sender,
                "recipient": recipient,
                "subject": subject
            })

        # 4. Analyst Email
        results["email"] = self.send_analyst_email(
            case_id=case_id,
            score=score,
            verdict=verdict,
            category=category,
            sender=sender,
            recipient=recipient,
            subject=subject,
            summary_text=summary_text
        )

        logger.info(f"[Notifier] Analyst alerts processed for {case_id}: {results}")
        return results

    async def async_notify_analyst(
        self,
        case_id: str,
        score: int,
        verdict: str,
        category: str,
        sender: str,
        recipient: str,
        subject: str,
        findings: List[Dict[str, Any]],
        summary_text: str = "",
        full_inspection: Optional[Dict[str, Any]] = None
    ):
        """Asynchronous wrapper for background execution without blocking mail flow."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            self.notify_analyst,
            case_id,
            score,
            verdict,
            category,
            sender,
            recipient,
            subject,
            findings,
            summary_text,
            full_inspection
        )


# Global notifier instance
notifier = AnalystNotifier()
