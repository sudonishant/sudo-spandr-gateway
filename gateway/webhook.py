"""
SIEM & SOC Alert Webhook Dispatcher for Cyber Squad ESG.
Sends real-time high-fidelity threat alerts to SOC webhooks, Slack, Discord, or syslog endpoints.
"""

from __future__ import annotations
import asyncio
import json
import logging
from typing import Any, Dict, Optional
import requests

from gateway.config import settings

logger = logging.getLogger("cybersquad.gateway.webhook")


def format_slack_alert(inspection: Dict[str, Any]) -> Dict[str, Any]:
    """Formats an inspection result into Slack Block Kit alert."""
    case_id = inspection.get("case_id", "UNKNOWN")
    score = inspection.get("threat_score", 0)
    category = inspection.get("category", "Unknown Threat")
    verdict = inspection.get("verdict", "UNKNOWN")
    policy = inspection.get("policy_action", "UNKNOWN")
    findings = inspection.get("findings", [])

    finding_lines = "\n".join(f"• *{f.get('title')}*: {f.get('description')}" for f in findings[:3])

    return {
        "text": f"🚨 [Cyber Squad ESG] High-Risk Email Intercepted: {case_id} (Score: {score}/100)",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🛡️ ESG Alert: {verdict} ({score}/100)"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Case ID:*\n`{case_id}`"},
                    {"type": "mrkdwn", "text": f"*Policy Action:*\n`{policy}`"},
                    {"type": "mrkdwn", "text": f"*Category:*\n{category}"},
                    {"type": "mrkdwn", "text": f"*Evaluator:*\n{inspection.get('evaluated_by', 'Local Engine')}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top Threat Findings:*\n{finding_lines or 'None'}"}
            }
        ]
    }


def dispatch_webhook(inspection_result_dict: Dict[str, Any], webhook_url: Optional[str] = None) -> bool:
    """Dispatches webhook notification synchronously or in background."""
    url = webhook_url or settings.WEBHOOK_URL
    if not url:
        return False

    min_score = settings.WEBHOOK_MIN_SCORE
    if inspection_result_dict.get("threat_score", 0) < min_score:
        return False

    try:
        payload = {
            "source": "Cyber Squad Enterprise ESG v4.0",
            "event": "EMAIL_INTERCEPTED",
            "timestamp": inspection_result_dict.get("generated_at"),
            "data": inspection_result_dict
        }

        # Check if slack webhook
        if "hooks.slack.com" in url:
            payload = format_slack_alert(inspection_result_dict)

        res = requests.post(url, json=payload, timeout=4.0)
        return res.status_code in [200, 201, 204]
    except Exception as e:
        logger.warning(f"Failed to dispatch webhook alert to {url}: {e}")
        return False


async def async_dispatch_webhook(inspection_result_dict: Dict[str, Any], webhook_url: Optional[str] = None):
    """Asynchronous wrapper for webhook dispatch."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, dispatch_webhook, inspection_result_dict, webhook_url)
