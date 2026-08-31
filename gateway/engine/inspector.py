"""
Unified Gateway Threat & Policy Inspector for Cyber Squad ESG.
Orchestrates heuristics, DNS authentication, MIME analysis, and optional Web Backend delegation.
"""

from __future__ import annotations
import email
import email.policy
import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import requests

from gateway.config import settings
from gateway.engine.rules import evaluate_rules, RuleFinding
from gateway.engine.authenticator import evaluate_authentication, AuthResult


@dataclass
class InspectionResult:
    case_id: str
    threat_score: int
    verdict: str           # CLEAN, SUSPICIOUS, MALICIOUS
    policy_action: str     # ACCEPT, TAG_SUBJECT, QUARANTINE, REJECT
    postfix_code: str      # Milter.CONTINUE, Milter.QUARANTINE, Milter.REJECT
    smtp_reply: str        # 250 2.0.0 or 550 5.7.1
    category: str
    findings: List[Dict[str, Any]]
    auth_summary: Dict[str, Any]
    headers_to_add: Dict[str, str]
    original_subject: str
    modified_subject: Optional[str]
    evidence_sha256: str
    scan_time_ms: float
    evaluated_by: str      # "local_engine" or "hybrid_web_core"


class GatewayInspector:
    def __init__(self):
        self.settings = settings

    def parse_raw_eml(self, raw_bytes: bytes) -> Tuple[str, str, str, str, Dict[str, str], List[Dict[str, Any]]]:
        """Parses raw EML bytes into sender, recipient, subject, body, headers, attachments."""
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        sender = str(msg.get("from", "")).strip()
        recipient = str(msg.get("to", "")).strip()
        subject = str(msg.get("subject", "")).strip()

        # Extract headers
        headers: Dict[str, str] = {}
        for k, v in msg.items():
            headers[k.lower()] = str(v)

        # Extract body and attachments
        body_parts = []
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                if filename or "attachment" in disp:
                    payload = part.get_payload(decode=True) or b""
                    attachments.append({
                        "filename": filename or "unnamed_attachment",
                        "content_type": content_type,
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest()
                    })
                elif content_type in ["text/plain", "text/html"]:
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_parts.append(content)
                        elif isinstance(content, bytes):
                            body_parts.append(content.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
        else:
            try:
                content = msg.get_content()
                body_parts.append(content if isinstance(content, str) else str(content))
            except Exception:
                payload = msg.get_payload(decode=True) or b""
                body_parts.append(payload.decode("utf-8", errors="ignore"))

        body = "\n".join(body_parts)
        return sender, recipient, subject, body, headers, attachments

    def inspect(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        client_ip: str = "127.0.0.1",
        raw_eml_bytes: Optional[bytes] = None
    ) -> InspectionResult:
        """
        Main inspection entry point.
        Evaluates email and calculates threat score, verdict, and policy enforcement action.
        """
        start_time = time.perf_counter()
        headers = headers or {}
        attachments = attachments or []

        # If raw EML was supplied, parse details if missing
        if raw_eml_bytes and (not sender or not body):
            p_sender, p_rcpt, p_subj, p_body, p_hdrs, p_atts = self.parse_raw_eml(raw_eml_bytes)
            sender = sender or p_sender
            recipient = recipient or p_rcpt
            subject = subject or p_subj
            body = body or p_body
            if not headers:
                headers = p_hdrs
            if not attachments:
                attachments = p_atts

        # Compute SHA-256 Hash of content
        if raw_eml_bytes:
            evidence_sha256 = hashlib.sha256(raw_eml_bytes).hexdigest()
        else:
            canonical = f"{sender}|{recipient}|{subject}|{body}".encode("utf-8")
            evidence_sha256 = hashlib.sha256(canonical).hexdigest()

        case_id = f"CS-ESG-{evidence_sha256[:10].upper()}"

        evaluated_by = "local_engine"
        rule_score = 0
        findings: List[RuleFinding] = []
        dominant_category = "General Email"

        # Try Web Core Delegation if enabled
        web_delegation_succeeded = False
        if self.settings.ENABLE_HYBRID_DELEGATION and self.settings.WEB_BACKEND_URL:
            try:
                res = requests.post(
                    self.settings.WEB_BACKEND_URL,
                    json={
                        "sender": sender,
                        "recipient": recipient,
                        "subject": subject,
                        "body": body,
                        "headers": headers
                    },
                    timeout=self.settings.WEB_BACKEND_TIMEOUT
                )
                if res.status_code == 200:
                    data = res.json()
                    rule_score = data.get("threat_score", 0)
                    dominant_category = data.get("category", "General Email")
                    reasons = data.get("reasons", [])
                    for idx, r in enumerate(reasons):
                        findings.append(RuleFinding(
                            rule_id=f"WEB-CORE-{idx+1:02d}",
                            category=dominant_category,
                            severity="HIGH" if rule_score >= 70 else "MEDIUM",
                            score_impact=20,
                            title=str(r),
                            description=f"Identified by Cyber Squad Web Analysis Core: {r}",
                            evidence=f"Signal: {r}"
                        ))
                    evaluated_by = "hybrid_web_core"
                    web_delegation_succeeded = True
            except Exception:
                web_delegation_succeeded = False

        # If web delegation was skipped or failed, use high-speed in-memory heuristic engine
        if not web_delegation_succeeded:
            rule_score, findings, dominant_category = evaluate_rules(
                sender=sender,
                recipient=recipient,
                subject=subject,
                body=body,
                headers=headers,
                attachments=attachments
            )
            evaluated_by = "local_engine"

        # Evaluate DNS Authentication (SPF / DKIM / DMARC)
        auth_res = evaluate_authentication(
            sender=sender,
            client_ip=client_ip,
            headers=headers,
            timeout=self.settings.DNS_RESOLVER_TIMEOUT
        )

        # Composite Threat Score (0 to 100)
        composite_score = min(100, rule_score + auth_res.penalty_score)

        # Determine Verdict & Policy Action
        if composite_score >= self.settings.REJECT_THRESHOLD:
            verdict = "MALICIOUS"
            policy_action = "REJECT" if not self.settings.AUTO_QUARANTINE_HIGH_RISK else "QUARANTINE"
            postfix_code = "Milter.REJECT"
            smtp_reply = f"550 5.7.1 Message rejected by Cyber Squad ESG: Threat score {composite_score}/100 [{dominant_category}] (Ref: {case_id})"
        elif composite_score >= self.settings.CLEAN_THRESHOLD:
            verdict = "SUSPICIOUS"
            policy_action = "TAG_SUBJECT"
            postfix_code = "Milter.QUARANTINE"  # In Postfix Milter, QUARANTINE routes to spam/hold
            smtp_reply = "250 2.0.0 Message accepted with suspicious tag"
        else:
            verdict = "CLEAN"
            policy_action = "ACCEPT"
            postfix_code = "Milter.CONTINUE"
            smtp_reply = "250 2.0.0 Message accepted for delivery"

        # Headers to Inject
        headers_to_add = {
            "X-CyberSquad-ESG-Version": self.settings.VERSION,
            "X-CyberSquad-Case-ID": case_id,
            "X-CyberSquad-Threat-Score": str(composite_score),
            "X-CyberSquad-Verdict": verdict,
            "X-CyberSquad-Category": dominant_category,
            "X-CyberSquad-SPF": auth_res.spf_status,
            "X-CyberSquad-DKIM": auth_res.dkim_status,
            "X-CyberSquad-DMARC": auth_res.dmarc_status,
            "X-CyberSquad-Evaluator": evaluated_by
        }

        # Subject Modification for Suspicious Verdict
        modified_subject = None
        if policy_action == "TAG_SUBJECT":
            headers_to_add["X-Spam-Flag"] = "YES"
            headers_to_add["X-Spam-Level"] = "*" * (composite_score // 10)
            if not subject.startswith(self.settings.SUBJECT_TAG_PREFIX):
                modified_subject = f"{self.settings.SUBJECT_TAG_PREFIX} {subject}"

        scan_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return InspectionResult(
            case_id=case_id,
            threat_score=composite_score,
            verdict=verdict,
            policy_action=policy_action,
            postfix_code=postfix_code,
            smtp_reply=smtp_reply,
            category=dominant_category,
            findings=[asdict(f) for f in findings],
            auth_summary=asdict(auth_res),
            headers_to_add=headers_to_add,
            original_subject=subject,
            modified_subject=modified_subject,
            evidence_sha256=evidence_sha256,
            scan_time_ms=scan_time_ms,
            evaluated_by=evaluated_by
        )
