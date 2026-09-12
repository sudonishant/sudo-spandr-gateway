"""
Continuous Intercepted Mail Archiver for SUDO SPANDR ESG.
Saves every email intercepted across the network into a structured, configurable vault.
For every email, it persists:
  1. <case_id>.eml         - Raw RFC 5322 byte-exact email
  2. <case_id>_report.json - Complete machine-readable forensic autopsy dossier
  3. <case_id>_summary.txt - Human-readable executive summary report
"""

from __future__ import annotations
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from gateway.config import settings

logger = logging.getLogger("sudospandr.gateway.archiver")


class EmailArchiver:
    def __init__(self, archive_dir: Optional[Path] = None):
        self.archive_dir = Path(archive_dir or settings.ARCHIVE_DIR)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def set_archive_dir(self, new_dir: Path | str) -> Path:
        """Dynamically reconfigures the archive storage destination."""
        self.archive_dir = Path(new_dir)
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        return self.archive_dir

    def generate_human_summary(
        self,
        case_id: str,
        sender: str,
        recipient: str,
        subject: str,
        threat_score: int,
        verdict: str,
        policy_action: str,
        category: str,
        client_ip: str,
        timestamp: str,
        findings: List[Dict[str, Any]],
        auth_summary: Dict[str, Any],
        evidence_sha256: str
    ) -> str:
        """Generates an executive, human-readable forensic summary report."""
        lines = [
            "================================================================================",
            "        SUDO SPANDR ESG - INTERCEPTED EMAIL FORENSIC AUTOPSY REPORT",
            "================================================================================",
            f"Case ID           : {case_id}",
            f"Timestamp (UTC)   : {timestamp}",
            f"Threat Score      : {threat_score}/100",
            f"Verdict           : {verdict}",
            f"Enforced Action   : {policy_action}",
            f"Primary Category  : {category}",
            f"Connecting IP     : {client_ip}",
            "--------------------------------------------------------------------------------",
            "EMAIL METADATA:",
            f"  From            : {sender}",
            f"  To              : {recipient}",
            f"  Subject         : {subject or '(No Subject)'}",
            f"  SHA-256 Digest  : {evidence_sha256}",
            "--------------------------------------------------------------------------------",
            "CRYPTOGRAPHIC AUTHENTICATION STATUS (RFC 7208 / 6376 / 7489):",
            f"  SPF Status      : {auth_summary.get('spf_status', 'NONE')}",
            f"  DKIM Status     : {auth_summary.get('dkim_status', 'NONE')}",
            f"  DMARC Status    : {auth_summary.get('dmarc_status', 'NONE')}",
            f"  Aligned From    : {auth_summary.get('aligned_domain', 'N/A')}",
            "--------------------------------------------------------------------------------",
            "KEY FORENSIC FINDINGS & HEURISTICS:"
        ]

        if findings:
            for i, f in enumerate(findings, 1):
                severity = f.get("severity", "MEDIUM")
                rule_id = f.get("rule_id", "RULE")
                title = f.get("title", "")
                score = f.get("score", 0)
                desc = f.get("description", "")
                lines.append(f"  [{i}] [{severity.upper()}] {title} (Rule: {rule_id}, Threat: +{score})")
                if desc:
                    lines.append(f"      Details: {desc}")
        else:
            lines.append("  (No high-risk threat indicators flagged. Clean mail stream.)")

        lines.extend([
            "--------------------------------------------------------------------------------",
            "EVIDENCE LEGAL CHAIN OF CUSTODY:",
            "  Standard        : Section 63 of Bharatiya Sakshya Adhiniyam (BSA) 2023",
            f"  Integrity Hash  : {evidence_sha256}",
            "  Status          : Sealed and archived automatically at gateway boundary.",
            "================================================================================\n"
        ])
        return "\n".join(lines)

    def archive_message(
        self,
        case_id: str,
        raw_eml_bytes: bytes,
        sender: str,
        recipient: str,
        subject: str,
        threat_score: int,
        verdict: str,
        policy_action: str,
        category: str,
        findings: List[Dict[str, Any]],
        auth_summary: Dict[str, Any],
        client_ip: str = "127.0.0.1",
        autopsy_dossier: Optional[Dict[str, Any]] = None,
        date_partition: bool = True
    ) -> Dict[str, Any]:
        """
        Saves the raw email, machine-readable JSON dossier, and human summary
        into the designated folder.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()
        date_folder_str = now.strftime("%Y-%m-%d")

        # Destination folder
        if date_partition:
            dest_dir = self.archive_dir / date_folder_str / case_id
        else:
            dest_dir = self.archive_dir / case_id
        dest_dir.mkdir(parents=True, exist_ok=True)

        # 1. Compute SHA-256 evidence hash
        sha256_hash = hashlib.sha256(raw_eml_bytes).hexdigest()

        # 2. Save raw RFC 5322 EML
        eml_path = dest_dir / f"{case_id}.eml"
        with open(eml_path, "wb") as f:
            f.write(raw_eml_bytes)

        # 3. Generate human summary and save .txt
        summary_text = self.generate_human_summary(
            case_id=case_id,
            sender=sender,
            recipient=recipient,
            subject=subject,
            threat_score=threat_score,
            verdict=verdict,
            policy_action=policy_action,
            category=category,
            client_ip=client_ip,
            timestamp=timestamp_str,
            findings=findings,
            auth_summary=auth_summary,
            evidence_sha256=sha256_hash
        )
        summary_path = dest_dir / f"{case_id}_summary.txt"
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary_text)

        # 4. Construct complete autopsy report
        report = {
            "case_id": case_id,
            "timestamp": timestamp_str,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "threat_score": threat_score,
            "verdict": verdict,
            "policy_action": policy_action,
            "category": category,
            "client_ip": client_ip,
            "sha256_hash": sha256_hash,
            "size_bytes": len(raw_eml_bytes),
            "findings": findings,
            "auth_summary": auth_summary,
            "autopsy_dossier": autopsy_dossier,
            "archive_paths": {
                "eml": str(eml_path),
                "summary": str(summary_path),
                "report": str(dest_dir / f"{case_id}_report.json")
            },
            "bsa_section_63": {
                "hash_algorithm": "SHA-256",
                "evidence_hash": sha256_hash,
                "certified_timestamp": timestamp_str,
                "admissibility_standard": "Section 63 of Bharatiya Sakshya Adhiniyam (BSA) 2023",
                "authenticity_status": "ARCHIVED_SEALED"
            }
        }

        # 5. Save machine-readable JSON report
        report_path = dest_dir / f"{case_id}_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"[Archiver] Intercepted mail saved to {dest_dir} (Score: {threat_score}, Verdict: {verdict})")
        return report

    def list_archived_cases(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Scans the archive directory and returns indexed case summaries sorted by timestamp descending."""
        cases = []
        # Find all _report.json files recursively
        for report_file in self.archive_dir.glob("**/*_report.json"):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cases.append({
                        "case_id": data.get("case_id"),
                        "timestamp": data.get("timestamp"),
                        "sender": data.get("sender"),
                        "recipient": data.get("recipient"),
                        "subject": data.get("subject"),
                        "threat_score": data.get("threat_score"),
                        "verdict": data.get("verdict"),
                        "policy_action": data.get("policy_action"),
                        "category": data.get("category"),
                        "client_ip": data.get("client_ip"),
                        "sha256_hash": data.get("sha256_hash"),
                        "folder": str(report_file.parent)
                    })
            except Exception:
                continue

        cases.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return cases[:limit]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an archived case report by case_id."""
        for report_file in self.archive_dir.glob(f"**/{case_id}_report.json"):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def get_summary_text(self, case_id: str) -> Optional[str]:
        """Retrieves the human-readable summary text by case_id."""
        for summary_file in self.archive_dir.glob(f"**/{case_id}_summary.txt"):
            try:
                with open(summary_file, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                return None
        return None


# Global archiver instance
archiver = EmailArchiver()
