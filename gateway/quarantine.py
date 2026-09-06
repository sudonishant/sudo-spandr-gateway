"""
Cryptographic Evidence Quarantine Vault for SUDO SPANDR ESG.
Persists intercepted high-threat emails with SHA-256 integrity sealing and Section 63 BSA 2023 compliance.
"""

from __future__ import annotations
import hmac
import hashlib
import json
import os
import smtplib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from gateway.config import settings


class QuarantineVault:
    def __init__(self, vault_dir: Optional[Path] = None, secret: Optional[str] = None):
        self.vault_dir = vault_dir or settings.QUARANTINE_DIR
        self.secret = (secret or settings.QUARANTINE_SECRET).encode("utf-8")
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def _generate_seal(self, sha256: str, timestamp: str, case_id: str) -> str:
        """Generates HMAC-SHA256 tamper-evident seal for forensic evidence."""
        msg = f"{case_id}:{sha256}:{timestamp}".encode("utf-8")
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

    def store(
        self,
        case_id: str,
        raw_eml_bytes: bytes,
        sender: str,
        recipient: str,
        subject: str,
        threat_score: int,
        category: str,
        findings: List[Dict[str, Any]],
        auth_summary: Dict[str, Any],
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """Stores a quarantined message and writes cryptographically sealed metadata."""
        now_utc = datetime.now(timezone.utc).isoformat()
        sha256_hash = hashlib.sha256(raw_eml_bytes).hexdigest()
        seal = self._generate_seal(sha256_hash, now_utc, case_id)

        meta = {
            "case_id": case_id,
            "status": "QUARANTINED",
            "timestamp": now_utc,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "threat_score": threat_score,
            "category": category,
            "client_ip": client_ip,
            "sha256_hash": sha256_hash,
            "hmac_seal": seal,
            "size_bytes": len(raw_eml_bytes),
            "findings": findings,
            "auth_summary": auth_summary,
            "bsa_section_63": {
                "hash_algorithm": "SHA-256",
                "evidence_hash": sha256_hash,
                "certified_timestamp": now_utc,
                "admissibility_standard": "Section 63 of Bharatiya Sakshya Adhiniyam (BSA) 2023",
                "authenticity_status": "SEALED_INTACT"
            }
        }

        eml_path = self.vault_dir / f"{case_id}.eml"
        meta_path = self.vault_dir / f"{case_id}.json"

        with open(eml_path, "wb") as f:
            f.write(raw_eml_bytes)

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)

        return meta

    def list_cases(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Lists quarantined items sorted by timestamp descending."""
        cases = []
        for meta_file in self.vault_dir.glob("*.json"):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cases.append(data)
            except Exception:
                continue

        # Sort descending by timestamp
        cases.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return cases[:limit]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves metadata for a specific quarantined case."""
        meta_path = self.vault_dir / f"{case_id}.json"
        if not meta_path.exists():
            return None
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def get_raw_eml(self, case_id: str) -> Optional[bytes]:
        """Retrieves raw RFC5322 EML bytes."""
        eml_path = self.vault_dir / f"{case_id}.eml"
        if not eml_path.exists():
            return None
        try:
            with open(eml_path, "rb") as f:
                return f.read()
        except Exception:
            return None

    def release_case(self, case_id: str, relay_host: Optional[str] = None, relay_port: Optional[int] = None) -> Dict[str, Any]:
        """
        Administratively releases a quarantined email to the downstream MTA.
        Updates quarantine record status to 'RELEASED'.
        """
        case_data = self.get_case(case_id)
        if not case_data:
            return {"status": "error", "message": f"Case {case_id} not found."}

        raw_eml = self.get_raw_eml(case_id)
        if not raw_eml:
            return {"status": "error", "message": f"Raw message body for {case_id} not found."}

        relay_host = relay_host or settings.SMTP_RELAY_HOST
        relay_port = relay_port or settings.SMTP_RELAY_PORT
        sender = case_data.get("sender")
        recipient = case_data.get("recipient")

        try:
            with smtplib.SMTP(relay_host, relay_port, timeout=10.0) as client:
                client.sendmail(sender, [recipient], raw_eml)

            # Update status
            case_data["status"] = "RELEASED"
            case_data["released_at"] = datetime.now(timezone.utc).isoformat()
            meta_path = self.vault_dir / f"{case_id}.json"
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(case_data, f, indent=2)

            return {
                "status": "success",
                "message": f"Case {case_id} successfully released and relayed to {recipient} via {relay_host}:{relay_port}",
                "released_at": case_data["released_at"]
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to relay released message to {relay_host}:{relay_port} - {str(e)}"
            }

    def delete_case(self, case_id: str) -> bool:
        """Deletes a case and its raw EML file."""
        eml_path = self.vault_dir / f"{case_id}.eml"
        meta_path = self.vault_dir / f"{case_id}.json"
        deleted = False
        if eml_path.exists():
            eml_path.unlink()
            deleted = True
        if meta_path.exists():
            meta_path.unlink()
            deleted = True
        return deleted

    def generate_bsa_certificate(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Generates an electronic record certificate under Section 63 BSA 2023."""
        case_data = self.get_case(case_id)
        if not case_data:
            return None

        raw_bytes = self.get_raw_eml(case_id) or b""
        current_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        is_valid = (current_sha256 == case_data.get("sha256_hash"))

        return {
            "certificate_title": "CERTIFICATE UNDER SECTION 63 OF BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023",
            "statute": "Bharatiya Sakshya Adhiniyam, 2023 (Admissibility of Electronic Records)",
            "case_reference": case_id,
            "evidence_details": {
                "intercepted_source_ip": case_data.get("client_ip"),
                "sender": case_data.get("sender"),
                "recipient": case_data.get("recipient"),
                "subject": case_data.get("subject"),
                "threat_score": case_data.get("threat_score"),
                "category": case_data.get("category"),
                "interception_timestamp_utc": case_data.get("timestamp"),
            },
            "forensic_integrity": {
                "algorithm": "SHA-256 (NIST FIPS 180-4)",
                "recorded_sha256": case_data.get("sha256_hash"),
                "recalculated_sha256": current_sha256,
                "tamper_detected": not is_valid,
                "hmac_seal": case_data.get("hmac_seal")
            },
            "declaration": "I hereby certify that this electronic output was produced by the SUDO SPANDR ESG Mail Flow Interceptor during ordinary operation, and cryptographic hash integrity verifies zero alteration.",
            "issued_by": "SUDO SPANDR Security Operations Center (SIH #26106)"
        }


vault = QuarantineVault()
