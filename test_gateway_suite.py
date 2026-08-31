"""
Automated Test Suite for Cyber Squad Enterprise ESG v4.0
Tests Heuristic Engine, Live Auth, Quarantine Vault, Section 63 BSA Integrity, FastAPI, and SMTP Proxy.
"""

import asyncio
import email
import json
import os
import smtplib
import sys
import unittest
from datetime import datetime
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.api import app as fastapi_app
from gateway.config import settings
from gateway.engine.inspector import GatewayInspector
from gateway.quarantine import QuarantineVault
from gateway.smtp_proxy import AsyncSMTPProxyServer, metrics


class TestCyberSquadESG(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(fastapi_app)
        cls.inspector = GatewayInspector()
        cls.test_vault_dir = Path("/tmp/test_cs_quarantine")
        cls.vault = QuarantineVault(vault_dir=cls.test_vault_dir, secret="test-secret-seal-2026")

    @classmethod
    def tearDownClass(cls):
        # Cleanup test vault files
        if cls.test_vault_dir.exists():
            for f in cls.test_vault_dir.glob("*"):
                try:
                    f.unlink()
                except Exception:
                    pass
            try:
                cls.test_vault_dir.rmdir()
            except Exception:
                pass

    def test_01_bec_detection(self):
        """Test Executive BEC Wire Transfer Detection."""
        res = self.inspector.inspect(
            sender="ceo@company-executive-desk.in",
            recipient="accountant@company.com",
            subject="URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)",
            body="Please wire $25.6M immediately to our external bank account. Strictly confidential, do not disclose to team members. Sent from my iPhone."
        )
        self.assertGreaterEqual(res.threat_score, 75)
        self.assertEqual(res.verdict, "MALICIOUS")
        self.assertEqual(res.category, "Business Email Compromise (BEC)")
        self.assertEqual(res.postfix_code, "Milter.REJECT")

    def test_02_typosquatting_detection(self):
        """Test Bank of Baroda Typosquatted Domain Detection."""
        res = self.inspector.inspect(
            sender="alerts@b0b-bank-security.in",
            recipient="user@company.com",
            subject="Bank of Baroda Security Update",
            body="Please verify your account at http://192.168.1.10/login to prevent suspension."
        )
        self.assertGreaterEqual(res.threat_score, 75)
        self.assertEqual(res.verdict, "MALICIOUS")
        # Check that typosquatting / lookalike finding was raised
        finding_rules = [f["rule_id"] for f in res.findings]
        self.assertTrue(any("DOM-" in r or "URL-" in r for r in finding_rules))

    def test_03_quishing_detection(self):
        """Test Quishing QR Code Phishing Detection."""
        res = self.inspector.inspect(
            sender="admin@cloud-service.com",
            recipient="user@company.com",
            subject="2FA Security Update Required",
            body="Please scan the below QR code with your mobile authenticator app.\n<img src='data:image/png;base64,...' />"
        )
        self.assertGreaterEqual(res.threat_score, 40)
        finding_rules = [f["rule_id"] for f in res.findings]
        self.assertTrue(any("QUISH-" in r for r in finding_rules))

    def test_04_dangerous_attachment(self):
        """Test Double Extension Attachment Detection."""
        res = self.inspector.inspect(
            sender="billing@vendor.com",
            recipient="user@company.com",
            subject="Overdue Invoice",
            body="Please find attached overdue invoice.",
            attachments=[{"filename": "Invoice_Overdue.pdf.exe", "content_type": "application/octet-stream", "size": 12000}]
        )
        self.assertGreaterEqual(res.threat_score, 75)
        self.assertEqual(res.verdict, "MALICIOUS")
        finding_rules = [f["rule_id"] for f in res.findings]
        self.assertTrue(any("ATT-DOUBLE-EXT-01" in r for r in finding_rules))

    def test_05_clean_message(self):
        """Test Clean Internal Message."""
        res = self.inspector.inspect(
            sender="colleague@partner.com",
            recipient="user@partner.com",
            subject="Meeting Minutes & Sprint Plan",
            body="Thanks for the discussion today. The notes have been updated.",
            headers={"message-id": "<test-clean-123@partner.com>", "date": "Mon, 31 Aug 2026 12:00:00 +0000"}
        )
        self.assertLess(res.threat_score, 40)
        self.assertEqual(res.verdict, "CLEAN")
        self.assertEqual(res.policy_action, "ACCEPT")
        self.assertEqual(res.postfix_code, "Milter.CONTINUE")

    def test_06_quarantine_vault_and_bsa_cert(self):
        """Test Cryptographic Quarantine Vault and Section 63 BSA Certificate."""
        case_id = "CS-TEST-QUAR-01"
        sample_eml = b"From: attacker@evil.com\nTo: victim@company.com\nSubject: Test Malicious\n\nMalicious content"
        
        # Store
        meta = self.vault.store(
            case_id=case_id,
            raw_eml_bytes=sample_eml,
            sender="attacker@evil.com",
            recipient="victim@company.com",
            subject="Test Malicious",
            threat_score=95,
            category="Malware Delivery",
            findings=[{"title": "Test Finding", "score_impact": 95}],
            auth_summary={"spf_status": "FAIL"}
        )
        self.assertEqual(meta["case_id"], case_id)
        self.assertTrue(meta["hmac_seal"])

        # Retrieve
        case = self.vault.get_case(case_id)
        self.assertIsNotNone(case)
        self.assertEqual(case["status"], "QUARANTINED")

        # Verify BSA Section 63 Certificate
        cert = self.vault.generate_bsa_certificate(case_id)
        self.assertIsNotNone(cert)
        self.assertFalse(cert["forensic_integrity"]["tamper_detected"])
        self.assertEqual(cert["forensic_integrity"]["recorded_sha256"], cert["forensic_integrity"]["recalculated_sha256"])

    def test_07_fastapi_endpoints(self):
        """Test FastAPI Health, Prometheus Metrics, and REST Inspect API."""
        # Health
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "healthy")

        # Prometheus Metrics
        res = self.client.get("/metrics")
        self.assertEqual(res.status_code, 200)
        self.assertIn("cybersquad_esg_scanned_total", res.text)
        self.assertIn("cybersquad_esg_quarantined_total", res.text)

        # Inspect REST API
        payload = {
            "sender": "attacker@b0b-bank.in",
            "recipient": "victim@company.com",
            "subject": "Urgent Bank Notice",
            "body": "Please verify your account immediately at http://192.168.1.50/login."
        }
        res = self.client.post("/api/v1/inspect", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("threat_score", data)
        self.assertIn("verdict", data)
        self.assertIn("postfix_code", data)

        # Dashboard HTML
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("CYBER SQUAD", res.text)


if __name__ == "__main__":
    unittest.main()
