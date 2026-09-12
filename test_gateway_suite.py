"""
Automated Test Suite for SUDO SPANDR Enterprise ESG v4.0
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


class TestSudoSpandrESG(unittest.TestCase):

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
        self.assertIn("sudospandr_esg_scanned_total", res.text)
        self.assertIn("sudospandr_esg_quarantined_total", res.text)

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
        self.assertIn("SUDO SPANDR", res.text)

    def test_08_forensic_autopsy_suite(self):
        """Test Deep Email Forensic Autopsy Engine (Multi-Hop, MITRE, Cognitive, CDR, BSA Sec 63)."""
        eml_headers = {
            "received": "from relay.onion-exit.de (unknown [185.220.101.5]) by mta.victimcorp.com (Postfix, TLSv1.3) with ESMTPS id 4X9Kz; Mon, 07 Sep 2026 14:15:00 +0000",
            "from": "CEO <ceo@exec-corp.in>",
            "to": "cfo@exec-corp.in",
            "subject": "CONFIDENTIAL: Urgent Financial Wire Instruction",
            "date": "Mon, 07 Sep 2026 14:14:30 +0000"
        }
        eml_body = "CFO, please initiate an urgent wire transfer of $450,000 to our vendor immediately before 5 PM. Keep this confidential."
        attachments = [{
            "filename": "remittance_invoice.pdf.exe",
            "content_type": "application/x-msdownload",
            "size": 524288,
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        }]

        res = self.inspector.inspect(
            sender="ceo@exec-corp.in",
            recipient="cfo@exec-corp.in",
            subject=eml_headers["subject"],
            body=eml_body,
            headers=eml_headers,
            attachments=attachments,
            client_ip="185.220.101.5"
        )

        self.assertIsNotNone(res.autopsy_dossier)
        dossier = res.autopsy_dossier

        # 1. Multi-hop relay validation
        hops = dossier["hop_sequence"]
        self.assertGreaterEqual(len(hops), 1)
        self.assertTrue(hops[0]["is_tor_or_vpn"])
        self.assertEqual(hops[0]["threat_intel"]["type"], "Tor Exit Node")

        # 2. Cognitive Linguistics validation
        cog = dossier["cognitive_profile"]
        self.assertGreater(cog["composite_psychological_index"], 40)
        self.assertGreater(cog["financial_urgency_score"], 0)

        # 3. CDR Disarm validation
        cdr = dossier["cdr_disarm_reports"]
        self.assertEqual(len(cdr), 1)
        self.assertEqual(cdr[0]["disarm_action"], "ISOLATED_PE_TRAP")
        self.assertFalse(cdr[0]["safe_to_render"])

        # 4. MITRE ATT&CK validation
        mitre = dossier["mitre_attack_matrix"]
        self.assertGreaterEqual(len(mitre), 1)
        mitre_ids = [m["id"] for m in mitre]
        self.assertTrue(any(t in mitre_ids for t in ["T1656", "T1036.007", "T1566.001"]))

        # 5. Section 63 BSA 2023 Certificate validation
        bsa = dossier["bsa_section_63_certificate"]
        self.assertIn("Bharatiya Sakshya Adhiniyam", bsa["statute"])
        self.assertEqual(bsa["cryptographic_verification"]["recorded_hash"], res.evidence_sha256)

    def test_09_autopsy_rest_api(self):
        """Test Autopsy REST API retrieval."""
        # Inspect and store a malicious email
        payload = {
            "sender": "ceo@company-executive-desk.in",
            "recipient": "cfo@company.com",
            "subject": "URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)",
            "body": "Please wire $25.6M immediately to our external bank account. Strictly confidential, do not disclose to team members. Sent from my iPhone.",
            "client_ip": "185.220.101.6"
        }
        insp_res = self.client.post("/api/v1/inspect", json=payload)
        self.assertEqual(insp_res.status_code, 200)
        case_id = insp_res.json()["case_id"]

        # Call autopsy endpoint
        autopsy_res = self.client.get(f"/api/v1/autopsy/{case_id}")
        self.assertEqual(autopsy_res.status_code, 200)
        autopsy_data = autopsy_res.json()
        self.assertEqual(autopsy_data["status"], "success")
        self.assertIn("autopsy_dossier", autopsy_data)
        self.assertEqual(autopsy_data["autopsy_dossier"]["bsa_section_63_certificate"]["case_reference"], case_id.replace("SPANDR-ESG-", "AUTOPSY-"))

    def test_10_archiver_and_analyst_alert(self):
        """Test continuous email archiving (.eml, _report.json, _summary.txt) and analyst notifier."""
        from gateway.archiver import archiver
        from gateway.notifier import notifier

        raw_test_bytes = b"From: attacker@fake-domain.com\nTo: user@target.org\nSubject: Critical Security Notice\n\nImmediate Action Required."
        case_id = "SPANDR-ESG-TEST-ARCHIVE-999"

        # Archive the email
        rec = archiver.archive_message(
            case_id=case_id,
            raw_eml_bytes=raw_test_bytes,
            sender="attacker@fake-domain.com",
            recipient="user@target.org",
            subject="Critical Security Notice",
            threat_score=85,
            verdict="MALICIOUS",
            policy_action="QUARANTINE",
            category="Credential Harvester",
            findings=[{"rule_id": "TEST-R1", "title": "Urgency Trigger", "score": 40, "severity": "HIGH"}],
            auth_summary={"spf_status": "FAIL", "dkim_status": "NONE", "dmarc_status": "FAIL"}
        )

        self.assertEqual(rec["case_id"], case_id)
        self.assertEqual(rec["threat_score"], 85)

        # Verify summary text exists and contains key fields
        summary_text = archiver.get_summary_text(case_id)
        self.assertIsNotNone(summary_text)
        self.assertIn("Critical Security Notice", summary_text)
        self.assertIn("SPANDR-ESG-TEST-ARCHIVE-999", summary_text)
        self.assertIn("Section 63 of Bharatiya Sakshya Adhiniyam", summary_text)

        # Verify case retrieval
        case_data = archiver.get_case(case_id)
        self.assertIsNotNone(case_data)
        self.assertEqual(case_data["sender"], "attacker@fake-domain.com")

        # Test analyst alert dispatch
        alert_res = notifier.notify_analyst(
            case_id=case_id,
            score=85,
            verdict="MALICIOUS",
            category="Credential Harvester",
            sender="attacker@fake-domain.com",
            recipient="user@target.org",
            subject="Critical Security Notice",
            findings=[{"rule_id": "TEST-R1", "title": "Urgency Trigger", "score": 40}],
            summary_text=summary_text
        )
        self.assertIn("desktop", alert_res)
        self.assertIn("telegram", alert_res)
        self.assertIn("webhook", alert_res)
        self.assertIn("email", alert_res)

    def test_11_archive_rest_endpoints(self):
        """Test FastAPI Archive listing and test alert REST endpoints."""
        # 1. Test GET /api/v1/archive
        res = self.client.get("/api/v1/archive")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("cases", data)
        self.assertGreaterEqual(data["total_cases"], 1)

        # 2. Test POST /api/v1/analyst/test-alert
        alert_req = {
            "threat_score": 92,
            "category": "BEC Wire Fraud Test",
            "sender": "attacker@evil-spoof.com",
            "recipient": "analyst@target.com",
            "subject": "Wire Transfer Urgent Test"
        }
        alert_res = self.client.post("/api/v1/analyst/test-alert", json=alert_req)
        self.assertEqual(alert_res.status_code, 200)
        alert_data = alert_res.json()
        self.assertEqual(alert_data["status"], "success")
        self.assertIn("channel_dispatch_results", alert_data)
        self.assertIn("desktop", alert_data["channel_dispatch_results"])


if __name__ == "__main__":
    unittest.main()


