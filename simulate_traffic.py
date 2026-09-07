#!/usr/bin/env python3
"""
Real-time Inbound Mail Flow Traffic Generator for SUDO SPANDR ESG.
Sends diverse realistic email streams (BEC, Spoofs, Malware, Quishing, Legitimate)
directly through the live SMTP Gateway (Port 10025) or Milter Socket to populate SOC metrics.
"""

import smtplib
import time
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

TRAFFIC_SAMPLES = [
    {
        "name": "BEC Executive Wire Fraud ($25.6M) via Bulletproof Russian Relay",
        "from": "executive-desk@b0b-finance-update.in",
        "to": "treasury@corporate-client.com",
        "subject": "URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)",
        "body": "Please wire $25.6M immediately to our offshore supplier account. Strictly confidential, do not disclose to others. Sent from my iPhone in a board meeting.",
        "headers": {
            "Received": "from bp-relay.c2-host.ru ([194.26.29.112]) by mail.corporate-client.com (Postfix, TLSv1.3) with ESMTPS id 3R9L8K; Mon, 07 Sep 2026 15:10:00 +0000",
            "Reply-To": "drop-box@attacker-route.ru"
        }
    },
    {
        "name": "Bank of Baroda Phishing Account Notice via German Tor Exit Node",
        "from": "security-alert@b0b-bank-security.in",
        "to": "user@corporate-client.com",
        "subject": "Action Required: Bank of Baroda Account Suspension Notice",
        "body": "Your corporate account will be suspended within 24 hours. Sign in at http://192.168.1.10/login/bob-secure to verify identity.",
        "headers": {
            "Received": "from tor-exit.zwiebelfreunde.de ([185.220.101.5]) by mail.corporate-client.com (Postfix, TLSv1.3) with ESMTPS id 8Q2X1M; Mon, 07 Sep 2026 15:12:00 +0000",
            "Received-SPF": "fail"
        }
    },
    {
        "name": "Quishing 2FA Security Update",
        "from": "security-admin@cloud-tenant-update.com",
        "to": "staff@corporate-client.com",
        "subject": "Microsoft Authenticator 2FA Security Update Required",
        "body": "Please scan the below QR code with your phone authenticator app.\n\n<img src='data:image/png;base64,...' />",
        "headers": {
            "Received": "from mx01.cloud-tenant-update.com ([199.249.230.70]) by mail.corporate-client.com with ESMTP id 9A1B2C; Mon, 07 Sep 2026 15:13:00 +0000"
        }
    },
    {
        "name": "Weaponized Double Extension Malware Delivery (.pdf.exe)",
        "from": "invoice-dept@vendor-billing-desk.net",
        "to": "accounts@corporate-client.com",
        "subject": "Overdue Invoice #INV-2026-9901 - Payment Pending",
        "body": "Please find attached the signed receipt and overdue invoice. Remit payment today.",
        "attachment_name": "Invoice_Overdue_Statement.pdf.exe",
        "headers": {
            "Received": "from outbound.vendor-billing-desk.net ([91.240.118.172]) by mail.corporate-client.com with ESMTPS id 7Z8Y9X; Mon, 07 Sep 2026 15:14:00 +0000"
        }
    },
    {
        "name": "LockBit 4.0 Weaponized VBA Macro Document (.docm)",
        "from": "procurement@contract-defense.org",
        "to": "cfo@corporate-client.com",
        "subject": "PRIORITY: Revised Defense Contract Addendum #8821",
        "body": "Please review the attached contract addendum. Enable macros when prompted to load automated audit signatures.",
        "attachment_name": "Defense_Addendum_Rev4.docm",
        "headers": {
            "Received": "from mail.contract-defense.org ([185.220.101.6]) by mail.corporate-client.com with ESMTPS id 5F4E3D; Mon, 07 Sep 2026 15:15:00 +0000"
        }
    },
    {
        "name": "Clean Project Weekly Sync",
        "from": "alice.dev@trusted-partner.com",
        "to": "team@corporate-client.com",
        "subject": "Weekly Sprint Notes and Action Items",
        "body": "Hi team, great work on finishing milestone 3 ahead of schedule. The demo is scheduled for Thursday.",
        "headers": {"Message-ID": "<2026-sync-alice@trusted-partner.com>", "Date": "Mon, 31 Aug 2026 14:00:00 +0000"}
    },
    {
        "name": "Clean Vendor Renewal Quotation",
        "from": "renewals@aws-licensing.com",
        "to": "it-procurement@corporate-client.com",
        "subject": "Annual Cloud Support Contract Renewal",
        "body": "Hello, your enterprise cloud support agreement is up for standard renewal next month. Quotation details are on the portal.",
        "headers": {"Message-ID": "<renewals-2026@aws-licensing.com>", "Date": "Mon, 31 Aug 2026 14:05:00 +0000"}
    }
]


def send_traffic(host: str = "127.0.0.1", port: int = 10025, count: int = 1, delay: float = 1.0):
    print(f"[*] Dispatching {count} batches of synthetic inbound email traffic to {host}:{port}...")

    total_sent = 0
    for round_num in range(1, count + 1):
        print(f"\n--- Batch #{round_num} ---")
        for sample in TRAFFIC_SAMPLES:
            msg = MIMEMultipart()
            msg["From"] = sample["from"]
            msg["To"] = sample["to"]
            msg["Subject"] = sample["subject"]

            for k, v in sample.get("headers", {}).items():
                msg[k] = v

            msg.attach(MIMEText(sample["body"], "plain"))

            if "attachment_name" in sample:
                part = MIMEApplication(b"MZ\x90\x00\x03\x00\x00\x00DummyExecutableBytes", Name=sample["attachment_name"])
                part["Content-Disposition"] = f'attachment; filename="{sample["attachment_name"]}"'
                msg.attach(part)

            try:
                with smtplib.SMTP(host, port, timeout=5.0) as client:
                    client.sendmail(sample["from"], [sample["to"]], msg.as_string())
                    print(f"[+] Sent: {sample['name']} -> ACCEPTED/TAGGED/QUARANTINED by Gateway")
            except smtplib.SMTPResponseException as e:
                print(f"[-] Policy Blocked: {sample['name']} -> 550 REJECTED ({e.smtp_code})")
            except Exception as e:
                print(f"[!] Connection failed: {e}")

            total_sent += 1
            if delay > 0:
                time.sleep(delay)

    print(f"\n[✓] Finished injecting {total_sent} synthetic inbound messages.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SUDO SPANDR ESG Synthetic Traffic Injector")
    parser.add_argument("--host", default="127.0.0.1", help="SMTP Gateway host")
    parser.add_argument("--port", type=int, default=10025, help="SMTP Gateway port")
    parser.add_argument("--count", type=int, default=1, help="Number of batches")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between messages in seconds")

    args = parser.parse_args()
    send_traffic(host=args.host, port=args.port, count=args.count, delay=args.delay)
