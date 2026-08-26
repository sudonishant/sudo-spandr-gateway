#!/usr/bin/env python3
"""
Cyber Squad Mail Flow Gateway Agent (Postfix Milter / Daemon)
SIH 2026 Problem Statement #26106
"""

import sys
import requests
import json
from typing import Dict, Any

BACKEND_API_URL = "http://localhost:8001/api/gateway-milter-check"

class CyberSquadMilterDaemon:
    def __init__(self, backend_url: str = BACKEND_API_URL):
        self.backend_url = backend_url
        print(f"[Cyber Squad Gateway] Initialized Milter Daemon connecting to {self.backend_url}")
        
    def process_incoming_mail(self, sender: str, recipient: str, subject: str, body: str, headers: dict = None) -> Dict[str, Any]:
        """Intercepts incoming mail stream and queries backend policy enforcer."""
        payload = {
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "headers": headers or {}
        }
        
        try:
            res = requests.post(self.backend_url, json=payload, timeout=3.0)
            if res.status_code == 200:
                data = res.json()
                print(f"[Milter Daemon] Result: {data['postfix_code']} (Threat Score: {data['threat_score']}%)")
                return data
        except Exception as e:
            print(f"[Milter Daemon] Backend offline or timeout: {e}. Falling back to default CONTINUE.")
            
        return {
            "status": "fallback",
            "policy_action": "ACCEPT",
            "postfix_code": "Milter.CONTINUE"
        }

if __name__ == "__main__":
    daemon = CyberSquadMilterDaemon()
    # Test Interception Simulation
    test_result = daemon.process_incoming_mail(
        sender="attacker@b0b-security-update.in",
        recipient="user@company.com",
        subject="URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)",
        body="Please wire $25.6M immediately to our external bank account. Do not disclose."
    )
    print("Test Policy Decision:", json.dumps(test_result, indent=2))
