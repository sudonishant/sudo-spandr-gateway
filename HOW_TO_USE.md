# 📘 SUDO SPANDR Enterprise ESG - Complete User & Operation Guide
### Kaise Use Karein / Step-by-Step Practical Manual
**SIH 2026 Problem Statement #26106 | Team SUDO SPANDR**

---

## 📑 Table of Contents
1. [Prerequisites & Quick Setup](#1-prerequisites--quick-setup)
2. [Starting the Gateway (1-Click & CLI)](#2-starting-the-gateway)
3. [Using the Web SOC Dashboard](#3-using-the-web-soc-dashboard)
4. [Testing Attack Scenarios (Simulation)](#4-testing-attack-scenarios)
5. [Sending Real Emails Through SMTP Gateway](#5-sending-real-emails-through-smtp-gateway)
6. [Quarantine Vault & Section 63 BSA Certificates](#6-quarantine-vault--section-63-bsa-certificates)
7. [Integrating with Postfix / Production MTAs](#7-integrating-with-postfix--production-mtas)
8. [Programmatic Python API Usage](#8-programmatic-python-api-usage)
9. [Docker & Containerized Launch](#9-docker--containerized-launch)
10. [Troubleshooting & FAQs](#10-troubleshooting--faqs)

---

## 1. Prerequisites & Quick Setup

### System Requirements:
- **Operating System:** Linux / macOS / Windows (WSL recommended for Windows)
- **Python:** Python 3.9+ (Python 3.10, 3.11, 3.12, 3.13, 3.14 fully supported)
- **Dependencies:** Listed in `requirements.txt` (zero external C-libraries needed!)

### Installation Steps:
```bash
# Navigate to the gateway repository
cd "/home/nee/Desktop/sih email/sudospandr-gateway-master"

# (Optional) Create & activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python requirements
pip install -r requirements.txt
```

---

## 2. Starting the Gateway

Aap gateway ko **3 alag tareeqon (methods)** se start kar sakte hain:

### Method A: 1-Click Shell Script (Sabse Simple)
```bash
./start_gateway.sh
```

### Method B: Unified CLI Runner
```bash
# Starts SMTP Proxy (:10025), Milter (:8893), and Web SOC (:8002)
python3 cli.py start
```

### Method C: Custom Ports / Host
```bash
python3 cli.py start --host 0.0.0.0 --smtp-port 10025 --milter-port 8893 --api-port 8002
```

Jab gateway start hoga, aapko terminal par green status confirmation dikhega:
```text
✓ ALL GATEWAY SINK INTERCEPTORS ONLINE
• SMTP Transparent Proxy:  0.0.0.0:10025
• Postfix Milter Socket:   0.0.0.0:8893
• FastAPI & Web SOC Dashboard: http://localhost:8002
• Prometheus Metrics:      http://localhost:8002/metrics
• Quarantine Storage:      ./quarantine_vault
```

---

## 3. Using the Web SOC Dashboard

Gateway start karne ke baad apne browser me open karein:
👉 **`http://localhost:8002`**

### Dashboard Features & Tabs:

1. **Top Metrics Counters:**
   - **Total Scanned:** Total kitne emails inspect hue.
   - **Clean Delivered:** Score < 40 wale legitimate emails jo bina rukawat deliver hue.
   - **Suspicious Tagged:** 40 <= Score < 75 wale emails jinme `[SUSPICIOUS]` tag add kiya gaya.
   - **Quarantined Vault:** Intercepted high-threat emails jo cryptographic hash ke saath safe vault me lock hain.
   - **Hard Rejected:** Score >= 75 wale critical threats jinhe SMTP 550 reject diya gaya.
   - **Avg Scan Time:** Real-time latency (normally 2ms - 8ms).

2. **Tab 1: Live Interception Feed (`Live Stream`)**
   - Inbound email connections live table me dynamically stream hote hain (via Server-Sent Events).
   - Case ID, Sender, Recipient, Threat Score, Category, aur Policy Action display hota hai.

3. **Tab 2: Evidence Quarantine Vault**
   - Quarantined emails ki poori list dekhein.
   - **Section 63 BSA Certificate:** `Stamp` icon click karke legal court-admissible certificate generate aur view karein.
   - **Raw EML Download:** `Download` icon se original intercepted `.eml` file download karein.
   - **Release to Mailbox:** `Paper Plane` icon click karke email ko recipient ke mailbox me release karein.

4. **Tab 3: Attack & Policy Simulator**
   - Alag-alag email attacks simulate karke gateway ka verdict test karein:
     - 💼 *CEO Wire Transfer ($25.6M)*
     - 🏦 *Bank of Baroda Phishing Spoof*
     - 📱 *2FA Quishing QR Code Attack*
     - 💣 *Double Extension Malware (.pdf.exe)*
     - ✅ *Clean Business Meeting*
   - Preset button par click karein aur **"EXECUTE ESG INTERCEPTION SIMULATION"** dabayein. Output me live threat breakdown, score, aur injected forensic headers dikhenge.

5. **Tab 4: Postfix & Topology Guide**
   - Production Postfix server ke configuration snippets copy karne ke liye reference.

---

## 4. Testing Attack Scenarios (Simulation)

Aap terminal se direct **multi-vector automated simulation** chala sakte hain:

```bash
python3 cli.py simulate
```

### Output Example:
```text
                       GATEWAY POLICY ENFORCEMENT MATRIX                        
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Scenario /      ┃ Threat ┃        ┃ Policy ┃ Milter ┃                        ┃
┃ Vector          ┃ Score  ┃ Verdict┃ Action ┃ Code   ┃ Key Findings           ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1. Executive BEC│  100%  │ MALIC..│ QUARAN.│ Milter.│ • BEC / CEO Fraud Cues │
│ Wire Transfer   │        │        │        │ REJECT │ • Reply-To Mismatch    │
│ 2. Bank of      │  85%   │ MALIC..│ QUARAN.│ Milter.│ • Direct IP in URL     │
│ Baroda Spoof    │        │        │        │ REJECT │ • Credential Harvest   │
│ 3. 2FA Quishing │  55%   │ SUSPIC.│ TAG_SUB│ Milter.│ • QR Code Attack Vector│
│ QR Attack       │        │        │        │ QUARAN.│ • Missing Message-ID  │
│ 4. Double Ext   │  100%  │ MALIC..│ QUARAN.│ Milter.│ • Double Extension     │
│ Malware (.exe)  │        │        │        │ REJECT │ • Dangerous Executable │
│ 5. Clean Sprint │   0%   │ CLEAN  │ ACCEPT │ Milter.│ No threats detected    │
│ Team Minutes    │        │        │        │ CONTIN.│                        │
└─────────────────┴────────┴────────┴────────┴────────┴────────────────────────┘
```

---

## 5. Sending Real Emails Through SMTP Gateway

Jab gateway active ho (`python3 cli.py start`), aap real SMTP messages port `10025` par bhejkar test kar sakte hain:

### Method 1: Using Built-in CLI Test Tool
```bash
# Test High-Threat BEC Email
python3 cli.py test-smtp \
  --sender "attacker@b0b-security-update.in" \
  --recipient "finance@company.com" \
  --subject "URGENT: Confidential Wire Transfer Needed ($25.6M)" \
  --body "Please wire $25.6M to our external account immediately. Do not disclose."

# Test Clean Email
python3 cli.py test-smtp \
  --sender "colleague@partner.com" \
  --recipient "user@company.com" \
  --subject "Team Roadmap Discussion" \
  --body "Hi, please review the sprint roadmap attached in the wiki."
```

### Method 2: Injecting a Batch of Synthetic Mail Traffic
```bash
# Injects realistic traffic streams with delays into Port 10025
python3 simulate_traffic.py --count 2 --delay 0.5
```

### Method 3: Using Standard Python `smtplib`
```python
import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Please wire $25.6M immediately to our external account.")
msg["From"] = "ceo@fake-executive.in"
msg["To"] = "employee@company.com"
msg["Subject"] = "URGENT: Confidential Wire Transfer"

with smtplib.SMTP("127.0.0.1", 10025) as s:
    s.sendmail(msg["From"], [msg["To"]], msg.as_string())
```

---

## 6. Quarantine Vault & Section 63 BSA Certificates

Sabhi intercepted high-threat emails **`quarantine_vault/`** directory me cryptographically seal ho jate hain.

### CLI se Quarantine List dekhna:
```bash
python3 cli.py quarantine-list
```

### Section 63 BSA 2023 Certificate Structure:
Electronic evidence Indian Courts me admissible banane ke liye har case ka SHA-256 integrity seal hota hai:
```json
{
  "certificate_title": "CERTIFICATE UNDER SECTION 63 OF BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023",
  "statute": "Bharatiya Sakshya Adhiniyam, 2023 (Admissibility of Electronic Records)",
  "case_reference": "CS-ESG-250647566A",
  "evidence_details": {
    "sender": "attacker@b0b-security-update.in",
    "recipient": "user@company.com",
    "threat_score": 100,
    "category": "Business Email Compromise (BEC)"
  },
  "forensic_integrity": {
    "algorithm": "SHA-256 (NIST FIPS 180-4)",
    "recorded_sha256": "250647566af4f396f7c244f0581a887940fddb21865ca0d0f69360e72cdf430a",
    "tamper_detected": false
  }
}
```

---

## 7. Integrating with Postfix / Production MTAs

### Step 1: Postfix Configuration
Apne mail server ki `/etc/postfix/main.cf` file me ye lines add karein:
```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:8893
non_smtpd_milters = inet:127.0.0.1:8893
milter_default_action = accept
milter_protocol = 6
```

### Step 2: Reload Postfix
```bash
sudo postfix reload
```

### Step 3: Run Milter Daemon in Background
```bash
python3 milter_daemon.py --serve --port 8893 &
```

---

## 8. Programmatic Python API Usage

Aap apne custom Python applications me directly SUDO SPANDR Gateway ke engine ko import karke use kar sakte hain:

```python
from gateway.engine.inspector import GatewayInspector

# Initialize Inspector
inspector = GatewayInspector()

# Inspect Inbound Message
result = inspector.inspect(
    sender="attacker@b0b-security-update.in",
    recipient="victim@company.com",
    subject="URGENT: Wire Transfer Needed",
    body="Please wire $25.6M immediately to external account."
)

print(f"Case ID: {result.case_id}")
print(f"Threat Score: {result.threat_score}%")
print(f"Verdict: {result.verdict}")             # CLEAN, SUSPICIOUS, MALICIOUS
print(f"Action: {result.policy_action}")        # ACCEPT, TAG_SUBJECT, QUARANTINE, REJECT
print(f"Milter Code: {result.postfix_code}")    # Milter.CONTINUE, Milter.REJECT
```

---

## 9. Docker & Containerized Launch

Production ya cloud server par deploy karne ke liye Docker Compose use karein:

```bash
# Build and start container in background
docker-compose up -d --build

# View container logs
docker-compose logs -f

# Check health
curl http://localhost:8002/health
```

---

## 10. Troubleshooting & FAQs

### Q1: `Address already in use` error aata hai to kya karein?
**Ans:** Port 10025, 8893 ya 8002 par pehle se koi service chal rahi ho sakti hai.
```bash
# Find and terminate existing process
fuser -k 10025/tcp 8893/tcp 8002/tcp
# Phir dobara start karein
python3 cli.py start
```

### Q2: Automated tests kaise run karein?
```bash
python3 test_gateway_suite.py
```

### Q3: Prometheus / Grafana me metrics kaise integrate karein?
**Ans:** Prometheus config me target add karein `localhost:8002` path `/metrics`.

---
*Developed with pride by **Team SUDO SPANDR** for **Smart India Hackathon 2026 (Problem Statement #26106)**.*
