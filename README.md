# Cyber Squad Enterprise Email Security Gateway (ESG v4.0)
### Next-Gen Inbound Mail Flow Interceptor & Postfix Milter Security Daemon
**SIH 2026 Problem Statement #26106 | Team Cyber Squad**

---

## 🛡️ Executive Summary

**Cyber Squad ESG v4.0** is an enterprise-grade Secure Email Gateway designed for real-time inbound mail flow interception, cognitive BEC / CEO-fraud detection, typosquatted brand defense (targeting Bank of Baroda, SBI, etc.), Quishing (QR-phishing) prevention, weaponized attachment disassembly, and cryptographic evidence preservation under **Section 63 of Bharatiya Sakshya Adhiniyam (BSA), 2023**.

```
                           [ Inbound Mail Stream ]
                                      │
                                      ▼
               ┌──────────────────────────────────────────────┐
               │    Cyber Squad ESG Interceptor (v4.0.0)      │
               │  • SMTP Proxy (:10025)   • Milter (:8893)    │
               └──────────────────────┬───────────────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
          [ Threat Engine ]   [ Live DNS Auth ]    [ Web Core API ]
          • BEC Cognitive     • SPF Validation     • Deep Triage
          • Typosquatting     • DKIM Parser        • CatBERT AI
          • Quishing / QR     • DMARC Alignment    • Failover Hub
          • File Polyglots    • Relay Tracker
                 └────────────────────┬────────────────────┘
                                      │
                                      ▼
            ┌────────────────────────────────────────────────────┐
            │            Policy Enforcement Matrix               │
            │  • Threat < 40:   ACCEPT & Relay Clean             │
            │  • 40 <= T < 75:  TAG [SUSPICIOUS] & Route to Spam │
            │  • Threat >= 75:  SMTP 550 REJECT / QUARANTINE     │
            └─────────┬──────────────────────────┬───────────────┘
                      │                          │
                      ▼                          ▼
           [ Downstream Mailbox ]    [ Section 63 BSA Vault ]
           Postfix / Exim / Inbox    Cryptographic SHA-256 Seal
```

---

## ✨ Key Capabilities & Modern Architecture

1. **Dual-Mode Interception Support**:
   - **Mode A: Asynchronous RFC 5321 SMTP Transparent Proxy** (`0.0.0.0:10025`): Zero-dependency pure Python `asyncio` proxy that inspects MIME streams, injects forensic headers, and relays clean mail to downstream MTAs.
   - **Mode B: Native Postfix Milter Protocol Daemon** (`0.0.0.0:8893` / Unix Socket): High-throughput Sendmail/Postfix Milter wire protocol handler.
2. **Next-Gen Heuristic & Behavioral Threat Engine**:
   - **BEC & CEO Fraud:** Detects urgent executive wire transfer directives, offshore routing requests, and cognitive pressure patterns in `< 5ms`.
   - **Brand Lookalike / Typosquatting:** Evaluates domain edit distances against monitored banking institutions (Bank of Baroda, SBI, HDFC, ICICI, etc.) and catches Punycode (`xn--`) attacks.
   - **Quishing (QR-Code Phishing):** Detects QR scan lures for 2FA / MFA authentication token harvesting.
   - **Dangerous Attachment Inspector:** Catches double extensions (`.pdf.exe`), macro-enabled containers, and executable magic bytes (`MZ`, `ELF`).
   - **AiTM & Malicious URL Scanner:** Identifies direct IP hostnames, deep subdomain nesting, and credential harvesting paths.
3. **Live DNS Email Authentication**:
   - Real-time DNS SPF record evaluation against sender IP.
   - DKIM signature parsing and alignment checks.
   - RFC 7489 DMARC policy enforcement.
4. **Section 63 BSA 2023 Evidence Quarantine Vault**:
   - Stores raw intercepted RFC5322 EML messages with HMAC-SHA256 integrity seals.
   - One-click Section 63 Electronic Evidence Certificate generation.
   - Administrative release, raw EML export, and deletion capabilities.
5. **Real-time SOC Web Dashboard & Prometheus Metrics**:
   - Embedded single-page Dark-Theme SOC Web interface on `http://localhost:8002/`.
   - Live attack map, stats counters, Quarantine Manager, and Attack Simulator.
   - Native `/metrics` endpoint for Prometheus / Grafana scraping.
   - Server-Sent Events (SSE) and WebSocket live telemetry streaming.
6. **SIEM & Webhook Alerting**:
   - Automated notification dispatching to Slack Block Kit, Discord, or SOC SIEM endpoints on high-threat detections.

---

## 🚀 Quick Start & Installation

### 1. Install Dependencies:
```bash
pip install -r requirements.txt
```

### 2. Launch Unified ESG Services:
```bash
# Starts SMTP Proxy (:10025), Milter (:8893), and SOC Dashboard (:8002)
python3 cli.py start
```

### 3. Open Web SOC Dashboard:
Open your browser and navigate to: **`http://localhost:8002`**

---

## 💻 CLI Commands & Testing

```bash
# 1. Run multi-vector attack & policy simulation
python3 cli.py simulate

# 2. Start standalone Milter daemon
python3 milter_daemon.py --serve --port 8893

# 3. Send a test email through the SMTP Gateway
python3 cli.py test-smtp --sender attacker@b0b-security-update.in --subject "URGENT: Wire Transfer"

# 4. List all quarantined items in vault
python3 cli.py quarantine-list

# 5. Inject synthetic traffic stream into the gateway
python3 simulate_traffic.py --count 2 --delay 0.5

# 6. Run automated test suite
python3 test_gateway_suite.py
```

---

## ⚙️ Postfix MTA Integration (`main.cf`)

To connect Cyber Squad ESG Milter directly into your production or staging Postfix mail server:

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:8893
non_smtpd_milters = inet:127.0.0.1:8893
milter_default_action = accept
milter_protocol = 6
milter_connect_macros = j {daemon_name} v
milter_helo_macros = {tls_version} {cipher} {cipher_bits}
milter_mail_macros = i {auth_type} {auth_authen}
```

Reload Postfix:
```bash
sudo postfix reload
```

---

## 📡 REST API & Prometheus Metrics Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Embedded Cyber SOC Web Dashboard |
| `/health` | `GET` | Health check & active socket status |
| `/metrics` | `GET` | Prometheus exposition format metrics |
| `/api/v1/stats` | `GET` | Operational throughput and threat statistics |
| `/api/v1/inspect` | `POST` | Inspect raw email payload (JSON) |
| `/api/v1/quarantine` | `GET` | List quarantined forensic records |
| `/api/v1/quarantine/{id}` | `GET` | Detailed case metadata |
| `/api/v1/quarantine/{id}/raw` | `GET` | Download raw RFC5322 EML file |
| `/api/v1/quarantine/{id}/bsa-certificate` | `GET` | Section 63 BSA 2023 certificate |
| `/api/v1/quarantine/{id}/release` | `POST` | Release quarantined email to recipient |
| `/api/v1/live-feed` | `GET` | Server-Sent Events (SSE) live SOC stream |

---

## 🐳 Docker Deployment

```bash
# Build and start via Docker Compose
docker-compose up -d --build

# View container logs
docker-compose logs -f
```

---

## ⚖️ Compliance & Legal Admissibility

All intercepted high-threat payloads preserved by Cyber Squad ESG conform to **Section 63 of Bharatiya Sakshya Adhiniyam (BSA), 2023** governing the legal admissibility of electronic evidence in Indian courts of law, with cryptographic SHA-256 timestamping and HMAC tamper-evident proof seals.
