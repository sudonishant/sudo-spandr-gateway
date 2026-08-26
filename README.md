# Cyber Squad Gateway Agent (Postfix Mail Flow Interceptor) - SIH #26106

Standalone Mail Flow Gateway Daemon (Postfix Milter) for real-time inbound SMTP email interception and policy enforcement by **Team Cyber Squad**.

---

## 🛡️ Policy Enforcement Rules

The Milter daemon connects to the Cyber Squad FastAPI Backend Core (`http://localhost:8001/api/gateway-milter-check`) to evaluate inbound emails in real time:

- **Threat Score < 40:** **`Milter.CONTINUE`** (Deliver to recipient inbox)
- **40 <= Threat Score < 75:** **`Milter.QUARANTINE`** (Append `X-CyberSquad-Suspicious: TRUE` & route to SPAM)
- **Threat Score >= 75:** **`Milter.REJECT`** (Hard SMTP Reject 550 - Access Denied)

---

## 🚀 Usage & Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run Milter Interception Daemon
python3 milter_daemon.py
```

### Postfix `main.cf` Integration:
```text
smtpd_milters = inet:localhost:8893
non_smtpd_milters = inet:localhost:8893
milter_default_action = accept
```
