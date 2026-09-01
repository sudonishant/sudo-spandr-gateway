#!/usr/bin/env bash
# ==============================================================================
# Cyber Squad ESG - Quick Start Runner (SIH 2026 #26106)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "🛡️  STARTING CYBER SQUAD ENTERPRISE EMAIL SECURITY GATEWAY (ESG v4.0)"
echo "======================================================================"

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 is not installed."
    exit 1
fi

# Optional virtual environment activation if exists
if [ -d "venv" ]; then
    echo "[*] Activating virtual environment (venv)..."
    source venv/bin/activate
fi

# Check dependencies
echo "[*] Verifying dependencies..."
python3 -c "import fastapi, uvicorn, pydantic, dnspython, rich, requests" 2>/dev/null || {
    echo "[*] Installing missing dependencies from requirements.txt..."
    pip install -r requirements.txt
}

echo ""
echo "[✓] Launching Unified Services:"
echo "    • SMTP Transparent Proxy : 0.0.0.0:10025"
echo "    • Postfix Milter Socket  : 0.0.0.0:8893"
echo "    • Web SOC Dashboard      : http://localhost:8002"
echo "    • Prometheus Metrics     : http://localhost:8002/metrics"
echo ""
echo "Press Ctrl+C to stop the gateway."
echo "======================================================================"

python3 cli.py start --host 0.0.0.0 --smtp-port 10025 --milter-port 8893 --api-port 8002
