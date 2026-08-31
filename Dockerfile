FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose ports:
# 10025: Inbound SMTP Proxy
# 8893: Postfix Milter Wire Socket
# 8002: FastAPI Control Plane & Web SOC Dashboard
EXPOSE 10025 8893 8002

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    CS_GW_SMTP_LISTEN_HOST=0.0.0.0 \
    CS_GW_MILTER_LISTEN_HOST=0.0.0.0 \
    CS_GW_API_LISTEN_HOST=0.0.0.0

CMD ["python3", "cli.py", "start", "--host", "0.0.0.0"]
