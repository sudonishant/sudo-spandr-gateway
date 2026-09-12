"""
FastAPI Control Plane, REST APIs, Prometheus Metrics & SSE Live Feed for SUDO SPANDR ESG.
"""

from __future__ import annotations
import asyncio
import json
from typing import Any, Dict, List, Optional
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from gateway.config import settings
from gateway.engine.inspector import GatewayInspector
from gateway.quarantine import vault
from gateway.smtp_proxy import metrics
from gateway.archiver import archiver
from gateway.notifier import notifier
from gateway.web_ui import DASHBOARD_HTML


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="SUDO SPANDR Enterprise Mail Flow Security Gateway (ESG) Control Plane",
    version=settings.VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

inspector = GatewayInspector()


class EmailInspectRequest(BaseModel):
    sender: str = Field(default="", max_length=500)
    recipient: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=2_000_000)
    headers: Optional[Dict[str, str]] = None
    attachments: Optional[List[Dict[str, Any]]] = None
    client_ip: Optional[str] = "127.0.0.1"


class RawEmlInspectRequest(BaseModel):
    raw_eml_base64: str = Field(description="Base64 encoded RFC5322 EML message")
    client_ip: Optional[str] = "127.0.0.1"


class QuarantineReleaseRequest(BaseModel):
    relay_host: Optional[str] = None
    relay_port: Optional[int] = None


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the Embedded SUDO SPANDR SOC Web Dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML, status_code=200)


@app.get("/health")
@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for container orchestrators and load balancers."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "smtp_gateway_port": settings.SMTP_LISTEN_PORT,
        "milter_daemon_port": settings.MILTER_LISTEN_PORT,
        "api_port": settings.API_LISTEN_PORT,
        "metrics": {
            "scanned": metrics.total_scanned,
            "quarantined": metrics.quarantined_count,
            "rejected": metrics.rejected_count
        }
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics() -> PlainTextResponse:
    """Exports metrics in standard Prometheus exposition format."""
    stats = metrics.get_stats()
    lines = [
        "# HELP sudospandr_esg_scanned_total Total number of inbound emails scanned",
        "# TYPE sudospandr_esg_scanned_total counter",
        f"sudospandr_esg_scanned_total {stats['total_scanned']}",
        "",
        "# HELP sudospandr_esg_clean_total Total number of clean emails accepted",
        "# TYPE sudospandr_esg_clean_total counter",
        f"sudospandr_esg_clean_total {stats['clean_count']}",
        "",
        "# HELP sudospandr_esg_tagged_total Total number of suspicious emails tagged",
        "# TYPE sudospandr_esg_tagged_total counter",
        f"sudospandr_esg_tagged_total {stats['tagged_count']}",
        "",
        "# HELP sudospandr_esg_quarantined_total Total number of emails sealed in quarantine vault",
        "# TYPE sudospandr_esg_quarantined_total counter",
        f"sudospandr_esg_quarantined_total {stats['quarantined_count']}",
        "",
        "# HELP sudospandr_esg_rejected_total Total number of malicious emails rejected with SMTP 550",
        "# TYPE sudospandr_esg_rejected_total counter",
        f"sudospandr_esg_rejected_total {stats['rejected_count']}",
        "",
        "# HELP sudospandr_esg_latency_ms_avg Average inspection latency in milliseconds",
        "# TYPE sudospandr_esg_latency_ms_avg gauge",
        f"sudospandr_esg_latency_ms_avg {stats['avg_latency_ms']}",
        ""
    ]
    return PlainTextResponse("\n".join(lines), media_type="text/plain; version=0.0.4")


@app.get("/api/v1/stats")
async def get_stats() -> Dict[str, Any]:
    """Retrieves operational gateway metrics and recent inspection logs."""
    return metrics.get_stats()


@app.post("/api/v1/inspect")
@app.post("/api/gateway-milter-check")
@app.post("/api/v1/gateway-milter-check")
async def inspect_email(req: EmailInspectRequest) -> Dict[str, Any]:
    """Inspects an email payload and returns threat scoring, findings, and policy decision."""
    res = inspector.inspect(
        sender=req.sender.strip(),
        recipient=req.recipient.strip(),
        subject=req.subject.strip(),
        body=req.body,
        headers=req.headers or {},
        attachments=req.attachments or [],
        client_ip=req.client_ip or "127.0.0.1"
    )

    # Record metrics for API inspections
    metrics.record(res, req.client_ip or "127.0.0.1", req.sender, req.recipient)

    raw_reconstructed = f"From: {req.sender}\nTo: {req.recipient}\nSubject: {req.subject}\n\n{req.body}".encode("utf-8")

    # Continuous Intercepted Email Archival (All Emails)
    if settings.ENABLE_ALL_MAIL_ARCHIVE:
        try:
            archiver.archive_message(
                case_id=res.case_id,
                raw_eml_bytes=raw_reconstructed,
                sender=req.sender,
                recipient=req.recipient,
                subject=res.original_subject,
                threat_score=res.threat_score,
                verdict=res.verdict,
                policy_action=res.policy_action,
                category=res.category,
                findings=res.findings,
                auth_summary=res.auth_summary,
                client_ip=req.client_ip or "127.0.0.1",
                autopsy_dossier=res.autopsy_dossier
            )
        except Exception as ex:
            print(f"[API] Archive error for {res.case_id}: {ex}")

    # Automated SOC Analyst Alerting for High Threat Emails
    if res.threat_score >= settings.ALERT_ANALYST_MIN_SCORE:
        summary_txt = archiver.get_summary_text(res.case_id) or ""
        asyncio.create_task(
            notifier.async_notify_analyst(
                case_id=res.case_id,
                score=res.threat_score,
                verdict=res.verdict,
                category=res.category,
                sender=req.sender,
                recipient=req.recipient,
                subject=res.original_subject,
                findings=res.findings,
                summary_text=summary_txt,
                full_inspection=asdict(res)
            )
        )

    # If score is critical and auto-quarantine is enabled, store in quarantine vault
    if res.policy_action in ["QUARANTINE", "REJECT"] and settings.AUTO_QUARANTINE_HIGH_RISK:
        vault.store(
            case_id=res.case_id,
            raw_eml_bytes=raw_reconstructed,
            sender=req.sender,
            recipient=req.recipient,
            subject=res.original_subject,
            threat_score=res.threat_score,
            category=res.category,
            findings=res.findings,
            auth_summary=res.auth_summary,
            client_ip=req.client_ip or "127.0.0.1",
            autopsy_dossier=res.autopsy_dossier
        )

    return asdict(res)



@app.post("/api/v1/autopsy/dissect-raw")
async def dissect_raw_eml(req: RawEmlInspectRequest) -> Dict[str, Any]:
    """
    Accepts a base64-encoded raw RFC5322 .EML file, executes full dissection,
    and returns comprehensive autopsy diagnostics.
    """
    import base64
    try:
        raw_bytes = base64.b64decode(req.raw_eml_base64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {e}")

    res = inspector.inspect(
        sender="",
        recipient="",
        subject="",
        body="",
        client_ip=req.client_ip or "127.0.0.1",
        raw_eml_bytes=raw_bytes
    )
    return asdict(res)


# --- AUTOPSY & FORENSIC DOSSIER APIS ---

@app.get("/api/v1/autopsy/{case_id}")
async def get_autopsy_dossier(case_id: str):
    """
    Retrieves the complete deep forensic autopsy dossier for a quarantined or inspected case.
    Includes Multi-Hop Relays, MITRE ATT&CK Mapping, Cognitive NLP, and CDR Disarm reports.
    """
    case = vault.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found in evidence vault.")

    dossier = case.get("autopsy_dossier")
    if not dossier:
        # If autopsy dossier wasn't persisted directly, generate on-the-fly from raw EML
        raw_eml = vault.get_raw_eml(case_id)
        if raw_eml:
            p_sender, p_rcpt, p_subj, p_body, p_hdrs, p_atts = inspector.parse_raw_eml(raw_eml)
            from gateway.engine.autopsy import autopsy_engine
            dossier_obj = autopsy_engine.generate_full_autopsy(
                sender=p_sender or case.get("sender", ""),
                recipient=p_rcpt or case.get("recipient", ""),
                subject=p_subj or case.get("subject", ""),
                body=p_body,
                headers=p_hdrs,
                findings=case.get("findings", []),
                threat_score=case.get("threat_score", 0),
                dominant_category=case.get("category", "General"),
                raw_eml_bytes=raw_eml,
                attachments=p_atts
            )
            dossier = asdict(dossier_obj)
        else:
            raise HTTPException(status_code=404, detail=f"No forensic evidence available for case {case_id}.")

    return {
        "status": "success",
        "case_id": case_id,
        "threat_score": case.get("threat_score"),
        "category": case.get("category"),
        "autopsy_dossier": dossier
    }


# --- QUARANTINE VAULT APIS ---

@app.get("/api/v1/quarantine")
async def list_quarantine():
    """Lists all quarantined records from the evidence vault."""
    return vault.list_cases()


@app.get("/api/v1/quarantine/{case_id}")
async def get_quarantine_case(case_id: str):
    """Retrieves detailed case metadata for a quarantined message."""
    case = vault.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Quarantined case {case_id} not found.")
    return case


@app.get("/api/v1/quarantine/{case_id}/raw")
async def get_quarantine_raw_eml(case_id: str):
    """Downloads the raw RFC5322 EML evidence file."""
    raw = vault.get_raw_eml(case_id)
    if not raw:
        raise HTTPException(status_code=404, detail=f"Raw EML file for case {case_id} not found.")
    return Response(
        content=raw,
        media_type="message/rfc822",
        headers={"Content-Disposition": f'attachment; filename="{case_id}.eml"'}
    )


@app.get("/api/v1/quarantine/{case_id}/bsa-certificate")
async def get_bsa_certificate(case_id: str):
    """Generates Section 63 BSA 2023 Electronic Evidence Certificate."""
    cert = vault.generate_bsa_certificate(case_id)
    if not cert:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    return cert


@app.post("/api/v1/quarantine/{case_id}/release")
async def release_quarantine_case(case_id: str, req: Optional[QuarantineReleaseRequest] = None):
    """Administratively releases a quarantined email and relays to recipient."""
    r_host = req.relay_host if req else None
    r_port = req.relay_port if req else None
    res = vault.release_case(case_id, relay_host=r_host, relay_port=r_port)
    if res.get("status") == "error":
        raise HTTPException(status_code=500, detail=res.get("message"))
    return res


@app.delete("/api/v1/quarantine/{case_id}")
async def delete_quarantine_case(case_id: str):
    """Deletes a quarantined case from the vault."""
    success = vault.delete_case(case_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    return {"status": "success", "message": f"Case {case_id} permanently deleted from vault."}


# --- LIVE SOC STREAMING (SSE & WEBSOCKET) ---

@app.get("/api/v1/live-feed")
async def sse_live_feed(request: Request):
    """Server-Sent Events (SSE) stream for real-time SOC incident feed."""
    q = asyncio.Queue(maxsize=50)
    metrics.event_subscribers.add(q)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=20.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            metrics.event_subscribers.discard(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    """WebSocket stream for real-time SOC dashboard telemetry."""
    await websocket.accept()
    q = asyncio.Queue(maxsize=50)
    metrics.event_subscribers.add(q)

    try:
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        metrics.event_subscribers.discard(q)


# --- INTERCEPTED MAIL ARCHIVE APIS ---

@app.get("/api/v1/archive")
async def list_archived_emails(limit: int = 100):
    """Lists all intercepted and archived emails with metadata and verdicts."""
    return {
        "status": "success",
        "archive_dir": str(archiver.archive_dir),
        "total_cases": len(archiver.list_archived_cases(limit=limit)),
        "cases": archiver.list_archived_cases(limit=limit)
    }


@app.get("/api/v1/archive/{case_id}")
async def get_archived_case_details(case_id: str):
    """Retrieves complete archived autopsy report and paths for a specific case."""
    case = archiver.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Archived case {case_id} not found.")
    return case


@app.get("/api/v1/archive/{case_id}/summary", response_class=PlainTextResponse)
async def get_archived_case_summary(case_id: str):
    """Returns human-readable text summary of the archived email."""
    txt = archiver.get_summary_text(case_id)
    if not txt:
        raise HTTPException(status_code=404, detail=f"Summary for case {case_id} not found.")
    return PlainTextResponse(content=txt, media_type="text/plain")


@app.post("/api/v1/archive/config")
async def configure_archive_dir(req: Dict[str, str]):
    """Configures the storage directory where intercepted emails will be saved."""
    new_dir = req.get("archive_dir")
    if not new_dir:
        raise HTTPException(status_code=400, detail="Missing 'archive_dir' in request body.")
    resolved = archiver.set_archive_dir(new_dir)
    return {
        "status": "success",
        "message": f"Archive storage path updated to {resolved}",
        "archive_dir": str(resolved)
    }


# --- SOC ANALYST ALERT TEST API ---

class AlertTestRequest(BaseModel):
    threat_score: Optional[int] = 88
    category: Optional[str] = "Phishing / BEC Simulation"
    sender: Optional[str] = "attacker@malicious-spoof.xyz"
    recipient: Optional[str] = "soc-analyst@enterprise.corp"
    subject: Optional[str] = "TEST ALERT: High Threat Email Intercepted"


@app.post("/api/v1/analyst/test-alert")
async def trigger_test_analyst_alert(req: Optional[AlertTestRequest] = None):
    """Triggers a test notification across all configured analyst channels."""
    score = req.threat_score if req else 88
    cat = req.category if req else "Phishing / BEC Simulation"
    snd = req.sender if req else "attacker@malicious-spoof.xyz"
    rcp = req.recipient if req else "soc-analyst@enterprise.corp"
    sbj = req.subject if req else "TEST ALERT: High Threat Email Intercepted"
    test_case_id = f"TEST-ALERT-{int(asyncio.get_event_loop().time())}"

    test_findings = [
        {"rule_id": "TEST-01", "title": "Urgent Financial Coercion Detected", "score": 45, "severity": "HIGH"},
        {"rule_id": "TEST-02", "title": "Untrusted Relay Infrastructure", "score": 35, "severity": "CRITICAL"}
    ]
    summary = f"Simulated test alert triggered from SOC API for case {test_case_id}.\nScore: {score}/100"

    results = notifier.notify_analyst(
        case_id=test_case_id,
        score=score,
        verdict="MALICIOUS",
        category=cat,
        sender=snd,
        recipient=rcp,
        subject=sbj,
        findings=test_findings,
        summary_text=summary
    )

    return {
        "status": "success",
        "case_id": test_case_id,
        "channel_dispatch_results": results,
        "configured_channels": {
            "desktop_enabled": settings.ENABLE_DESKTOP_NOTIFICATIONS,
            "telegram_configured": bool(settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID),
            "webhook_configured": bool(settings.ANALYST_WEBHOOK_URL or settings.WEBHOOK_URL),
            "email_configured": bool(settings.ANALYST_EMAIL)
        }
    }

