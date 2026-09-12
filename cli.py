#!/usr/bin/env python3
"""
SUDO SPANDR Enterprise ESG - Command Line Interface (CLI)
SIH 2026 Problem Statement #26106
"""

from __future__ import annotations
import argparse
import asyncio
import json
import os
import smtplib
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict

import requests
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from gateway.api import app as fastapi_app
from gateway.config import settings
from gateway.engine.inspector import GatewayInspector
from gateway.milter_server import AsyncMilterServer
from gateway.quarantine import vault
from gateway.smtp_proxy import AsyncSMTPProxyServer, metrics
from gateway.archiver import archiver
from gateway.notifier import notifier

console = Console()



def print_banner():
    banner = Text(r"""
   _____ __  ______  ____     _____ ____  ___    _   ______  ____     ___________ _____ 
  / ___// / / / __ \/ __ \   / ___// __ \/   |  / | / / __ \/ __ \   / ____/ ___// ___/ 
  \__ \/ / / / / / / / / /   \__ \/ /_/ / /| | /  |/ / / / / /_/ /  / __/  \__ \/ / __  
 ___/ / /_/ / /_/ / /_/ /   ___/ / ____/ ___ |/ /|  / /_/ / _, _/  / /___ ___/ / /_/ /  
/____/\____/_____/\____/   /____/_/   /_/  |_/_/ |_/_____/_/ |_|  /_____//____/\____/   
                                                           v4.0 (SIH PS #26106)
    """, style="bold cyan")
    console.print(banner)
    console.print("[dim]SUDO SPANDR Enterprise Mail Flow Interceptor & Postfix Milter Security Gateway[/dim]\n")


async def run_unified_gateway(host: str, smtp_port: int, milter_port: int, api_port: int):
    """Runs SMTP Proxy, Milter Wire Server, and FastAPI Web SOC concurrently."""
    print_banner()

    inspector = GatewayInspector()

    # 1. Setup SMTP Proxy
    smtp_server = AsyncSMTPProxyServer(host=host, port=smtp_port, inspector=inspector)
    await smtp_server.start()

    # 2. Setup Milter Wire Server
    milter_server = AsyncMilterServer(host=host, port=milter_port, inspector=inspector)
    await milter_server.start()

    # 3. Setup Uvicorn FastAPI Server
    config = uvicorn.Config(
        app=fastapi_app,
        host=host,
        port=api_port,
        log_level="warning",
        access_log=False
    )
    server = uvicorn.Server(config)

    console.print(Panel(
        f"[bold green]✓ ALL GATEWAY SINK INTERCEPTORS ONLINE[/bold green]\n\n"
        f"• [bold cyan]SMTP Transparent Proxy:[/bold cyan]  [white]{host}:{smtp_port}[/white]\n"
        f"• [bold yellow]Postfix Milter Wire Socket:[/bold yellow] [white]{host}:{milter_port}[/white]\n"
        f"• [bold magenta]FastAPI & Web SOC Dashboard:[/bold magenta] [white]http://{host if host != '0.0.0.0' else 'localhost'}:{api_port}[/white]\n"
        f"• [bold blue]Prometheus Metrics Endpoint:[/bold blue]  [white]http://{host if host != '0.0.0.0' else 'localhost'}:{api_port}/metrics[/white]\n"
        f"• [bold purple]Quarantine Storage Vault:[/bold purple]    [white]{settings.QUARANTINE_DIR}[/white]",
        title="[bold white]SUDO SPANDR ESG CONTROL PLANE[/bold white]",
        border_style="cyan"
    ))

    try:
        await server.serve()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await smtp_server.stop()
        await milter_server.stop()
        console.print("[yellow][!] Gateway services cleanly stopped.[/yellow]")


def cmd_simulate():
    """Runs a multi-scenario email attack simulation."""
    print_banner()
    console.print("[bold yellow]⚡ RUNNING MULTI-VECTOR ATTACK & POLICY SIMULATION[/bold yellow]\n")

    scenarios = [
        {
            "name": "1. High-Urgency Executive BEC Wire Transfer",
            "sender": "ceo-desk@b0b-finance-update.in",
            "recipient": "cfo@company.com",
            "subject": "URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)",
            "body": "Please wire $25.6M immediately to our external bank account. Strictly confidential, do not disclose to other team members. Sent from my iPhone in a private meeting.",
            "headers": {"reply-to": "offshore-drop@attacker-mail.ru"}
        },
        {
            "name": "2. Bank of Baroda Brand Impersonation & Typosquatting",
            "sender": "alerts@b0b-bank-security.in",
            "recipient": "victim@company.com",
            "subject": "Action Required: Bank of Baroda Account Suspension Notice",
            "body": "Your Bank of Baroda corporate account has been flagged. Verify your login credentials within 2 hours at http://192.168.10.45/login/bob-auth to prevent account freeze.",
            "headers": {"received-spf": "fail"}
        },
        {
            "name": "3. 2FA QR-Code Quishing Vector",
            "sender": "support@cloud-tenant-update.com",
            "recipient": "user@company.com",
            "subject": "Microsoft Authenticator 2FA Security Update Required",
            "body": "Scan the below QR code with your mobile device immediately to update your Microsoft Authenticator MFA token before access is revoked.\n<img src='data:image/png;base64,iVBORw0KGgo...' />",
            "headers": {}
        },
        {
            "name": "4. Weaponized Double-Extension Malware Attachment",
            "sender": "invoice@vendor-express.net",
            "recipient": "accounts@company.com",
            "subject": "Overdue Invoice #INV-2026-9901 - Payment Pending",
            "body": "Please find attached the signed receipt and overdue invoice. Remit payment today.",
            "attachments": [{"filename": "Signed_Invoice_Overdue.pdf.exe", "content_type": "application/octet-stream", "size": 45000}],
            "headers": {}
        },
        {
            "name": "5. Clean Internal Team Meeting Minutes",
            "sender": "engineer@partner-company.com",
            "recipient": "dev-team@company.com",
            "subject": "Project Sprint Roadmap & Meeting Minutes",
            "body": "Hi team, thanks for attending today's sprint sync. The minutes and action items have been documented on the internal wiki. See you at tomorrow's standup.",
            "headers": {"message-id": "<msg-2026@partner-company.com>", "date": "Mon, 31 Aug 2026 12:00:00 +0000"}
        }
    ]

    inspector = GatewayInspector()
    table = Table(title="GATEWAY POLICY ENFORCEMENT MATRIX", show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Scenario / Vector", style="bold white", ratio=2)
    table.add_column("Threat Score", justify="center", style="bold", ratio=1)
    table.add_column("Verdict", justify="center", ratio=1)
    table.add_column("Policy Action", justify="center", ratio=1)
    table.add_column("Milter Code", style="dim", ratio=1)
    table.add_column("Key Findings", style="yellow", ratio=3)

    for sc in scenarios:
        res = inspector.inspect(
            sender=sc["sender"],
            recipient=sc["recipient"],
            subject=sc["subject"],
            body=sc["body"],
            headers=sc.get("headers", {}),
            attachments=sc.get("attachments", [])
        )

        score_style = "bold red" if res.threat_score >= 75 else "bold yellow" if res.threat_score >= 40 else "bold green"
        verdict_style = "red" if res.verdict == "MALICIOUS" else "yellow" if res.verdict == "SUSPICIOUS" else "green"

        finding_str = "\n".join(f"• {f['title']}" for f in res.findings[:2]) if res.findings else "No threats detected"

        table.add_row(
            f"[bold]{sc['name']}[/bold]\n[dim]{sc['sender']}[/dim]",
            f"[{score_style}]{res.threat_score}%[/{score_style}]",
            f"[{verdict_style}]{res.verdict}[/{verdict_style}]",
            f"[bold]{res.policy_action}[/bold]",
            res.postfix_code,
            finding_str
        )

    console.print(table)


def cmd_test_smtp(host: str, port: int, sender: str, recipient: str, subject: str, body: str):
    """Sends a test SMTP message through the running gateway."""
    console.print(f"[bold cyan][*] Sending test SMTP message to {host}:{port}...[/bold cyan]")
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(host, port, timeout=10.0) as client:
            code, resp = client.sendmail(sender, [recipient], msg.as_string())
            console.print(f"[bold green]✓ SMTP Response: {code} - {resp.decode('utf-8', errors='ignore')}[/bold green]")
    except smtplib.SMTPResponseException as e:
        console.print(f"[bold red]✗ SMTP Rejected by ESG Policy: Code {e.smtp_code} - {e.smtp_error.decode('utf-8', errors='ignore')}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]✗ Connection error: {e}[/bold red]")


def cmd_quarantine_list():
    """Lists quarantined records."""
    cases = vault.list_cases()
    if not cases:
        console.print("[yellow]Quarantine vault is empty.[/yellow]")
        return

    table = Table(title="CRYPTOGRAPHIC QUARANTINE VAULT", show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Case ID", style="bold purple")
    table.add_column("Timestamp", style="dim")
    table.add_column("Sender", style="white")
    table.add_column("Subject", style="cyan")
    table.add_column("Threat Score", justify="center", style="bold red")
    table.add_column("Status", justify="center")
    table.add_column("BSA Seal (SHA-256)", style="dim")

    for c in cases:
        table.add_row(
            c.get("case_id"),
            c.get("timestamp", "")[:19],
            c.get("sender"),
            c.get("subject"),
            f"{c.get('threat_score')}%",
            c.get("status"),
            f"{c.get('sha256_hash', '')[:16]}..."
        )
    console.print(table)


def cmd_archive_list(limit: int = 50):
    """Lists all continuous intercepted emails saved in the archive directory."""
    cases = archiver.list_archived_cases(limit=limit)
    console.print(f"[bold cyan]📁 INTERCEPTED EMAIL VAULT ARCHIVE[/bold cyan] (Directory: [yellow]{archiver.archive_dir}[/yellow])\n")
    if not cases:
        console.print("[yellow]Archive vault is currently empty. Start the gateway or send an email to populate.[/yellow]")
        return

    table = Table(title="INTERCEPTED INCOMING EMAIL ARCHIVE", show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Case ID", style="bold white")
    table.add_column("Timestamp (UTC)", style="dim")
    table.add_column("Sender", style="green")
    table.add_column("Subject", style="cyan")
    table.add_column("Score", justify="center", style="bold red")
    table.add_column("Verdict", justify="center")
    table.add_column("Action", justify="center")
    table.add_column("Client IP", style="dim")

    for c in cases:
        score = c.get("threat_score", 0)
        score_color = "red" if score >= 75 else ("yellow" if score >= 40 else "green")
        table.add_row(
            c.get("case_id"),
            c.get("timestamp", "")[:19],
            c.get("sender"),
            c.get("subject", "(No Subject)")[:35],
            f"[{score_color}]{score}%[/{score_color}]",
            c.get("verdict"),
            c.get("policy_action"),
            c.get("client_ip", "127.0.0.1")
        )
    console.print(table)
    console.print(f"[dim]Total records displayed: {len(cases)} | Use 'python3 cli.py archive-view <case_id>' for full report.[/dim]\n")


def cmd_archive_view(case_id: str):
    """Views the stored forensic summary and report for an archived email."""
    summary = archiver.get_summary_text(case_id)
    case = archiver.get_case(case_id)
    if not summary and not case:
        console.print(f"[bold red]✗ Archived case {case_id} not found in {archiver.archive_dir}[/bold red]")
        return

    if summary:
        console.print(Panel(summary, title=f"FORENSIC REPORT: {case_id}", border_style="cyan"))

    if case and "archive_paths" in case:
        paths = case["archive_paths"]
        console.print(f"[bold green]Raw EML:[/bold green]   {paths.get('eml')}")
        console.print(f"[bold green]JSON Dossier:[/bold green] {paths.get('report')}")
        console.print(f"[bold green]Text Summary:[/bold green] {paths.get('summary')}")


def cmd_test_alert(score: int = 88, category: str = "BEC / Executive Impersonation"):
    """Triggers and verifies multi-channel alert dispatch to analysts."""
    console.print("[bold yellow]🚨 TRIGGERING MULTI-CHANNEL SOC ANALYST ALERT TEST[/bold yellow]\n")
    test_case_id = f"ALERT-TEST-{int(time.time())}"
    test_findings = [
        {"rule_id": "SOC-ALERT-01", "title": "Critical Wire Transfer Request Detected", "score": 50, "severity": "CRITICAL"},
        {"rule_id": "SOC-ALERT-02", "title": "Typosquatted Banking Domain", "score": 38, "severity": "HIGH"}
    ]
    summary = f"Simulated High-Score Threat Test Alert\nCase: {test_case_id}\nThreat Score: {score}/100"

    results = notifier.notify_analyst(
        case_id=test_case_id,
        score=score,
        verdict="MALICIOUS",
        category=category,
        sender="attacker@fake-bank-login.in",
        recipient="chief-accountant@enterprise.in",
        subject="CRITICAL: Immediate Wire Transfer Required ($1.2M)",
        findings=test_findings,
        summary_text=summary
    )

    table = Table(title="ANALYST ALERT DISPATCH STATUS", show_header=True, header_style="bold red")
    table.add_column("Channel", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Channel Details", style="dim")

    table.add_row(
        "Desktop Notification",
        "[bold green]✓ SENT[/bold green]" if results.get("desktop") else "[yellow]OFF / UNSUPPORTED[/yellow]",
        "Linux notify-send pop-up on host"
    )
    table.add_row(
        "Telegram Bot Alert",
        "[bold green]✓ SENT[/bold green]" if results.get("telegram") else "[dim]SKIPPED (No Token in .env)[/dim]",
        f"Bot Token: {settings.TELEGRAM_BOT_TOKEN or 'Not configured'}"
    )
    table.add_row(
        "SOC Webhook (Discord/Slack)",
        "[bold green]✓ SENT[/bold green]" if results.get("webhook") else "[dim]SKIPPED (No Webhook URL in .env)[/dim]",
        f"URL: {settings.ANALYST_WEBHOOK_URL or settings.WEBHOOK_URL or 'Not configured'}"
    )
    table.add_row(
        "Analyst Email",
        "[bold green]✓ SENT[/bold green]" if results.get("email") else "[dim]SKIPPED (No Email in .env)[/dim]",
        f"Target: {settings.ANALYST_EMAIL or 'Not configured'}"
    )
    console.print(table)



def cmd_autopsy(case_id_or_file: str):
    """Generates and prints a surgical terminal autopsy report for a case or raw EML."""
    from gateway.engine.autopsy import autopsy_engine

    case = vault.get_case(case_id_or_file)
    raw_eml = None

    if case:
        raw_eml = vault.get_raw_eml(case_id_or_file)
        dossier_data = case.get("autopsy_dossier")
    elif os.path.exists(case_id_or_file):
        with open(case_id_or_file, "rb") as f:
            raw_eml = f.read()
        inspector = GatewayInspector()
        p_sender, p_rcpt, p_subj, p_body, p_hdrs, p_atts = inspector.parse_raw_eml(raw_eml)
        res = inspector.inspect(
            sender=p_sender,
            recipient=p_rcpt,
            subject=p_subj,
            body=p_body,
            headers=p_hdrs,
            attachments=p_atts,
            raw_eml_bytes=raw_eml
        )
        dossier_data = res.autopsy_dossier
    else:
        console.print(f"[bold red]Error:[/bold red] Case or file '{case_id_or_file}' not found in vault.")
        return

    if not dossier_data and raw_eml:
        inspector = GatewayInspector()
        p_sender, p_rcpt, p_subj, p_body, p_hdrs, p_atts = inspector.parse_raw_eml(raw_eml)
        dossier_obj = autopsy_engine.generate_full_autopsy(
            sender=p_sender,
            recipient=p_rcpt,
            subject=p_subj,
            body=p_body,
            headers=p_hdrs,
            findings=[],
            threat_score=90,
            dominant_category="Forensic Inspection",
            raw_eml_bytes=raw_eml,
            attachments=p_atts
        )
        from dataclasses import asdict
        dossier_data = asdict(dossier_obj)

    if not dossier_data:
        console.print("[bold red]No autopsy data could be extracted.[/bold red]")
        return

    console.print(Panel.fit(
        f"[bold cyan]SUDO SPANDR SURGICAL EMAIL AUTOPSY DOSSIER[/bold cyan]\n"
        f"[bold white]Case Ref:[/bold white] {dossier_data.get('autopsy_id')}\n"
        f"[bold white]Originating IP:[/bold white] [bold red]{dossier_data.get('originating_ip')}[/bold red] ({dossier_data.get('origin_country')})\n"
        f"[bold white]Timestamp (UTC):[/bold white] {dossier_data.get('timestamp_utc')}",
        title="🔬 FORENSIC POSTMORTEM",
        border_style="magenta"
    ))

    # 1. Multi-Hop Relays
    hops_table = Table(title="TRANSPORT RELAY RECONSTRUCTION (MULTI-HOP HOPS)", show_header=True, header_style="bold blue")
    hops_table.add_column("Hop #", justify="center")
    hops_table.add_column("From Host", style="white")
    hops_table.add_column("By Host", style="dim")
    hops_table.add_column("IP Address", style="yellow")
    hops_table.add_column("Protocol / TLS", style="cyan")
    hops_table.add_column("Δ Time (s)", justify="right")
    hops_table.add_column("Threat Tag", style="bold red")

    for h in dossier_data.get("hop_sequence", []):
        threat_tag = h["threat_intel"].get("type", "Standard")
        if h.get("is_tor_or_vpn"):
            threat_tag = f"[blink red]{threat_tag}[/blink red]"
        hops_table.add_row(
            str(h.get("hop_number")),
            h.get("from_host"),
            h.get("by_host"),
            h.get("ip_address"),
            f"{h.get('protocol')}\n{h.get('tls_version')}",
            str(h.get("delta_seconds")),
            threat_tag
        )
    console.print(hops_table)

    # 2. MITRE ATT&CK
    mitre_table = Table(title="MITRE ATT&CK MATRIX MAPPING", show_header=True, header_style="bold red")
    mitre_table.add_column("Technique ID", style="bold red")
    mitre_table.add_column("Tactic", style="white")
    mitre_table.add_column("Technique / Subtechnique", style="cyan")
    mitre_table.add_column("Observed Evidence", style="dim")

    for m in dossier_data.get("mitre_attack_matrix", []):
        mitre_table.add_row(
            m.get("id"),
            m.get("tactic"),
            f"{m.get('technique')} -> {m.get('subtechnique')}",
            str(m.get("finding_title") or m.get("description")[:60])
        )
    console.print(mitre_table)

    # 3. Section 63 BSA Certificate
    bsa = dossier_data.get("bsa_section_63_certificate", {})
    cert_text = (
        f"[bold green]Certificate ID:[/bold green] {bsa.get('certificate_id')}\n"
        f"[bold green]Legal Standard:[/bold green] {bsa.get('statute')}\n"
        f"[bold green]Recorded SHA-256:[/bold green] {bsa.get('cryptographic_verification', {}).get('recorded_hash')}\n"
        f"[bold green]Integrity Seal:[/bold green] {bsa.get('cryptographic_verification', {}).get('authenticity_seal')}\n"
        f"[dim]{bsa.get('examiner_declaration')}[/dim]"
    )
    console.print(Panel(cert_text, title="⚖️ BSA 2023 SECTION 63 COURT CERTIFICATE", border_style="green"))


def main():
    parser = argparse.ArgumentParser(description="SUDO SPANDR Enterprise ESG v4.0 CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # start
    start_parser = subparsers.add_parser("start", help="Start unified ESG services (SMTP Proxy, Milter, Web SOC)")
    start_parser.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    start_parser.add_argument("--smtp-port", type=int, default=settings.SMTP_LISTEN_PORT, help="SMTP Proxy Port (default: 10025)")
    start_parser.add_argument("--milter-port", type=int, default=settings.MILTER_LISTEN_PORT, help="Milter Port (default: 8893)")
    start_parser.add_argument("--api-port", type=int, default=settings.API_LISTEN_PORT, help="FastAPI & SOC Web Port (default: 8002)")

    # simulate
    subparsers.add_parser("simulate", help="Run multi-vector attack & policy simulation")

    # autopsy
    autopsy_parser = subparsers.add_parser("autopsy", help="Perform surgical forensic autopsy on case or EML file")
    autopsy_parser.add_argument("target", help="Case ID (e.g. SPANDR-ESG-1234) or path to .eml file")

    # test-smtp
    smtp_parser = subparsers.add_parser("test-smtp", help="Send test email to SMTP gateway")
    smtp_parser.add_argument("--host", default="127.0.0.1")
    smtp_parser.add_argument("--port", type=int, default=settings.SMTP_LISTEN_PORT)
    smtp_parser.add_argument("--sender", default="attacker@b0b-security-update.in")
    smtp_parser.add_argument("--recipient", default="user@company.com")
    smtp_parser.add_argument("--subject", default="URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)")
    smtp_parser.add_argument("--body", default="Please wire $25.6M immediately. Sent from my iPhone.")

    # quarantine
    subparsers.add_parser("quarantine-list", help="List all quarantined messages in vault")

    # archive-list
    archive_list_parser = subparsers.add_parser("archive-list", help="List all intercepted incoming emails in vault")
    archive_list_parser.add_argument("--limit", type=int, default=50, help="Maximum records to list (default: 50)")

    # archive-view
    archive_view_parser = subparsers.add_parser("archive-view", help="View forensic report of an archived email")
    archive_view_parser.add_argument("case_id", help="Case ID (e.g. SPANDR-ESG-XXXX)")

    # test-alert
    test_alert_parser = subparsers.add_parser("test-alert", help="Send test high-threat alert to all configured analyst channels")
    test_alert_parser.add_argument("--score", type=int, default=88, help="Simulated threat score (default: 88)")

    args = parser.parse_args()

    if args.command == "start":
        asyncio.run(run_unified_gateway(args.host, args.smtp_port, args.milter_port, args.api_port))
    elif args.command == "simulate":
        cmd_simulate()
    elif args.command == "autopsy":
        cmd_autopsy(args.target)
    elif args.command == "test-smtp":
        cmd_test_smtp(args.host, args.port, args.sender, args.recipient, args.subject, args.body)
    elif args.command == "quarantine-list":
        cmd_quarantine_list()
    elif args.command == "archive-list":
        cmd_archive_list(args.limit)
    elif args.command == "archive-view":
        cmd_archive_view(args.case_id)
    elif args.command == "test-alert":
        cmd_test_alert(args.score)
    else:
        # Default: print simulation
        cmd_simulate()


if __name__ == "__main__":
    main()

