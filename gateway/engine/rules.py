"""
High-Performance Heuristic Threat & Pattern Engine for Cyber Squad Gateway (ESG).
Evaluates zero-day BEC, Quishing, Typosquatting, Dangerous MIME attachments, and Phishing URLs in <5ms.
"""

from __future__ import annotations
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class RuleFinding:
    rule_id: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    score_impact: int
    title: str
    description: str
    evidence: str


# High-value Target Brand & Banking Domains for Lookalike & Typosquatting Analysis
MONITORED_DOMAINS = {
    "bankofbaroda.com": "Bank of Baroda",
    "bankofbaroda.co.in": "Bank of Baroda",
    "bobfinancial.com": "Bank of Baroda Financial",
    "sbi.co.in": "State Bank of India",
    "onlinesbi.sbi": "State Bank of India",
    "hdfcbank.com": "HDFC Bank",
    "icicibank.com": "ICICI Bank",
    "axisbank.com": "Axis Bank",
    "pnbindia.in": "Punjab National Bank",
    "rbi.org.in": "Reserve Bank of India",
    "incometax.gov.in": "Income Tax Department India",
    "gov.in": "Government of India",
    "nic.in": "National Informatics Centre",
    "microsoft.com": "Microsoft",
    "office365.com": "Microsoft 365",
    "outlook.com": "Microsoft Outlook",
    "google.com": "Google",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "paypal.com": "PayPal",
}

# High-Risk Attachment Extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".cpl", ".msi", ".jar", ".ps1", ".ps1xml", ".ps2",
    ".iso", ".img", ".vhd", ".lnk", ".chm", ".reg", ".pif"
}

MACRO_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".ace"
}

# Known Malicious / Suspicious Mailer Software
SUSPICIOUS_MAILERS = [
    r"phpmailer", r"swaks", r"darkmailer", r"massmail", r"python-urllib",
    r"curl", r"libwww-perl", r"sendgrid-unverified", r"anonymous"
]


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _normalize_homoglyphs(text: str) -> str:
    """Replaces common visual homoglyphs (e.g. 0 -> o, 1 -> l, etc.)"""
    table = str.maketrans({
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
        "7": "t", "8": "b", "@": "a", "$": "s", "!": "i"
    })
    return text.translate(table)


def extract_urls(text: str) -> List[str]:
    """Extracts all HTTP/HTTPS and IP URLs from text."""
    pattern = r"https?://[^\s<>\"{}|\\^`]+"
    raw_urls = re.findall(pattern, text or "", re.IGNORECASE)
    cleaned = []
    seen = set()
    for u in raw_urls:
        u = u.rstrip(".,;!?:'\"()[]{}")
        if u and u not in seen:
            seen.add(u)
            cleaned.append(u)
    return cleaned


def evaluate_rules(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    headers: Dict[str, str],
    attachments: Optional[List[Dict[str, Any]]] = None
) -> Tuple[int, List[RuleFinding], str]:
    """
    Evaluates heuristic and behavioral detection rules against the parsed email.
    Returns:
        (total_score: int, findings: List[RuleFinding], dominant_category: str)
    """
    findings: List[RuleFinding] = []
    category_counts: Dict[str, int] = {}

    def add_finding(f: RuleFinding):
        findings.append(f)
        category_counts[f.category] = category_counts.get(f.category, 0) + f.score_impact

    sender_clean = sender.strip().lower()
    subject_clean = subject.strip()
    body_clean = body or ""
    headers_lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    attachments = attachments or []

    # 1. SENDER & DOMAIN TYPOSQUATTING / LOOKALIKE ANALYSIS
    from_domain = ""
    if "@" in sender_clean:
        from_domain = sender_clean.split("@", 1)[-1].strip()

    if from_domain:
        # Check Punycode IDN Homograph
        if "xn--" in from_domain:
            add_finding(RuleFinding(
                rule_id="DOM-PUNYCODE-01",
                category="Typosquatting & Impersonation",
                severity="CRITICAL",
                score_impact=45,
                title="Punycode / IDN Homograph Domain Detected",
                description=f"Sender domain '{from_domain}' uses internationalized encoding (xn--), a high-confidence indicator of visual domain spoofing.",
                evidence=f"Sender Domain: {from_domain}"
            ))

        # Check Lookalike / Typosquatting against Monitored Brands (e.g. b0b-security-update.in)
        norm_domain = _normalize_homoglyphs(from_domain)
        for target_dom, brand_name in MONITORED_DOMAINS.items():
            target_base = target_dom.split(".")[0]
            # Match patterns like b0b-, -bankofbaroda, bob-security, etc.
            if target_base in norm_domain and from_domain != target_dom:
                add_finding(RuleFinding(
                    rule_id="DOM-SPOOF-01",
                    category="Typosquatting & Impersonation",
                    severity="CRITICAL",
                    score_impact=50,
                    title=f"Brand Impersonation / Typosquatting Targeting {brand_name}",
                    description=f"Sender domain '{from_domain}' mimics legitimate brand '{target_dom}' using keyword insertion or leetspeak substitutions.",
                    evidence=f"Sender Domain: {from_domain} mimicking {target_dom} ({brand_name})"
                ))
                break

            # Levenshtein distance check on domain label
            domain_label = from_domain.split(".")[0]
            if len(domain_label) >= 4 and len(target_base) >= 4:
                dist = _levenshtein_distance(domain_label, target_base)
                if 0 < dist <= 2 and from_domain != target_dom:
                    add_finding(RuleFinding(
                        rule_id="DOM-TYPO-02",
                        category="Typosquatting & Impersonation",
                        severity="HIGH",
                        score_impact=40,
                        title=f"Typosquatted Lookalike Domain Targeting {brand_name}",
                        description=f"Sender domain label '{domain_label}' is {dist} edit(s) away from official brand domain '{target_base}'.",
                        evidence=f"Distance: {dist} to '{target_dom}'"
                    ))
                    break

    # 2. BUSINESS EMAIL COMPROMISE (BEC) & FINANCIAL FRAUD COGNITIVE LINGUISTICS
    full_text = f"{subject_clean}\n{body_clean}".lower()

    bec_urgent_patterns = [
        (r"\b(wire transfer|confidential wire|swift transfer|immediate payment|routing number|direct deposit)\b", "High-Value Financial Transfer Request", 35),
        (r"\b(strictly confidential|do not disclose|keep this private|in a meeting|sent from my iphone|do not call)\b", "Executive Isolation / Confidentiality Pressure", 25),
        (r"\b(\$?\d{1,3}(?:,\d{3})*(?:\.\d+)?\s*(?:million|m|k|usd|inr|crore|lakh))\b", "Explicit High Monetary Figure Mentioned", 20),
        (r"\b(urgent(?:ly)?|immediate(?:ly)?|action required|account suspended|verify within \d+ hours?|final notice)\b", "Urgent Coercive Pressure Language", 15),
        (r"\b(gift card|steam card|apple card|google play card|itunes card)\b", "Gift Card Reimbursement Fraud Pattern", 40),
        (r"\b(update your bank details|change of payroll|vendor invoice update|new beneficiary account)\b", "Payroll / Beneficiary Redirection Threat", 35)
    ]

    bec_hits = []
    bec_score = 0
    for pattern, label, pts in bec_urgent_patterns:
        if re.search(pattern, full_text, re.IGNORECASE):
            bec_hits.append(label)
            bec_score += pts

    if len(bec_hits) >= 2 or bec_score >= 45:
        impact = min(bec_score + 20, 85) if bec_score >= 50 else min(bec_score, 60)
        add_finding(RuleFinding(
            rule_id="BEC-COGNITIVE-01",
            category="Business Email Compromise (BEC)",
            severity="CRITICAL" if bec_score >= 50 else "HIGH",
            score_impact=impact,
            title="Business Email Compromise (BEC) / CEO Fraud Cues",
            description="The message exhibits characteristic linguistic markers of executive impersonation, urgent unauthorized financial wire directives, and social engineering coercion.",
            evidence=f"Detected Markers: {', '.join(bec_hits)}"
        ))

    # 3. QUISHING (QR CODE PHISHING) DETECTION
    quishing_patterns = [
        r"\b(scan (?:the )?(?:below )?qr code|qr code below|authenticator app|2fa verification|mfa update|scan with your mobile device|scan to view document)\b",
        r"\b(microsoft authenticator|baroda secure|sbi yono qr|security token qr)\b"
    ]
    quishing_hit = any(re.search(p, full_text, re.IGNORECASE) for p in quishing_patterns)
    has_image_indicator = bool(re.search(r"<img\s+[^>]*src=[\"'](?:data:image|cid:|https?:)", body_clean, re.IGNORECASE) or 
                               any(a.get("content_type", "").startswith("image/") for a in attachments))

    if quishing_hit and (has_image_indicator or "qr" in full_text):
        add_finding(RuleFinding(
            rule_id="QUISH-DETECT-01",
            category="Quishing (QR Code Phishing)",
            severity="HIGH",
            score_impact=45,
            title="Quishing (QR-Code Phishing) Attack Vector",
            description="Email instructs recipient to scan an embedded QR code with a mobile device, bypassing conventional URL and sandbox inspection.",
            evidence="QR scan instruction combined with embedded visual element detected."
        ))

    # 4. URL & AiTM (ADVERSARY-IN-THE-MIDDLE) ANALYSIS
    urls = extract_urls(f"{body_clean}\n{headers_lower.get('list-unsubscribe', '')}")
    for raw_u in urls:
        parsed = urllib.parse.urlparse(raw_u)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()

        # Raw IP Hostname
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            add_finding(RuleFinding(
                rule_id="URL-IP-HOST-01",
                category="Phishing & Malicious URLs",
                severity="CRITICAL",
                score_impact=40,
                title="Direct IP Address in URL Hostname",
                description=f"URL uses raw IP hostname '{hostname}' instead of a registered domain, commonly used in phishing relays and command-and-control drops.",
                evidence=f"Suspicious URL: {raw_u}"
            ))

        # Deep Subdomain / Suspicious TLD
        if len(hostname.split(".")) > 4:
            add_finding(RuleFinding(
                rule_id="URL-DEEP-SUB-01",
                category="Phishing & Malicious URLs",
                severity="MEDIUM",
                score_impact=20,
                title="Deep Subdomain Structure Detected",
                description=f"Hostname '{hostname}' has excessive subdomain nesting, often used to bypass reputation blocklists.",
                evidence=f"Deep domain: {hostname}"
            ))

        # Credential Harvesting Keywords in Path
        if re.search(r"/(?:login|signin|auth|verify|session|update-account|secure-portal|webmail|outlook-auth)\b", path):
            add_finding(RuleFinding(
                rule_id="URL-CRED-HARVEST-01",
                category="Credential Harvesting Phishing",
                severity="HIGH",
                score_impact=35,
                title="Credential Harvesting / Phishing URL Path",
                description=f"URL contains authentication/login keywords '{path}' hosted on an unverified domain '{hostname}'.",
                evidence=f"Phishing Target: {raw_u}"
            ))

    # 5. DANGEROUS MIME ATTACHMENT INSPECTION
    for att in attachments:
        att_name = str(att.get("filename", "")).lower()
        content_type = str(att.get("content_type", "")).lower()
        size = att.get("size", 0)

        # Check Double Extension (e.g. invoice.pdf.exe)
        double_ext_match = re.search(r"\.(pdf|docx|xlsx|jpg|png|txt)\.([a-z0-9]{2,4})$", att_name)
        if double_ext_match:
            secondary_ext = f".{double_ext_match.group(2)}"
            if secondary_ext in DANGEROUS_EXTENSIONS or secondary_ext in [".exe", ".scr", ".vbs", ".js", ".bat"]:
                add_finding(RuleFinding(
                    rule_id="ATT-DOUBLE-EXT-01",
                    category="Dangerous Attachments & Malware",
                    severity="CRITICAL",
                    score_impact=50,
                    title="Double Extension Concealment Technique",
                    description=f"Attachment '{att_name}' uses double extension trick to disguise executable payload as a document.",
                    evidence=f"File: {att_name}"
                ))

        # Direct dangerous extension
        for ext in DANGEROUS_EXTENSIONS:
            if att_name.endswith(ext):
                add_finding(RuleFinding(
                    rule_id="ATT-DANGEROUS-EXT-02",
                    category="Dangerous Attachments & Malware",
                    severity="CRITICAL",
                    score_impact=50,
                    title=f"Executable / Dangerous Attachment ({ext.upper()})",
                    description=f"Inbound message carries dangerous executable or script container '{att_name}'.",
                    evidence=f"Attachment: {att_name} ({ext})"
                ))
                break

        # Macro-enabled Office container
        for mext in MACRO_EXTENSIONS:
            if att_name.endswith(mext):
                add_finding(RuleFinding(
                    rule_id="ATT-MACRO-DOC-03",
                    category="Macro Weaponization",
                    severity="HIGH",
                    score_impact=35,
                    title=f"Macro-Enabled Office Document ({mext.upper()})",
                    description=f"Attachment '{att_name}' contains VBA macros capable of secondary payload execution upon opening.",
                    evidence=f"Attachment: {att_name}"
                ))
                break

    # 6. HEADER INTEGRITY & SENDER ANOMALIES
    reply_to = headers_lower.get("reply-to", "").strip().lower()
    if reply_to and "@" in reply_to and "@" in sender_clean:
        reply_domain = reply_to.split("@", 1)[-1].strip().rstrip(">")
        if from_domain and reply_domain and from_domain != reply_domain:
            add_finding(RuleFinding(
                rule_id="HDR-REPLY-MISMATCH-01",
                category="Header Anomalies",
                severity="HIGH",
                score_impact=30,
                title="Reply-To Domain Mismatch (Traffic Redirection)",
                description=f"Inbound sender domain '{from_domain}' differs from the response routing address '{reply_domain}'.",
                evidence=f"From: {from_domain} vs Reply-To: {reply_domain}"
            ))

    mailer = headers_lower.get("x-mailer", "") or headers_lower.get("user-agent", "")
    for susp_m in SUSPICIOUS_MAILERS:
        if re.search(susp_m, mailer, re.IGNORECASE):
            add_finding(RuleFinding(
                rule_id="HDR-SUSP-MAILER-02",
                category="Suspicious Mail Software",
                severity="MEDIUM",
                score_impact=20,
                title="Automated / Mass-Mailing Software Detected",
                description=f"Message was dispatched using raw script / mass-mailer client '{mailer}'.",
                evidence=f"X-Mailer: {mailer}"
            ))
            break

    # Missing mandatory RFC 5322 headers
    if not headers_lower.get("message-id"):
        add_finding(RuleFinding(
            rule_id="HDR-MISSING-MSGID-03",
            category="Header Anomalies",
            severity="LOW",
            score_impact=10,
            title="Missing Mandatory RFC 5322 Message-ID Header",
            description="Email lacks a standard Message-ID header, indicative of ad-hoc mail injection.",
            evidence="Header 'Message-ID' is absent."
        ))

    # Calculate overall risk score
    raw_total = sum(f.score_impact for f in findings)
    # Normalized capped score (0-100)
    final_score = min(100, raw_total)

    # Determine dominant threat category
    dominant_category = "General / Clean"
    if category_counts:
        dominant_category = max(category_counts.items(), key=lambda item: item[1])[0]

    return final_score, findings, dominant_category
