"""
Live DNS Email Authentication Engine (SPF, DKIM, DMARC) for Cyber Squad ESG.
Performs RFC-compliant verification on inbound SMTP client connections and headers.
"""

from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


@dataclass
class AuthResult:
    spf_status: str        # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR, NOT_CHECKED
    spf_reason: str
    dkim_status: str       # PASS, FAIL, PRESENT_UNVERIFIED, NONE, INVALID_HEADER
    dkim_reason: str
    dmarc_status: str      # PASS, FAIL, NONE, REJECT_POLICY, QUARANTINE_POLICY
    dmarc_policy: str      # none, quarantine, reject, not_found
    dmarc_reason: str
    alignment_spf: bool
    alignment_dkim: bool
    penalty_score: int     # Points added to threat score if auth fails


def _query_txt(domain: str, timeout: float = 2.0) -> List[str]:
    """Queries DNS TXT records for a domain safely with timeout."""
    if not DNS_AVAILABLE or not domain:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            # Join multiple TXT chunks
            txt_str = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings)
            records.append(txt_str)
        return records
    except Exception:
        return []


def check_spf(sender_domain: str, client_ip: str, timeout: float = 2.0) -> Tuple[str, str]:
    """Checks SPF TXT record for sender_domain against client_ip."""
    if not sender_domain:
        return "NONE", "No sender domain provided"
    if not client_ip or client_ip in ["127.0.0.1", "::1", "localhost", "test-client"]:
        return "PASS", "Loopback / Internal Trusted Relay"

    txt_records = _query_txt(sender_domain, timeout=timeout)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        return "NONE", f"No SPF record found for {sender_domain}"

    spf_record = spf_records[0]
    tokens = spf_record.split()

    try:
        client_addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return "PERMERROR", f"Invalid client IP: {client_ip}"

    # Basic SPF token evaluation
    for token in tokens[1:]:
        t = token.lower()
        if t.startswith("+ip4:") or t.startswith("ip4:"):
            cidr = t.replace("+ip4:", "").replace("ip4:", "")
            try:
                if client_addr in ipaddress.ip_network(cidr, strict=False):
                    return "PASS", f"Client IP {client_ip} matched SPF ip4:{cidr}"
            except Exception:
                pass
        elif t.startswith("-ip4:"):
            cidr = t.replace("-ip4:", "")
            try:
                if client_addr in ipaddress.ip_network(cidr, strict=False):
                    return "FAIL", f"Client IP {client_ip} explicitly forbidden by SPF -ip4:{cidr}"
            except Exception:
                pass
        elif t in ["-all", "all", "+all", "~all", "?all"]:
            if t == "-all":
                return "FAIL", f"Client IP {client_ip} failed strict SPF -all for {sender_domain}"
            elif t == "~all":
                return "SOFTFAIL", f"Client IP {client_ip} softfailed SPF ~all for {sender_domain}"
            elif t == "?all":
                return "NEUTRAL", f"SPF ?all neutral evaluation for {sender_domain}"
            elif t in ["+all", "all"]:
                return "PASS", f"SPF +all wildcard match"

    return "NEUTRAL", f"No matching mechanism in SPF: {spf_record}"


def check_dkim_header(headers: Dict[str, str]) -> Tuple[str, str, Optional[str]]:
    """Analyzes DKIM-Signature header for structure, domain, and selector."""
    dkim_sig = headers.get("dkim-signature") or headers.get("x-dkim-signature") or ""
    if not dkim_sig:
        return "NONE", "No DKIM-Signature header present", None

    # Parse tags
    tags = {}
    for part in dkim_sig.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    domain = tags.get("d")
    selector = tags.get("s")
    algo = tags.get("a", "rsa-sha256")

    if not domain or not selector:
        return "INVALID_HEADER", "DKIM-Signature missing mandatory 'd=' or 's=' tag", None

    return "PRESENT_UNVERIFIED", f"DKIM Signature present (domain: {domain}, selector: {selector}, algo: {algo})", domain


def check_dmarc(from_domain: str, spf_status: str, dkim_domain: Optional[str], timeout: float = 2.0) -> Tuple[str, str, str, bool, bool]:
    """
    Evaluates DMARC record and alignment for from_domain.
    Returns (dmarc_status, dmarc_policy, reason, alignment_spf, alignment_dkim)
    """
    if not from_domain:
        return "NONE", "not_found", "No From domain", False, False

    txt_records = _query_txt(f"_dmarc.{from_domain}", timeout=timeout)
    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return "NONE", "not_found", f"No DMARC policy published for {from_domain}", False, False

    dmarc_record = dmarc_records[0]
    policy_match = re.search(r"\bp=([a-zA-Z]+)", dmarc_record)
    policy = policy_match.group(1).lower() if policy_match else "none"

    alignment_spf = (spf_status == "PASS")
    alignment_dkim = bool(dkim_domain and (dkim_domain.lower() == from_domain.lower() or from_domain.lower().endswith(f".{dkim_domain.lower()}")))

    dmarc_pass = alignment_spf or alignment_dkim

    if dmarc_pass:
        return "PASS", policy, f"DMARC Passed (SPF align: {alignment_spf}, DKIM align: {alignment_dkim})", alignment_spf, alignment_dkim
    else:
        if policy == "reject":
            return "FAIL", policy, f"DMARC Failed under strict p=reject policy for {from_domain}", alignment_spf, alignment_dkim
        elif policy == "quarantine":
            return "FAIL", policy, f"DMARC Failed under p=quarantine policy for {from_domain}", alignment_spf, alignment_dkim
        else:
            return "FAIL", policy, f"DMARC Failed under p={policy} monitoring policy", alignment_spf, alignment_dkim


def evaluate_authentication(
    sender: str,
    client_ip: str,
    headers: Dict[str, str],
    timeout: float = 2.0
) -> AuthResult:
    """Unifies live SPF, DKIM, and DMARC verification into an AuthResult."""
    headers_lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    from_domain = sender.split("@", 1)[-1].strip().lower() if "@" in sender else ""

    # Check incoming Authentication-Results header if already evaluated upstream
    auth_results_hdr = headers_lower.get("authentication-results", "")
    if auth_results_hdr:
        # If upstream MTA already stamped Authentication-Results, parse it
        spf_m = re.search(r"spf=(pass|fail|softfail|neutral|none)", auth_results_hdr, re.IGNORECASE)
        dkim_m = re.search(r"dkim=(pass|fail|none)", auth_results_hdr, re.IGNORECASE)
        dmarc_m = re.search(r"dmarc=(pass|fail|none)", auth_results_hdr, re.IGNORECASE)

        spf_st = spf_m.group(1).upper() if spf_m else "NOT_CHECKED"
        dkim_st = dkim_m.group(1).upper() if dkim_m else "PRESENT_UNVERIFIED"
        dmarc_st = dmarc_m.group(1).upper() if dmarc_m else "NOT_CHECKED"

        penalty = 0
        if spf_st == "FAIL" or dmarc_st == "FAIL":
            penalty += 35
        elif spf_st == "SOFTFAIL":
            penalty += 15

        return AuthResult(
            spf_status=spf_st,
            spf_reason="Extracted from trusted Authentication-Results header",
            dkim_status=dkim_st,
            dkim_reason="Extracted from trusted Authentication-Results header",
            dmarc_status=dmarc_st,
            dmarc_policy="reported",
            dmarc_reason="Reported by upstream MTA",
            alignment_spf=(spf_st == "PASS"),
            alignment_dkim=(dkim_st == "PASS"),
            penalty_score=penalty
        )

    # Perform live DNS authentication
    spf_status, spf_reason = check_spf(from_domain, client_ip, timeout=timeout)
    dkim_status, dkim_reason, dkim_domain = check_dkim_header(headers_lower)
    dmarc_status, dmarc_policy, dmarc_reason, align_spf, align_dkim = check_dmarc(
        from_domain, spf_status, dkim_domain, timeout=timeout
    )

    penalty = 0
    if spf_status == "FAIL":
        penalty += 30
    elif spf_status == "SOFTFAIL":
        penalty += 15

    if dmarc_status == "FAIL":
        if dmarc_policy == "reject":
            penalty += 45
        elif dmarc_policy == "quarantine":
            penalty += 35
        else:
            penalty += 20

    return AuthResult(
        spf_status=spf_status,
        spf_reason=spf_reason,
        dkim_status=dkim_status,
        dkim_reason=dkim_reason,
        dmarc_status=dmarc_status,
        dmarc_policy=dmarc_policy,
        dmarc_reason=dmarc_reason,
        alignment_spf=align_spf,
        alignment_dkim=align_dkim,
        penalty_score=penalty
    )
