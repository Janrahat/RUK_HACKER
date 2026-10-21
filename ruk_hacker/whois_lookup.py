"""Minimal WHOIS client (RFC 3912, TCP port 43) with referral following."""

from __future__ import annotations

import ipaddress
import re

from .net import raw_socket_read
from .utils import is_domain, is_ip

IANA_WHOIS = "whois.iana.org"
MAX_REFERRALS = 4

FIELD_ALIASES = {
    "domain name": "domain",
    "domain": "domain",
    "registrar": "registrar",
    "registrar url": "registrar_url",
    "registrar iana id": "registrar_id",
    "registrar abuse contact email": "abuse_email",
    "abuse contact email": "abuse_email",
    "creation date": "created",
    "created": "created",
    "created on": "created",
    "registered on": "created",
    "updated date": "updated",
    "last updated": "updated",
    "last modified": "updated",
    "registry expiry date": "expires",
    "expiry date": "expires",
    "expiration date": "expires",
    "registrar registration expiration date": "expires",
    "expires": "expires",
    "registrant organization": "registrant_org",
    "registrant country": "registrant_country",
    "name server": "nameservers",
    "nserver": "nameservers",
    "domain status": "status",
    "status": "status",
    "dnssec": "dnssec",
    "org-name": "organization",
    "orgname": "organization",
    "netname": "netname",
    "country": "country",
    "inetnum": "inetnum",
    "netrange": "inetnum",
    "cidr": "inetnum",
    "descr": "description",
    "organisation": "organization",
    "admin-c": "admin_contact",
    "tech-c": "tech_contact",
}

REFERRAL_RE = re.compile(r"(?:whois|ReferralServer|refer|Registrar WHOIS Server)\s*:\s*(?:whois://)?([A-Za-z0-9.\-:]+)", re.I)


def _clean_server(value: str) -> str:
    value = value.strip().strip("/")
    value = value.replace("whois://", "").replace("rwhois://", "")
    value = value.split("/")[0]
    return value.strip()


def _query_server(server: str, query: str, timeout: float = 10.0) -> str:
    server = _clean_server(server)
    if not server:
        return ""
    host = server
    port = 43
    if ":" in server:
        parts = server.rsplit(":", 1)
        if parts[1].isdigit():
            host, port = parts[0], int(parts[1])
    payload = (query + "\r\n").encode("ascii", "ignore")
    data = raw_socket_read(host, port, payload=payload, timeout=timeout, read_bytes=200000)
    return data.decode("utf-8", "replace")


def _find_referral(text: str) -> str:
    match = REFERRAL_RE.search(text)
    if not match:
        return ""
    return _clean_server(match.group(1))


def _parse_fields(text: str) -> dict:
    fields = {}
    nameservers = []
    status = []
    for line in text.splitlines():
        if not line or line.startswith("%") or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        canonical = FIELD_ALIASES.get(key)
        if not canonical:
            continue
        if canonical == "nameservers":
            if value not in nameservers:
                nameservers.append(value.split()[0].lower())
        elif canonical == "status":
            if value not in status:
                status.append(value)
        elif canonical not in fields:
            fields[canonical] = value
    if nameservers:
        fields["nameservers"] = nameservers
    if status:
        fields["status"] = status
    return fields


def whois_domain(domain: str, timeout: float = 12.0, server: str = None) -> dict:
    """Perform a WHOIS lookup for a domain, following IANA referrals."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not is_domain(domain):
        return {"ok": False, "error": f"invalid domain: {domain}", "raw": ""}

    result = {"ok": False, "query": domain, "server": None, "raw": "",
              "fields": {}, "referrals": [], "error": None}

    current_server = server
    if not current_server:
        try:
            iana_text = _query_server(IANA_WHOIS, domain, timeout=timeout)
        except OSError as exc:
            result["error"] = f"could not reach IANA: {exc}"
            return result
        result["raw"] = iana_text
        current_server = _find_referral(iana_text) or ""
        if not current_server:
            result["ok"] = bool(iana_text.strip())
            result["fields"] = _parse_fields(iana_text)
            return result

    text = ""
    seen = set()
    server_used = current_server
    for _hop in range(MAX_REFERRALS):
        if not current_server or current_server in seen:
            break
        seen.add(current_server)
        server_used = current_server
        try:
            text = _query_server(current_server, domain, timeout=timeout)
        except OSError as exc:
            result["error"] = f"{current_server}: {exc}"
            break
        result["referrals"].append(current_server)
        referral = _find_referral(text)
        if not referral or referral == current_server:
            break
        current_server = referral

    if text:
        result["raw"] = text
        result["fields"] = _parse_fields(text)
        result["ok"] = bool(text.strip())
    result["server"] = server_used
    return result


def whois_ip(ip: str, timeout: float = 12.0) -> dict:
    """WHOIS lookup for an IP address (RIR referral chain)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": f"invalid IP: {ip}", "raw": "", "fields": {}}

    result = {"ok": False, "query": str(address), "server": None, "raw": "",
              "fields": {}, "referrals": [], "error": None}
    try:
        iana_text = _query_server(IANA_WHOIS, str(address), timeout=timeout)
    except OSError as exc:
        result["error"] = f"could not reach IANA: {exc}"
        return result

    server = _find_referral(iana_text) or "whois.arin.net"
    text = ""
    for _hop in range(MAX_REFERRALS):
        try:
            text = _query_server(server, str(address), timeout=timeout)
        except OSError as exc:
            result["error"] = f"{server}: {exc}"
            break
        result["referrals"].append(server)
        referral = _find_referral(text)
        if not referral or referral == server:
            break
        server = referral

    result["raw"] = text or iana_text
    result["fields"] = _parse_fields(result["raw"])
    result["server"] = server
    result["ok"] = bool(result["raw"].strip())
    return result


def days_until(date_text: str):
    """Best-effort parse of a WHOIS date string into days remaining."""
    import datetime
    if not date_text:
        return None
    candidates = [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y",
    ]
    cleaned = str(date_text).strip().replace("  ", " ")
    for fmt in candidates:
        try:
            parsed = datetime.datetime.strptime(cleaned[:len(datetime.datetime.now().strftime(fmt)) + 6], fmt)
        except (ValueError, TypeError):
            continue
        if parsed.tzinfo is not None:
            now = datetime.datetime.now(datetime.timezone.utc)
        else:
            now = datetime.datetime.now()
        return (parsed - now).days
    return None
