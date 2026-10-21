"""HTTP header auditing, security-header grading and TLS certificate inspection."""

from __future__ import annotations

import hashlib
import re
import ssl
import time
from urllib.parse import urlparse

from .net import get_certificate, http_request
from .utils import normalize_url

# header -> (weight, recommendation)
SECURITY_HEADERS = {
    "strict-transport-security": (
        3, "Add HSTS so browsers only use HTTPS (e.g. max-age=31536000; includeSubDomains)."),
    "content-security-policy": (
        3, "Define a CSP to mitigate XSS and data-injection attacks."),
    "x-content-type-options": (
        2, "Send 'X-Content-Type-Options: nosniff' to stop MIME sniffing."),
    "x-frame-options": (
        2, "Send X-Frame-Options: DENY (or CSP frame-ancestors) against clickjacking."),
    "referrer-policy": (
        1, "Set Referrer-Policy: strict-origin-when-cross-origin."),
    "permissions-policy": (
        1, "Restrict powerful browser APIs with Permissions-Policy."),
    "cross-origin-opener-policy": (
        1, "Consider Cross-Origin-Opener-Policy: same-origin."),
}

DISCLOSURE_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-generator",
    "x-drupal-cache", "via", "x-backend-server", "x-varnish",
]

COOKIE_FLAGS = ("secure", "httponly", "samesite")


def header_audit(target: str, timeout: float = 10.0, follow: bool = True,
                 insecure: bool = False) -> dict:
    """Fetch a URL and audit its response + security headers."""
    result = {
        "url": None,
        "status": None,
        "reason": "",
        "elapsed": 0.0,
        "server": None,
        "redirects": [],
        "headers": {},
        "raw_headers": [],
        "security": [],
        "missing": [],
        "disclosure": {},
        "cookies": [],
        "grade": None,
        "score": 0,
        "max_score": 0,
        "error": None,
    }
    try:
        url = normalize_url(target)
    except ValueError as exc:
        result["error"] = str(exc)
        return result
    result["url"] = url

    response = http_request(url, method="GET", timeout=timeout, allow_redirects=follow,
                            insecure=insecure)
    if response.get("error"):
        result["error"] = response["error"]
    result["status"] = response.get("status")
    result["reason"] = response.get("reason")
    result["elapsed"] = round(response.get("elapsed") or 0.0, 3)
    result["redirects"] = response.get("redirects") or []
    result["raw_headers"] = [(str(k), str(v)) for k, v in response.get("headers") or []]

    headers = {}
    for key, value in result["raw_headers"]:
        lowered = key.lower()
        if lowered in headers:
            if value not in headers[lowered].split(", "):
                headers[lowered] = headers[lowered] + ", " + value
        else:
            headers[lowered] = value
    result["headers"] = headers
    result["server"] = headers.get("server")

    max_score = sum(weight for weight, _ in SECURITY_HEADERS.values())
    score = 0
    for name, (weight, advice) in SECURITY_HEADERS.items():
        value = headers.get(name)
        if value:
            score += weight
            result["security"].append({"header": name, "value": value, "present": True, "weight": weight})
        else:
            result["security"].append({"header": name, "value": "", "present": False, "weight": weight})
            result["missing"].append({"header": name, "advice": advice, "weight": weight})

    result["score"] = score
    result["max_score"] = max_score
    result["grade"] = _grade(score, max_score)

    for name in DISCLOSURE_HEADERS:
        if headers.get(name):
            result["disclosure"][name] = headers[name]

    for key, value in result["raw_headers"]:
        if key.lower() == "set-cookie":
            result["cookies"].append(_analyse_cookie(value))

    hsts = headers.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if match and int(match.group(1)) < 15552000:
            result["missing"].append({
                "header": "strict-transport-security (weak)",
                "advice": "HSTS max-age is below 6 months (~15552000s).",
                "weight": 1,
            })
    return result


def _grade(score: int, max_score: int) -> str:
    if max_score <= 0:
        return "?"
    pct = score / max_score
    if pct >= 0.95:
        return "A+"
    if pct >= 0.85:
        return "A"
    if pct >= 0.7:
        return "B"
    if pct >= 0.55:
        return "C"
    if pct >= 0.4:
        return "D"
    if pct >= 0.2:
        return "E"
    return "F"


def _analyse_cookie(value: str) -> dict:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    name = parts[0].split("=")[0] if parts else ""
    lowered = value.lower()
    flags = {flag: flag in lowered for flag in COOKIE_FLAGS}
    issues = []
    if not flags["secure"]:
        issues.append("missing Secure")
    if not flags["httponly"]:
        issues.append("missing HttpOnly")
    if "samesite" not in lowered:
        issues.append("missing SameSite")
    return {"name": name, "flags": flags, "issues": issues}


def cert_info(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Return a structured view of the TLS certificate for host:port."""
    host = host.strip()
    if "://" in host:
        host = urlparse(host).hostname or host
    if ":" in host and not host.count(":") > 1:
        host = host.split(":")[0]

    raw = get_certificate(host, port, timeout=timeout)
    result = {
        "host": host,
        "port": port,
        "ok": raw.get("ok", False),
        "error": raw.get("error"),
        "subject": {},
        "issuer": {},
        "san": [],
        "not_before": None,
        "not_after": None,
        "days_left": None,
        "expired": None,
        "self_signed": None,
        "version": raw.get("version"),
        "cipher": (raw.get("cipher") or ("", "", 0))[0] if raw.get("cipher") else None,
        "bits": (raw.get("cipher") or ("", "", 0))[2] if raw.get("cipher") else None,
        "serial": None,
        "sha256": None,
        "chain_trusted": None,
        "protocol_warnings": [],
    }
    if not raw.get("ok"):
        return result

    meta = raw.get("meta") or {}
    result["subject"] = _flatten_name(meta.get("subject", ()))
    result["issuer"] = _flatten_name(meta.get("issuer", ()))
    result["not_before"] = meta.get("notBefore")
    result["not_after"] = meta.get("notAfter")
    result["serial"] = meta.get("serialNumber")
    result["san"] = [value for _kind, value in meta.get("subjectAltName", ())]

    der = raw.get("der")
    if der:
        result["sha256"] = hashlib.sha256(der).hexdigest()

    if result["not_after"]:
        days = _days_until(result["not_after"])
        result["days_left"] = days
        result["expired"] = (days is not None and days < 0)

    if result["subject"] and result["issuer"]:
        result["self_signed"] = result["subject"].get("commonName") == result["issuer"].get("commonName")

    result["chain_trusted"] = _verify_chain(host, port, timeout)

    if result["version"] and result["version"] not in ("TLSv1.2", "TLSv1.3"):
        result["protocol_warnings"].append(f"Outdated protocol negotiated: {result['version']}")
    if result["days_left"] is not None and 0 <= result["days_left"] <= 14:
        result["protocol_warnings"].append(
            f"Certificate expires in {result['days_left']} day(s) — renew soon.")
    if result["self_signed"]:
        result["protocol_warnings"].append("Certificate appears self-signed.")
    return result


def _verify_chain(host: str, port: int, timeout: float) -> bool:
    """Check whether the default trust store accepts the certificate chain."""
    import socket
    context = ssl.create_default_context()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        with context.wrap_socket(sock, server_hostname=host):
            return True
    except (ssl.SSLError, ssl.CertificateError, OSError):
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _flatten_name(name_seq) -> dict:
    flat = {}
    for rdn in name_seq or ():
        for key, value in rdn:
            flat[str(key)] = str(value)
    return flat


def _days_until(date_text: str):
    try:
        parsed = time.strptime(date_text, "%b %d %H:%M:%S %Y %Z")
        seconds = time.mktime(parsed) - time.time()
        return int(seconds // 86400)
    except (ValueError, TypeError):
        return None


def technology_hints(audit: dict) -> list:
    """Guess the stack from headers, cookies and body keywords."""
    hints = set()
    headers = audit.get("headers") or {}
    server = (headers.get("server") or "").lower()
    powered = (headers.get("x-powered-by") or "").lower()

    for token, label in (
        ("nginx", "Nginx"), ("apache", "Apache"), ("litespeed", "LiteSpeed"),
        ("cloudflare", "Cloudflare"), ("gunicorn", "Gunicorn"), ("iis", "Microsoft IIS"),
        ("openresty", "OpenResty"), ("caddy", "Caddy"),
    ):
        if token in server:
            hints.add(label)
    for token, label in (
        ("php", "PHP"), ("asp.net", "ASP.NET"), ("express", "Express.js"),
        ("next.js", "Next.js"), ("nuxt", "Nuxt"), ("django", "Django"),
        ("servlet", "Java Servlet"), ("flask", "Flask"),
    ):
        if token in powered:
            hints.add(label)
    for header in headers:
        if header.startswith("x-nextjs"):
            hints.add("Next.js")
        if header.startswith("x-drupal"):
            hints.add("Drupal")
        if header.startswith("x-shopify"):
            hints.add("Shopify")
        if header.startswith("x-wp"):
            hints.add("WordPress")
    return sorted(hints)
