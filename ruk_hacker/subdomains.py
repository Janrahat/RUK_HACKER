"""Subdomain enumeration using DNS resolution plus certificate (crt.sh) intel."""

from __future__ import annotations

import json
import re

from .config import data_path
from .dnsclient import DNSError, resolve_a, resolve_aaaa, query
from .net import http_request
from .utils import RateLimiter, read_wordlist, run_threaded

DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "api-v1", "api-v2",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "prod", "production", "beta", "alpha", "demo", "sandbox", "preview",
    "admin", "panel", "portal", "dashboard", "manage", "management", "console",
    "app", "apps", "mobile", "m", "wap", "static", "assets", "cdn", "img",
    "images", "media", "files", "download", "downloads", "upload", "uploads",
    "blog", "news", "shop", "store", "cart", "checkout", "pay", "payments",
    "secure", "ssl", "vpn", "remote", "gateway", "proxy", "edge", "lb",
    "db", "database", "mysql", "postgres", "redis", "mongo", "cache",
    "ci", "cd", "jenkins", "gitlab", "git", "repo", "registry", "docker",
    "grafana", "prometheus", "kibana", "monitor", "monitoring", "status",
    "sso", "auth", "login", "id", "identity", "oauth", "accounts", "account",
    "support", "help", "docs", "wiki", "kb", "forum", "community", "chat",
    "web", "web1", "web2", "server", "host", "node1", "node2", "cluster",
    "v2", "v3", "old", "legacy", "archive", "backup", "bak", "internal",
    "intranet", "extranet", "partner", "partners", "crm", "erp", "hr",
    "marketing", "sales", "tracking", "analytics", "stats", "metrics",
    "search", "video", "stream", "live", "tv", "radio", "music", "podcast",
]


def load_wordlist(path: str = None) -> list:
    if path:
        words = read_wordlist(path, default=[])
        if words:
            return words
    bundled = data_path("subdomains.txt")
    words = read_wordlist(bundled, default=[])
    return words or list(DEFAULT_SUBDOMAINS)


def _resolve_sub(host: str, timeout: float) -> dict:
    try:
        response = query(host, "A", timeout=timeout)
    except DNSError:
        return None
    if response.get("status") == "NXDOMAIN":
        return None
    ips = [r["value"] for r in response["answers"] if r["type"] == "A"]
    cnames = [r["value"] for r in response["answers"] if r["type"] == "CNAME"]
    if not ips:
        try:
            v6 = resolve_aaaa(host, timeout=timeout)
        except DNSError:
            v6 = []
        if not v6:
            return None
        ips = v6
    return {"subdomain": host, "ips": ips, "cnames": cnames,
            "source": "dns-bruteforce"}


def _wildcard_ips(domain: str, timeout: float) -> set:
    """Detect wildcard DNS by resolving random labels."""
    import random
    import string
    found = set()
    for _ in range(2):
        label = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
        probe = f"{label}.{domain}"
        try:
            ips = resolve_a(probe, timeout=timeout)
        except DNSError:
            ips = []
        found.update(ips)
    return found


def crtsh_lookup(domain: str, timeout: float = 20.0) -> list:
    """Harvest subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = http_request(url, timeout=timeout)
    if response.get("error") or response.get("status") != 200:
        return []
    try:
        records = json.loads(response["body"].decode("utf-8", "replace"))
    except ValueError:
        return []
    if not isinstance(records, list):
        return []
    names = set()
    pattern = re.compile(r"^[a-z0-9*_.-]+$", re.I)
    for record in records:
        if not isinstance(record, dict):
            continue
        for field in ("name_value", "common_name"):
            raw = record.get(field) or ""
            for candidate in str(raw).splitlines():
                candidate = candidate.strip().lower().lstrip("*.").rstrip(".")
                if not candidate or not pattern.match(candidate):
                    continue
                if not candidate.endswith("." + domain) and candidate != domain:
                    continue
                names.add(candidate)
    return sorted(names)


def enumerate_subdomains(domain: str, wordlist=None, threads: int = 40,
                         timeout: float = 4.0, rate: float = 0.0, use_crtsh: bool = True,
                         on_progress=None) -> dict:
    """Enumerate subdomains for a domain and return the resolved set."""
    domain = (domain or "").strip().lower().rstrip(".")
    result = {
        "domain": domain,
        "found": [],
        "total_checked": 0,
        "wildcard": None,
        "sources": [],
        "error": None,
        "notes": [],
    }
    if not domain or "." not in domain:
        result["error"] = f"invalid domain: {domain}"
        return result

    wildcard_ips = _wildcard_ips(domain, timeout)
    result["wildcard"] = sorted(wildcard_ips) if wildcard_ips else None
    if wildcard_ips:
        result["notes"].append(
            "wildcard DNS detected — entries matching the wildcard IPs were filtered")

    words = load_wordlist(wordlist)
    candidates = [f"{word}.{domain}" for word in words]
    ct_names = []
    if use_crtsh:
        ct_names = crtsh_lookup(domain, timeout=max(timeout, 15))
        if ct_names:
            result["sources"].append(f"crt.sh ({len(ct_names)} names)")
            for name in ct_names:
                if name not in candidates:
                    candidates.append(name)

    # dedupe preserving order
    seen = set()
    unique = []
    for name in candidates:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    result["total_checked"] = len(unique)

    limiter = RateLimiter(rate)
    outcomes = run_threaded(lambda host: _resolve_sub(host, timeout), unique,
                            threads=threads, limiter=limiter, on_progress=on_progress)

    found = []
    for _host, value, error in outcomes:
        if error is not None or not value:
            continue
        if wildcard_ips and set(value["ips"]) and set(value["ips"]).issubset(wildcard_ips):
            continue
        if value["subdomain"] in ct_names:
            value["source"] = "crt.sh"
            if "crt.sh" not in result["sources"]:
                result["sources"].append("crt.sh")
        found.append(value)

    found.sort(key=lambda item: item["subdomain"])
    result["found"] = found
    if "dns-bruteforce" not in result["sources"]:
        result["sources"].insert(0, "dns-bruteforce")
    if not found:
        result["notes"].append("no subdomains resolved — try a larger wordlist")
    return result


def dns_record_sweep(domain: str, timeout: float = 5.0) -> dict:
    """Collect the common DNS records for a domain."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "SRV"]
    result = {"domain": domain, "records": {}, "errors": {}}
    for qtype in record_types:
        try:
            response = query(domain, qtype, timeout=timeout)
            values = []
            for record in response["answers"]:
                values.append({"value": record["value"], "ttl": record["ttl"]})
            if values:
                result["records"][qtype] = values
        except DNSError as exc:
            result["errors"][qtype] = str(exc)
    return result
