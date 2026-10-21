"""Directory / path discovery with soft-404 detection and rate limiting."""

from __future__ import annotations

from urllib.parse import urljoin

from .config import data_path
from .net import http_request
from .utils import RateLimiter, normalize_url, read_wordlist, run_threaded

DEFAULT_PATHS = [
    "admin", "admin/login", "administrator", "login", "dashboard", "panel",
    "api", "api/v1", "graphql", "swagger", "swagger-ui.html", "api-docs",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt", ".well-known/security.txt",
    "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql", "database.sql",
    ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
    "config.php", "config.json", "config.yml", "web.config", ".htaccess",
    "phpinfo.php", "info.php", "server-status", "server-info", "test",
    "uploads", "files", "images", "assets", "static", "media", "download",
    "docs", "documentation", "readme.md", "README.md", "CHANGELOG.md",
    "wp-admin", "wp-login.php", "wp-content", "xmlrpc.php",
    "console", "debug", "actuator", "actuator/health", "metrics", "health",
    "status", "version", "private", "secret", "secrets", "internal",
    "old", "tmp", "temp", "logs", "log", "error.log", "access.log",
    "install", "setup", "update", "cgi-bin", "register", "signup",
    "user", "users", "account", "profile", "settings", "portal",
]

INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500, 503}

NOISE_SIZES_TOLERANCE = 0


def load_wordlist(path: str = None) -> list:
    if path:
        words = read_wordlist(path, default=[])
        if words:
            return words
    bundled = data_path("common_paths.txt")
    words = read_wordlist(bundled, default=[])
    return words or list(DEFAULT_PATHS)


def dirscan(base_url: str, wordlist=None, threads: int = 30, timeout: float = 8.0,
            rate: float = 0.0, codes=None, suppress_codes=None, on_progress=None,
            extra_headers: dict = None) -> dict:
    """Discover paths on base_url.

    Performs a baseline request with a random non-existent path to learn what a
    404 (or soft-404) looks like, then flags responses that differ from it.
    """
    result = {
        "url": None,
        "baseline": None,
        "found": [],
        "tested": 0,
        "duration": 0.0,
        "error": None,
        "notes": [],
    }
    try:
        result["url"] = normalize_url(base_url)
    except ValueError as exc:
        result["error"] = str(exc)
        return result
    base = result["url"].rstrip("/") + "/"

    words = list(wordlist) if wordlist else load_wordlist()
    words = [str(word).strip().lstrip("/") for word in words if str(word).strip()]
    if not words:
        result["error"] = "empty path list"
        return result

    import time
    started = time.monotonic()

    # --- Baseline / soft-404 calibration --------------------------------
    import random
    import string
    probe = "".join(random.choice(string.ascii_lowercase) for _ in range(14))
    baseline_resp = http_request(urljoin(base, f"{probe}{probe}"), method="HEAD",
                                 timeout=timeout, headers=extra_headers)
    baseline = {
        "status": baseline_resp.get("status"),
        "length": len(baseline_resp.get("body") or b""),
        "error": baseline_resp.get("error"),
    }
    # Some servers reject HEAD (405/501) or omit a body: fall back to GET so the
    # baseline reflects what a normal request to a missing path looks like.
    if baseline["status"] is None or baseline["status"] >= 400 or baseline["length"] == 0:
        baseline_resp = http_request(urljoin(base, f"{probe}{probe}"), method="GET",
                                     timeout=timeout, headers=extra_headers)
        if baseline_resp.get("status") is not None:
            baseline["status"] = baseline_resp.get("status")
            baseline["length"] = len(baseline_resp.get("body") or b"")
            baseline["error"] = baseline_resp.get("error")
    result["baseline"] = baseline
    if baseline["error"]:
        result["notes"].append(f"baseline request issue: {baseline['error']}")

    allow = set(codes) if codes else None
    deny = set(suppress_codes) if suppress_codes else {404}
    limiter = RateLimiter(rate)

    def _probe(path):
        url = urljoin(base, path)
        response = http_request(url, method="GET", timeout=timeout,
                                allow_redirects=False, headers=extra_headers)
        if response.get("error"):
            return {"path": path, "status": None, "length": 0,
                    "redirect": None, "error": response["error"]}
        status = response.get("status")
        length = len(response.get("body") or b"")
        location = ""
        for key, value in response.get("headers") or []:
            if key.lower() == "location":
                location = value
                break
        return {"path": path, "status": status, "length": length,
                "redirect": location or None, "error": None}

    outcomes = run_threaded(_probe, words, threads=threads, limiter=limiter,
                            on_progress=on_progress)
    result["tested"] = len(words)
    findings = []
    for _word, value, error in outcomes:
        if error is not None or value is None:
            continue
        if value.get("error"):
            continue
        status = value.get("status")
        if status is None:
            continue
        if allow:
            if status not in allow:
                continue
        elif status not in INTERESTING_STATUS:
            continue
        if status in deny:
            continue
        # soft-404 filter
        if (baseline["status"] == status and baseline["length"]
                and abs(value["length"] - baseline["length"]) <= NOISE_SIZES_TOLERANCE
                and status == 200):
            continue
        findings.append({
            "path": "/" + value["path"],
            "url": urljoin(base, value["path"]),
            "status": status,
            "length": value["length"],
            "redirect": value.get("redirect"),
        })

    order = {200: 0, 201: 0, 204: 1, 401: 2, 403: 3, 301: 4, 302: 4, 307: 4,
             405: 5, 500: 6, 503: 6}
    findings.sort(key=lambda item: (order.get(item["status"], 9), item["path"]))
    result["found"] = findings
    result["duration"] = round(time.monotonic() - started, 2)
    if not findings:
        result["notes"].append("no accessible paths detected with the current list")
    return result
