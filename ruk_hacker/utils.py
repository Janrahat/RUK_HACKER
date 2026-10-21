"""Shared utilities: target validation, port parsing, rate limiting, threading."""

from __future__ import annotations

import ipaddress
import os
import random
import re
import socket
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 512, 513, 514, 587, 636, 993, 995, 1080, 1433, 1521, 1723, 2049,
    3000, 3128, 3306, 3389, 4444, 5000, 5432, 5555, 5900, 5984, 6379, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 10000, 27017,
]

SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 512: "exec", 513: "login",
    514: "shell", 587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2181: "zookeeper", 3000: "node/gitea", 3128: "squid", 3306: "mysql",
    3389: "rdp", 4444: "metasploit", 5000: "flask/upnp", 5432: "postgresql",
    5555: "adb", 5601: "kibana", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kube-api", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8086: "influxdb", 8443: "https-alt",
    8888: "http-alt", 9000: "php-fpm", 9090: "prometheus", 9200: "elasticsearch",
    9300: "elasticsearch", 10000: "webmin", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 50000: "sap",
}


def parse_ports(spec: str, limit: int = 65536) -> list:
    """Parse a port spec like '22,80,100-110,top' into a sorted int list."""
    if not spec:
        return list(TOP_PORTS)
    text = str(spec).strip().lower()
    if text in ("top", "top100", "default", "common"):
        return list(TOP_PORTS)
    if text in ("all", "full", "1-65535"):
        return list(range(1, limit + 1))

    ports = set()
    for chunk in re.split(r"[,\s]+", text):
        if not chunk:
            continue
        if chunk in ("top", "common"):
            ports.update(TOP_PORTS)
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(f"invalid port range: {chunk}")
            if start > end:
                start, end = end, start
            for port in range(max(1, start), min(limit, end) + 1):
                ports.add(port)
            continue
        try:
            port = int(chunk)
        except ValueError:
            raise ValueError(f"invalid port: {chunk}")
        if 1 <= port <= limit:
            ports.add(port)
    return sorted(ports)


def service_name(port: int) -> str:
    return SERVICE_MAP.get(port, "unknown")


# ---------------------------------------------------------------------------
# Target validation / normalisation
# ---------------------------------------------------------------------------

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$"
)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    value = value.rstrip(".")
    if not value or len(value) > 253:
        return False
    if ".." in value:
        return False
    return bool(DOMAIN_RE.match(value))


def normalize_target(target: str) -> str:
    """Strip scheme/path/credentials and return a bare host (or IP)."""
    target = (target or "").strip()
    if not target:
        raise ValueError("empty target")
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
    else:
        host = target.split("/")[0].split("?")[0]
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        if host.count(":") == 1:  # host:port
            host = host.split(":")[0]
    host = host.strip("[]").strip()
    if not host:
        raise ValueError(f"could not parse target: {target}")
    if not (is_ip(host) or is_domain(host)):
        raise ValueError(f"invalid host: {host}")
    return host


def normalize_url(target: str) -> str:
    """Return a full http(s) URL from a bare host or URL."""
    target = (target or "").strip()
    if not target:
        raise ValueError("empty target")
    if "://" not in target:
        return f"https://{target.split('/')[0]}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    return target


def ensure_scheme_url(target: str, scheme: str = "https") -> str:
    host = normalize_target(target)
    return f"{scheme}://{host}"


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------

def resolve_host(host: str, timeout: float = 4.0) -> list:
    """Resolve host to a list of IP strings (A + AAAA). Empty list on failure."""
    if is_ip(host):
        return [host]

    results = []

    def _worker():
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, OSError):
            return
        for info in infos:
            addr = info[4][0]
            if addr not in results:
                results.append(addr)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join(timeout)
    return results


def primary_ip(host: str, timeout: float = 4.0):
    ips = resolve_host(host, timeout)
    if not ips:
        return None
    for addr in ips:
        if ":" not in addr:
            return addr
    return ips[0]


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class RateLimiter:
    """Simple token-less minimum-interval limiter shared across threads."""

    def __init__(self, rate: float = 0.0):
        self.interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                delay = self._next - now
            else:
                delay = 0.0
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Threaded execution
# ---------------------------------------------------------------------------

def run_threaded(func, items, threads: int = 50, limiter: RateLimiter = None,
                 on_progress=None, timeout=None) -> list:
    """Run func over items concurrently, preserving input order.

    Returns a list of (item, result, error) tuples where error is None on success.
    The function never raises for individual item failures.
    """
    items = list(items)
    total = len(items)
    if total == 0:
        return []
    threads = max(1, min(int(threads or 1), 300))
    results = [None] * total
    done = 0

    def _task(index, item):
        if limiter is not None:
            limiter.wait()
        try:
            return index, item, func(item), None
        except Exception as exc:  # noqa: BLE001 - per-item isolation is intended
            return index, item, None, exc

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_task, idx, item) for idx, item in enumerate(items)]
        for future in as_completed(futures):
            index, item, value, error = future.result()
            results[index] = (item, value, error)
            done += 1
            if on_progress:
                try:
                    on_progress(done, total)
                except Exception:
                    pass
    return results


def bounded_map(func, items, threads: int = 50, timeout: float = None):
    """Parallel map that returns only successful values."""
    out = []
    for _item, value, error in run_threaded(func, items, threads=threads):
        if error is None and value is not None:
            out.append(value)
    return out


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def human_bytes(num: float) -> str:
    if num is None:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"


def format_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, sec = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z") or time.strftime("%Y-%m-%dT%H:%M:%S")


def now_stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def sanitize_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "report")
    return cleaned.strip("._") or "report"


def random_token(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def is_termux() -> bool:
    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    if os.path.isdir("/data/data/com.termux"):
        return True
    return "termux" in os.environ.get("HOME", "").lower()


def read_wordlist(path: str, default=None) -> list:
    """Read a newline wordlist file, ignoring comments and blanks."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = [line.strip() for line in fh]
    except OSError:
        return list(default or [])
    return [line for line in lines if line and not line.startswith("#")]


def safe_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def eprint(*args, **kwargs) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)
