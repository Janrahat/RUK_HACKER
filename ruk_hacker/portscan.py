"""TCP port scanner with threading, rate limiting and banner grabbing."""

from __future__ import annotations

import socket

from .net import grab_banner, tcp_connect
from .utils import (RateLimiter, primary_ip, resolve_host, run_threaded,
                    service_name)


def _scan_one(host: str, port: int, timeout: float, banners: bool):
    elapsed = tcp_connect(host, port, timeout=timeout)
    if elapsed is None:
        return None
    banner = grab_banner(host, port, timeout=timeout) if banners else ""
    return {
        "port": port,
        "state": "open",
        "service": service_name(port),
        "banner": banner,
        "latency_ms": round(elapsed * 1000, 1),
    }


def scan_host(host: str, ports, timeout: float = 3.0, threads: int = 60,
              rate: float = 0.0, banners: bool = False, on_progress=None) -> dict:
    """Scan a list of ports on a single host.

    Returns a dict with target metadata and the list of open ports.
    """
    ports = list(ports)
    result = {
        "target": host,
        "ips": [],
        "ip": None,
        "ports_scanned": len(ports),
        "open": [],
        "duration": 0.0,
        "error": None,
    }

    ips = resolve_host(host, timeout=min(timeout, 5))
    result["ips"] = ips
    if not ips:
        result["error"] = f"could not resolve host: {host}"
        return result
    result["ip"] = primary_ip(host, timeout=min(timeout, 5)) or ips[0]
    address = result["ip"]

    limiter = RateLimiter(rate)
    entries = [(_scan_host_worker, address, port) for port in ports]

    def _runner(item):
        _fn, addr, port = item
        return _fn(addr, port, timeout, banners)

    import time
    started = time.monotonic()
    outcomes = run_threaded(_runner, entries, threads=threads, limiter=limiter,
                            on_progress=on_progress)
    open_ports = [value for _item, value, error in outcomes if error is None and value]
    open_ports.sort(key=lambda entry: entry["port"])
    result["open"] = open_ports
    result["duration"] = round(time.monotonic() - started, 2)
    return result


def _scan_host_worker(host, port, timeout, banners):
    return _scan_one(host, port, timeout, banners)


def summarize_risk(open_ports) -> list:
    """Flag commonly risky exposed services."""
    risky = {
        21: ("FTP", "Cleartext file transfer — disable or use SFTP.", "high"),
        23: ("Telnet", "Cleartext remote shell — replace with SSH.", "critical"),
        25: ("SMTP", "Open relay risk — verify auth/relay restrictions.", "medium"),
        139: ("NetBIOS", "Legacy file sharing — block at the firewall.", "high"),
        445: ("SMB", "SMB exposure — block from the internet (ransomware vector).", "critical"),
        1433: ("MSSQL", "Database exposed — restrict to trusted networks.", "high"),
        3306: ("MySQL", "Database exposed — bind to localhost or use a VPN.", "high"),
        3389: ("RDP", "RDP exposure — put behind a VPN + MFA.", "critical"),
        4444: ("Metasploit", "Known backdoor port — investigate immediately.", "critical"),
        5432: ("PostgreSQL", "Database exposed — restrict access.", "high"),
        5900: ("VNC", "Remote desktop — tunnel through SSH/VPN.", "critical"),
        6379: ("Redis", "Often unauthenticated — bind to localhost.", "critical"),
        9200: ("Elasticsearch", "Often unauthenticated — never expose publicly.", "critical"),
        11211: ("Memcached", "Amplification risk — bind to localhost.", "high"),
        27017: ("MongoDB", "Often unauthenticated — restrict access.", "critical"),
    }
    findings = []
    for entry in open_ports:
        port = entry["port"]
        if port in risky:
            name, advice, severity = risky[port]
            findings.append({
                "port": port,
                "service": name,
                "severity": severity,
                "advice": advice,
            })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["port"]))
    return findings


def scan_multiple(hosts, ports, timeout=3.0, threads=60, rate=0.0, banners=False,
                  on_progress=None) -> list:
    results = []
    for index, host in enumerate(hosts, 1):
        if on_progress:
            on_progress(index - 1, len(hosts), f"host {host}")
        results.append(scan_host(host, ports, timeout=timeout, threads=threads,
                                 rate=rate, banners=banners))
        if on_progress:
            on_progress(index, len(hosts), f"host {host}")
    return results


def host_alive(host: str, timeout: float = 2.0) -> bool:
    """Cheap liveness check against a small set of always-listening ports."""
    for port in (443, 80, 22):
        if tcp_connect(host, port, timeout=timeout) is not None:
            return True
    return False


def socket_family_hint(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET
