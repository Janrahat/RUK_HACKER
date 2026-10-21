"""Local system information for Termux / Android."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import sys

from .config import APP_NAME, VERSION
from .ipinfo import local_ip
from .utils import human_bytes, is_termux


def _cmd(command, timeout: float = 4.0) -> str:
    try:
        out = subprocess.run(command, shell=True, capture_output=True, text=True,
                             timeout=timeout)
        return (out.stdout or "").strip()
    except (subprocess.SubprocessError, OSError):
        return ""


def _meminfo() -> dict:
    info = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                key, _, value = line.partition(":")
                value = value.strip().split()
                if value:
                    try:
                        info[key.strip()] = int(value[0]) * 1024
                    except ValueError:
                        pass
    except OSError:
        pass
    total = info.get("MemTotal")
    available = info.get("MemAvailable") or info.get("MemFree")
    used = (total - available) if (total and available) else None
    return {
        "total": human_bytes(total) if total else None,
        "available": human_bytes(available) if available else None,
        "used": human_bytes(used) if used else None,
        "percent_used": round(used * 100 / total, 1) if used and total else None,
    }


def _uptime() -> str:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            seconds = float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return ""
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _cpu() -> dict:
    model = ""
    cores = os.cpu_count()
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith(("hardware", "model name")):
                    model = line.split(":", 1)[-1].strip()
                    break
    except OSError:
        pass
    load = os.getloadavg() if hasattr(os, "getloadavg") else None
    return {
        "model": model or platform.processor() or "unknown",
        "cores": cores,
        "architecture": platform.machine(),
        "load_1m": round(load[0], 2) if load else None,
        "load_5m": round(load[1], 2) if load else None,
        "load_15m": round(load[2], 2) if load else None,
    }


def _storage(path: str = "/") -> dict:
    try:
        usage = shutil.disk_usage(path)
        return {
            "path": path or "/",
            "total": human_bytes(usage.total),
            "used": human_bytes(usage.used),
            "free": human_bytes(usage.free),
            "percent_used": round(usage.used * 100 / usage.total, 1) if usage.total else None,
        }
    except OSError:
        return {"path": path, "total": None, "used": None, "free": None}


def _installed_pkgs() -> dict:
    out = {}
    for name, command in (
        ("python", "python --version"),
        ("pip", "pip --version"),
        ("openssl", "openssl version"),
        ("curl", "curl --version | head -1"),
        ("git", "git --version"),
        ("nmap", "nmap --version | head -1"),
        ("dig", "dig -v 2>&1 | head -1"),
        ("whois", "whois --version 2>&1 | head -1"),
        ("jq", "jq --version"),
        ("termux_api", "command -v termux-toast"),
    ):
        value = _cmd(command)
        if value:
            out[name] = value.splitlines()[0][:80]
    return out


def _network() -> dict:
    interfaces = []
    try:
        for entry in sorted(os.listdir("/sys/class/net")):
            if entry == "lo":
                continue
            address = ""
            try:
                with open(f"/sys/class/net/{entry}/address", "r", encoding="utf-8") as fh:
                    address = fh.read().strip()
            except OSError:
                pass
            state = ""
            try:
                with open(f"/sys/class/net/{entry}/operstate", "r", encoding="utf-8") as fh:
                    state = fh.read().strip()
            except OSError:
                pass
            interfaces.append({"name": entry, "mac": address, "state": state})
    except OSError:
        pass
    return {
        "hostname": socket.gethostname(),
        "local_ip": local_ip(),
        "interfaces": interfaces,
    }


def sysinfo() -> dict:
    """Collect a full system snapshot."""
    return {
        "tool": f"{APP_NAME} v{VERSION}",
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "termux": is_termux(),
        "prefix": os.environ.get("PREFIX", ""),
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
        "home": os.path.expanduser("~"),
        "cwd": os.getcwd(),
        "timezone": _cmd("getprop persist.sys.timezone") or os.environ.get("TZ", ""),
        "android_version": _cmd("getprop ro.build.version.release"),
        "device_model": _cmd("getprop ro.product.model"),
        "android_arch": _cmd("getprop ro.product.cpu.abi"),
        "uptime": _uptime(),
        "cpu": _cpu(),
        "memory": _meminfo(),
        "storage_home": _storage(os.path.expanduser("~")),
        "network": _network(),
        "installed": _installed_pkgs(),
    }
