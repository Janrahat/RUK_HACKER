"""IP intelligence: geolocation, ASN and reverse DNS (no API key required)."""

from __future__ import annotations

import json
import socket

from .net import http_request
from .utils import is_ip, primary_ip, reverse_dns

DEFAULT_ENDPOINT = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"


def _get_json(url: str, timeout: float = 8.0):
    response = http_request(url, timeout=timeout)
    if response.get("error"):
        return None, response["error"]
    if response.get("status") != 200:
        return None, f"HTTP {response.get('status')}"
    try:
        return json.loads(response["body"].decode("utf-8", "replace")), None
    except ValueError:
        return None, "invalid JSON response"


def geo_lookup(target: str, timeout: float = 8.0) -> dict:
    """Resolve a host and return geo/ASN details for its primary IP."""
    target = (target or "").strip()
    result = {
        "query": target,
        "ip": None,
        "reverse": "",
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "zip": None,
        "latitude": None,
        "longitude": None,
        "timezone": None,
        "isp": None,
        "org": None,
        "asn": None,
        "hosting": None,
        "proxy": None,
        "mobile": None,
        "source": None,
        "error": None,
    }
    if not target:
        result["error"] = "empty target"
        return result

    if is_ip(target):
        ip = target
    else:
        ip = primary_ip(target, timeout=min(timeout, 6))
        if not ip:
            result["error"] = f"could not resolve {target}"
            return result
    result["ip"] = ip

    try:
        result["reverse"] = reverse_dns(ip) or ""
    except OSError:
        result["reverse"] = ""

    payload, error = _get_json(DEFAULT_ENDPOINT.format(ip=ip), timeout=timeout)
    if payload is None or payload.get("status") == "fail":
        result["error"] = error or (payload or {}).get("message", "lookup failed")
        return result

    result.update({
        "country": payload.get("country"),
        "country_code": payload.get("countryCode"),
        "region": payload.get("regionName") or payload.get("region"),
        "city": payload.get("city"),
        "zip": payload.get("zip"),
        "latitude": payload.get("lat"),
        "longitude": payload.get("lon"),
        "timezone": payload.get("timezone"),
        "isp": payload.get("isp"),
        "org": payload.get("org"),
        "asn": payload.get("as"),
        "hosting": payload.get("hosting"),
        "proxy": payload.get("proxy"),
        "mobile": payload.get("mobile"),
        "source": "ip-api.com",
    })
    if not result["reverse"] and payload.get("reverse"):
        result["reverse"] = payload["reverse"]
    return result


def my_ip(timeout: float = 8.0) -> dict:
    """Return the public egress IP with geo info."""
    payload, error = _get_json("http://ip-api.com/json/?fields=status,message,query,country,city,isp,org,as,timezone", timeout=timeout)
    if payload is None:
        return {"ip": None, "error": error}
    if payload.get("status") == "fail":
        return {"ip": None, "error": payload.get("message", "lookup failed")}
    return {
        "ip": payload.get("query"),
        "country": payload.get("country"),
        "city": payload.get("city"),
        "isp": payload.get("isp"),
        "org": payload.get("org"),
        "asn": payload.get("as"),
        "timezone": payload.get("timezone"),
        "error": None,
    }


def local_ip() -> str:
    """Best-effort local (LAN) address without sending packets anywhere."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()
