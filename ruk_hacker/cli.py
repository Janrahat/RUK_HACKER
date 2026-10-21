"""CLI entry logic: argparse subcommands, interactive menu and output rendering."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import config as cfgmod
from . import ui
from .config import APP_NAME, LEGAL_NOTICE, VERSION, load_config, save_config, set_value
from .dnsclient import DNSError, query, reverse, trace
from .dirscan import dirscan, load_wordlist as load_paths
from .ipinfo import geo_lookup, local_ip, my_ip
from .portscan import scan_host, summarize_risk
from .report import save_report
from .subdomains import (dns_record_sweep, enumerate_subdomains,
                         load_wordlist as load_subdomains)
from .sysinfo import sysinfo
from .utils import format_duration, normalize_target, parse_ports, resolve_host
from .webaudit import cert_info, header_audit, technology_hints
from .whois_lookup import days_until, whois_domain, whois_ip

MODULES = ["scan", "ports", "dns", "whois", "web", "ssl", "ip", "subdomains",
           "dirscan", "sysinfo", "report", "update", "version", "config"]


# ---------------------------------------------------------------------------
# Legal gate
# ---------------------------------------------------------------------------

def legal_gate(interactive: bool = True, force_accept: bool = False) -> bool:
    """Ensure the user has accepted the authorised-use notice.

    Acceptance is stored once in ~/.ruk_hacker/config.json. It can also be
    given for a single run with --accept-terms or RUK_ACCEPT_TERMS=1, which
    keeps pipelines (cron, scripts, CI) non-blocking.
    """
    cfg = load_config()
    if cfg.get("terms_accepted") or force_accept:
        if force_accept and not cfg.get("terms_accepted"):
            cfg["terms_accepted"] = True
            save_config(cfg)
        return True
    if os.environ.get("RUK_ACCEPT_TERMS") not in (None, "", "0", "false", "False"):
        if not cfg.get("terms_accepted"):
            cfg["terms_accepted"] = True
            save_config(cfg)
        return True
    if not interactive:
        return False

    ui.header("Authorised use required", "⚠")
    print()
    for line in LEGAL_NOTICE.splitlines():
        print("  " + ui.paint(line, "yellow"))
    print()
    if not ui.confirm("I confirm I will only test systems I own or have permission to test",
                      default=False):
        ui.error("Acceptance required. Exiting.")
        return False
    cfg["terms_accepted"] = True
    save_config(cfg)
    ui.success("Thanks — acceptance saved to ~/.ruk_hacker/config.json")
    return True


# ---------------------------------------------------------------------------
# Shared option plumbing
# ---------------------------------------------------------------------------

def _common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-t", "--timeout", type=float, default=None,
                        help="per-request timeout in seconds (default: 5)")
    parser.add_argument("--threads", type=int, default=None,
                        help="worker threads (default: 60)")
    parser.add_argument("--rate", type=float, default=None,
                        help="max requests per second, 0 = unlimited")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="print machine-readable JSON to stdout")
    parser.add_argument("--out", metavar="PATH", default=None,
                        help="write a report to this path")
    parser.add_argument("--format", choices=["json", "html", "txt", "all"], default=None,
                        help="report format when --out is used (default: by extension)")
    parser.add_argument("--quiet", action="store_true", help="suppress the banner")


def _resolve(cfg, args, key, default):
    value = getattr(args, key, None)
    if value is None:
        value = cfg.get(key, default)
    return value


def _emit(module: str, data: dict, args, cfg, duration: str = "—") -> int:
    """Render results, honouring --json/--out/--quiet."""
    if getattr(args, "as_json", False):
        print(json.dumps({"module": module, "version": VERSION, "data": data},
                         indent=2, ensure_ascii=False, default=str))
    out_path = getattr(args, "out", None)
    fmt = getattr(args, "format", None)
    if out_path:
        if not fmt:
            ext = os.path.splitext(out_path)[1].lstrip(".").lower()
            fmt = ext if ext in ("json", "html", "txt") else "json"
        result = save_report(module, data, fmt=fmt, path=out_path, duration=duration)
        if result.get("ok"):
            ui.success(f"Report written: {result['path']}")
        else:
            ui.error(f"Could not write report: {result.get('error')}")
    elif getattr(args, "as_json", False) is False and cfg.get("auto_save"):
        result = save_report(module, data, fmt="json", duration=duration)
        if result.get("ok"):
            ui.info(f"auto-saved → {result['path']}")
    return 0


# ---------------------------------------------------------------------------
# Module renderers (text mode)
# ---------------------------------------------------------------------------

def render_scan(data: dict) -> None:
    ui.header(f"Port scan · {data.get('target')}", "🔍")
    ui.kv_table({
        "target": data.get("target"),
        "resolved ip": data.get("ip"),
        "ips": data.get("ips"),
        "ports scanned": data.get("ports_scanned"),
        "open found": len(data.get("open") or []),
        "duration": f"{data.get('duration')} s",
    })
    rows = [[entry["port"], entry["service"], entry.get("banner") or "—",
             entry.get("latency_ms")] for entry in data.get("open") or []]
    ui.table(["port", "service", "banner", "ms"], rows, title="Open ports")
    risks = data.get("risk") or []
    if risks:
        ui.table(["severity", "port", "service", "advice"],
                 [[item["severity"], item["port"], item["service"], item["advice"]]
                  for item in risks], title="Risk flags")
    else:
        ui.success("No commonly risky services exposed.")
    ui.footer()


def render_dns(data: dict) -> None:
    domain = data.get("domain") or data.get("target")
    ui.header(f"DNS · {domain}", "🌐")
    records = data.get("records") or {}
    if not records:
        ui.warn("No records returned (domain may not exist or DNS blocked).")
    for rtype, values in records.items():
        rows = []
        for item in values:
            value = item.get("value") if isinstance(item, dict) else item
            ttl = item.get("ttl") if isinstance(item, dict) else "—"
            if isinstance(value, dict):
                value = ", ".join(f"{k}={v}" for k, v in value.items())
            rows.append([value, ttl])
        ui.table(["value", "ttl"], rows, title=rtype)
    if data.get("reverse"):
        ui.table(["ptr"], [[item] for item in data["reverse"]], title="Reversed")
    if data.get("resolved_ips"):
        ui.kv_table({"resolved": data["resolved_ips"]}, title="Resolution")
    if data.get("chain"):
        ui.table(["from", "to"], [[c["from"], c["to"]] for c in data["chain"]],
                 title="CNAME chain")
    if data.get("errors"):
        ui.warn(f"some record types failed: {', '.join(sorted(data['errors']))}")
    ui.footer()


def render_whois(data: dict) -> None:
    ui.header(f"WHOIS · {data.get('query')}", "📋")
    fields = data.get("fields") or {}
    if fields:
        ui.kv_table({k.replace("_", " "): v for k, v in fields.items()}, title="Parsed fields")
    else:
        ui.warn("No fields parsed — showing raw response snippet.")
        snippet = (data.get("raw") or "").strip().splitlines()[:40]
        for line in snippet:
            print("  " + ui.paint(line[:110], "gray"))
    if fields.get("expires"):
        remaining = days_until(fields["expires"])
        if remaining is not None:
            color = "red" if remaining < 30 else ("yellow" if remaining < 90 else "green")
            print()
            ui.info(f"expires in {ui.paint(str(remaining) + ' days', color, bold=True)}")
    if data.get("referrals"):
        ui.info("referral chain: " + " → ".join(data["referrals"]))
    if data.get("error"):
        ui.error(data["error"])
    ui.footer()


def render_ip(data: dict) -> None:
    ui.header(f"IP intelligence · {data.get('query')}", "📍")
    ui.kv_table({
        "ip": data.get("ip"),
        "reverse dns": data.get("reverse"),
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "zip": data.get("zip"),
        "coordinates": (f"{data.get('latitude')}, {data.get('longitude')}"
                        if data.get("latitude") is not None else None),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "organisation": data.get("org"),
        "asn": data.get("asn"),
        "hosting": data.get("hosting"),
        "proxy/vpn": data.get("proxy"),
        "mobile": data.get("mobile"),
        "source": data.get("source"),
    }, title="Geo / ASN")
    if data.get("error"):
        ui.error(data["error"])
    ui.footer()


def render_web(data: dict) -> None:
    ui.header(f"Web header audit · {data.get('url')}", "🛡")
    ui.kv_table({
        "status": f"{data.get('status')} {data.get('reason') or ''}",
        "server": data.get("server"),
        "security grade": ui.paint(str(data.get("grade")), _grade_color(data.get("grade")), bold=True),
        "score": f"{data.get('score')}/{data.get('max_score')}",
        "redirects": len(data.get("redirects") or []),
        "technologies": ", ".join(data.get("technologies") or []) or None,
        "response time": f"{data.get('elapsed')} s",
    })
    rows = []
    for item in data.get("security") or []:
        state = ui.paint("present", "green") if item["present"] else ui.paint("missing", "red")
        rows.append([item["header"], state, item.get("value") or "—"])
    ui.table(["header", "state", "value"], rows, title="Security headers")
    if data.get("missing"):
        ui.table(["header", "advice"],
                 [[item["header"], item["advice"]] for item in data["missing"]],
                 title="Recommendations")
    if data.get("disclosure"):
        ui.table(["header", "value"], [[k, v] for k, v in data["disclosure"].items()],
                 title="Information disclosure")
    if data.get("cookies"):
        ui.table(["cookie", "issues"],
                 [[c["name"], ", ".join(c["issues"]) or "ok"] for c in data["cookies"]],
                 title="Cookies")
    if data.get("error"):
        ui.error(data["error"])
    ui.footer()


def _grade_color(grade):
    if not grade:
        return "gray"
    if grade.startswith("A"):
        return "green"
    if grade == "B":
        return "cyan"
    if grade == "C":
        return "yellow"
    return "red"


def render_ssl(data: dict) -> None:
    ui.header(f"TLS certificate · {data.get('host')}:{data.get('port')}", "🔐")
    if not data.get("ok"):
        ui.error(f"could not retrieve certificate: {data.get('error')}")
        return
    subject = data.get("subject") or {}
    issuer = data.get("issuer") or {}
    ui.kv_table({
        "subject cn": subject.get("commonName"),
        "organisation": subject.get("organizationName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "valid from": data.get("not_before"),
        "valid until": data.get("not_after"),
        "days left": data.get("days_left"),
        "tls version": data.get("version"),
        "cipher": data.get("cipher"),
        "bits": data.get("bits"),
        "chain trusted": data.get("chain_trusted"),
        "self signed": data.get("self_signed"),
        "sha-256": data.get("sha256"),
    }, title="Certificate")
    if data.get("san"):
        ui.table(["subject alternative names"], [[name] for name in data["san"]])
    for warning in data.get("protocol_warnings") or []:
        ui.warn(warning)
    if not data.get("chain_trusted"):
        ui.warn("Chain is not trusted by the system CA store (self-signed, expired or incomplete chain).")
    ui.footer()


def render_subdomains(data: dict) -> None:
    ui.header(f"Subdomains · {data.get('domain')}", "🕸")
    ui.kv_table({
        "domain": data.get("domain"),
        "found": len(data.get("found") or []),
        "checked": data.get("total_checked"),
        "sources": ", ".join(data.get("sources") or []),
        "wildcard dns": ", ".join(data.get("wildcard") or []) or "none",
    })
    rows = [[item["subdomain"], ", ".join(item.get("ips") or []),
             ", ".join(item.get("cnames") or []) or "—", item.get("source")]
            for item in data.get("found") or []]
    ui.table(["subdomain", "ips", "cname", "source"], rows, title="Resolved hosts")
    for note in data.get("notes") or []:
        ui.warn(note)
    if data.get("error"):
        ui.error(data["error"])
    ui.footer()


def render_dirscan(data: dict) -> None:
    ui.header(f"Path discovery · {data.get('url')}", "📁")
    baseline = data.get("baseline") or {}
    ui.kv_table({
        "target": data.get("url"),
        "paths tested": data.get("tested"),
        "found": len(data.get("found") or []),
        "baseline status": baseline.get("status"),
        "duration": f"{data.get('duration')} s",
    })
    rows = []
    for item in data.get("found") or []:
        status = item.get("status")
        color = "green" if status == 200 else ("yellow" if status and status < 400 else "red")
        rows.append([ui.paint(str(item["path"]), "white"),
                     ui.paint(str(status), color, bold=True),
                     item.get("length"), item.get("redirect") or "—"])
    ui.table(["path", "status", "bytes", "redirect"], rows, title="Discovered")
    for note in data.get("notes") or []:
        ui.warn(note)
    if data.get("error"):
        ui.error(data["error"])
    ui.footer()


def render_sysinfo(data: dict) -> None:
    ui.header("System information", "📱")
    ui.kv_table({k.replace("_", " "): v for k, v in data.items()
                 if not isinstance(v, (dict, list))}, title="Device")
    for key in ("cpu", "memory", "storage_home", "network", "installed"):
        if isinstance(data.get(key), dict):
            ui.kv_table(data[key], title=key.replace("_", " "))
    if data.get("network", {}).get("interfaces"):
        ui.table(["iface", "mac", "state"],
                 [[i["name"], i.get("mac") or "—", i.get("state") or "—"]
                  for i in data["network"]["interfaces"]], title="Interfaces")
    ui.footer()


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_ports(args, cfg) -> int:
    """Alias for scan with the top-ports list."""
    if not getattr(args, "port", None):
        args.port = "top"
    return cmd_scan(args, cfg)


def cmd_scan(args, cfg) -> int:
    target = normalize_target(args.target)
    ports = parse_ports(getattr(args, "port", None) or "top")
    timeout = _resolve(cfg, args, "timeout", 5.0)
    threads = _resolve(cfg, args, "threads", 60)
    rate = _resolve(cfg, args, "rate", 0.0)

    if not getattr(args, "quiet", False) and not getattr(args, "as_json", False):
        ui.header(f"Scanning {target}", "🎯")
        ui.info(f"{len(ports)} ports · {threads} threads · timeout {timeout}s"
                + (f" · {rate}/s" if rate else ""))

    ips = resolve_host(target, timeout=min(timeout, 5))
    if not ips:
        ui.error(f"could not resolve {target}")
        return 2

    progress = None
    if not getattr(args, "quiet", False) and not getattr(args, "as_json", False):
        progress = lambda done, total, label=None: ui.progress(done, total, target)

    started = time.monotonic()
    data = scan_host(target, ports, timeout=timeout, threads=threads, rate=rate,
                     banners=getattr(args, "banners", False), on_progress=progress)
    data["risk"] = summarize_risk(data.get("open") or [])
    elapsed = format_duration(time.monotonic() - started)

    if not getattr(args, "as_json", False):
        if not data["open"]:
            ui.warn("no open ports found — host may be firewalled or offline")
        render_scan(data)
    return _emit("scan", data, args, cfg, duration=elapsed)


def cmd_dns(args, cfg) -> int:
    target = args.target.strip()
    timeout = _resolve(cfg, args, "timeout", 5.0)
    server = getattr(args, "server", None)
    if server:
        cfg["dns_servers"] = [server]

    is_target_ip = _looks_ip(target)
    data = {"domain": target, "target": target, "records": {}, "errors": {}}

    if is_target_ip:
        try:
            ptr = reverse(target, server=server, timeout=timeout)
            data["reverse"] = ptr
            data["resolved_ips"] = [target]
            if ptr:
                data["records"]["PTR"] = [{"value": name, "ttl": ""} for name in ptr]
        except DNSError as exc:
            data["errors"]["PTR"] = str(exc)
    else:
        sweep = dns_record_sweep(target, timeout=timeout)
        data["records"] = sweep["records"]
        data["errors"] = sweep.get("errors") or {}
        data["resolved_ips"] = resolve_host(target, timeout=timeout)
        data["chain"] = trace(target, timeout=timeout)

    if getattr(args, "record", None):
        qtype = args.record.upper()
        try:
            response = query(target, qtype, server=server, timeout=timeout)
            data["records"] = {qtype: [{"value": r["value"], "ttl": r["ttl"]}
                                       for r in response["answers"]]}
            data["status"] = response.get("status")
        except DNSError as exc:
            data["errors"][qtype] = str(exc)

    if not getattr(args, "as_json", False):
        render_dns(data)
    return _emit("dns", data, args, cfg)


def cmd_whois(args, cfg) -> int:
    target = args.target.strip()
    timeout = _resolve(cfg, args, "timeout", 12.0)
    if _looks_ip(target):
        data = whois_ip(target, timeout=timeout)
    else:
        data = whois_domain(target, timeout=timeout)
    if not getattr(args, "as_json", False):
        render_whois(data)
    elif data.get("raw"):
        data["raw"] = data["raw"][:4000]
    return _emit("whois", data, args, cfg)


def cmd_ip(args, cfg) -> int:
    timeout = _resolve(cfg, args, "timeout", 8.0)
    target = getattr(args, "target", None)
    if getattr(args, "me", False) or not target:
        data = my_ip(timeout=timeout)
        data["local_ip"] = local_ip()
        data["query"] = data.get("ip")
    else:
        data = geo_lookup(target, timeout=timeout)
    if not getattr(args, "as_json", False):
        render_ip(data)
    return _emit("ip", data, args, cfg)


def cmd_web(args, cfg) -> int:
    timeout = _resolve(cfg, args, "timeout", 10.0)
    data = header_audit(args.target, timeout=timeout,
                        follow=not getattr(args, "no_redirect", False),
                        insecure=getattr(args, "insecure", False))
    data["technologies"] = technology_hints(data)
    if getattr(args, "headers_only", False):
        data["security"] = []
        data["missing"] = []
    if not getattr(args, "as_json", False):
        if getattr(args, "headers_only", False):
            ui.header(f"Headers · {data.get('url')}", "📨")
            ui.kv_table(dict(data.get("headers") or {}))
        else:
            render_web(data)
    return _emit("web", data, args, cfg)


def cmd_ssl(args, cfg) -> int:
    timeout = _resolve(cfg, args, "timeout", 10.0)
    target = args.target.strip()
    port = 443
    if "://" in target:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        target = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else port)
    elif ":" in target and target.count(":") == 1:
        host, _, port_text = target.partition(":")
        if port_text.isdigit():
            target, port = host, int(port_text)
    data = cert_info(target, port=port, timeout=timeout)
    if not getattr(args, "as_json", False):
        render_ssl(data)
    return _emit("ssl", data, args, cfg)


def cmd_subdomains(args, cfg) -> int:
    domain = normalize_target(args.target)
    timeout = _resolve(cfg, args, "timeout", 4.0)
    threads = _resolve(cfg, args, "threads", 40)
    rate = _resolve(cfg, args, "rate", 0.0)
    wordlist = None
    if getattr(args, "wordlist", None):
        wordlist = load_subdomains(args.wordlist)
    if not getattr(args, "as_json", False):
        ui.header(f"Enumerating subdomains of {domain}", "🕸")
        ui.info(f"wordlist {len(wordlist) if wordlist else len(load_subdomains())} labels"
                f" · {'crt.sh enabled' if not args.no_crtsh else 'dns only'}")
    progress = None
    if not getattr(args, "as_json", False) and not getattr(args, "quiet", False):
        progress = lambda done, total, label=None: ui.progress(done, total, domain)
    data = enumerate_subdomains(domain, wordlist=wordlist, threads=threads,
                                timeout=timeout, rate=rate,
                                use_crtsh=not getattr(args, "no_crtsh", False),
                                on_progress=progress)
    if not getattr(args, "as_json", False):
        render_subdomains(data)
    return _emit("subdomains", data, args, cfg)


def cmd_dirscan(args, cfg) -> int:
    timeout = _resolve(cfg, args, "timeout", 8.0)
    threads = _resolve(cfg, args, "threads", 30)
    rate = _resolve(cfg, args, "rate", 0.0)
    words = load_paths(getattr(args, "wordlist", None))
    codes = set()
    for chunk in (getattr(args, "codes", None) or "200,204,301,302,307,401,403,405,500").split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            codes.add(int(chunk))
    if not getattr(args, "as_json", False):
        ui.header(f"Path discovery · {args.target}", "📁")
        ui.info(f"{len(words)} paths · {threads} threads"
                + (f" · {rate}/s" if rate else ""))
    progress = None
    if not getattr(args, "as_json", False) and not getattr(args, "quiet", False):
        progress = lambda done, total, label=None: ui.progress(done, total, args.target)
    data = dirscan(args.target, wordlist=words, threads=threads, timeout=timeout,
                   rate=rate, codes=codes, on_progress=progress)
    if not getattr(args, "as_json", False):
        render_dirscan(data)
    return _emit("dirscan", data, args, cfg)


def cmd_sysinfo(args, cfg) -> int:
    data = sysinfo()
    if not getattr(args, "as_json", False):
        render_sysinfo(data)
    return _emit("sysinfo", data, args, cfg)


def cmd_report(args, cfg) -> int:
    """Rebuild a report from a previously saved JSON file."""
    path = os.path.expanduser(args.input)
    if not os.path.isfile(path):
        ui.error(f"file not found: {path}")
        return 2
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError) as exc:
        ui.error(f"could not read JSON: {exc}")
        return 2
    module = payload.get("module", "report")
    data = payload.get("data", payload)
    fmt = args.format or "html"
    result = save_report(module, data, fmt=fmt, path=args.out,
                         duration=payload.get("duration", "—"))
    if result.get("ok"):
        for item in result.get("written") or []:
            ui.success(f"{item['path']}  ({item['bytes']} bytes)")
        return 0
    ui.error(result.get("error") or "failed")
    return 1


def cmd_update(args, cfg) -> int:
    from .updater import check_for_update, self_update
    if getattr(args, "apply", False):
        return self_update()
    result = check_for_update()
    if result.get("error"):
        ui.warn(f"update check failed: {result['error']}")
        ui.info(f"current version: {VERSION}")
        return 1
    ui.kv_table({
        "current version": VERSION,
        "latest version": result.get("latest"),
        "status": ui.paint("update available", "yellow", bold=True)
        if result.get("update_available") else ui.paint("up to date", "green"),
    }, title="Update check")
    if result.get("notes"):
        print()
        for line in str(result["notes"]).splitlines()[:8]:
            ui.bullet(line)
    if result.get("url"):
        ui.info(f"release: {result['url']}")
    return 0


def cmd_version(args, cfg) -> int:
    print(f"{APP_NAME} v{VERSION}")
    if getattr(args, "as_json", False):
        print(json.dumps({"name": APP_NAME, "version": VERSION,
                          "python": sys.version.split()[0],
                          "config": cfgmod.CONFIG_FILE}, indent=2))
    return 0


def cmd_config(args, cfg) -> int:
    if getattr(args, "set", None):
        key, _, value = args.set.partition("=")
        key = key.strip()
        if not key:
            ui.error("use --set key=value")
            return 2
        value = _coerce(value.strip())
        cfg = set_value(key, value)
        ui.success(f"{key} = {value}")
        return 0
    if getattr(args, "unset", None):
        key = args.unset.strip()
        default = cfgmod.DEFAULTS.get(key)
        cfg = set_value(key, default)
        ui.success(f"{key} reset to default ({default!r})")
        return 0
    ui.header("Configuration", "⚙")
    ui.kv_table(cfg, title=cfgmod.CONFIG_FILE)
    ui.info("change a value with: ruk_hacker config --set key=value")
    return 0


def _coerce(value: str):
    lowered = value.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _looks_ip(value: str) -> bool:
    from .utils import is_ip
    return is_ip(value)


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

MENU_ITEMS = [
    ("1", "Port scanner", "TCP connect scan with banners + risk flags"),
    ("2", "DNS lookup", "A/AAAA/MX/NS/TXT/SOA/CAA + CNAME chain"),
    ("3", "WHOIS", "Domain / IP registration data"),
    ("4", "IP intelligence", "Geo, ISP, ASN, reverse DNS"),
    ("5", "Web header audit", "Security headers, grade, cookies"),
    ("6", "TLS certificate", "Validity, SAN, chain trust, cipher"),
    ("7", "Subdomain enumeration", "DNS brute force + crt.sh"),
    ("8", "Path discovery", "Directory/file discovery with soft-404 detection"),
    ("9", "System information", "Device, CPU, memory, storage, packages"),
    ("10", "Quick recon", "DNS + headers + TLS in one pass"),
    ("11", "Settings", "Timeouts, threads, rate limit, report folder"),
    ("12", "About / legal", "Version and authorised-use notice"),
    ("0", "Exit", ""),
]


def interactive_menu(cfg) -> int:
    ui.banner()
    if not legal_gate(interactive=True):
        return 1
    while True:
        print()
        ui.section("Main menu")
        for key, label, desc in MENU_ITEMS:
            marker = ui.paint(f"[{key:>2}]", "cyan", bold=True)
            text = ui.paint(label.ljust(24), "white")
            note = ui.paint(desc, "gray", dim=True) if desc else ""
            print(f"  {marker} {text} {note}")
        print()
        try:
            choice = input(ui.paint("  ruk ❯ ", "magenta", bold=True)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            ui.info("bye — stay legal.")
            return 0
        if choice in ("0", "q", "quit", "exit"):
            ui.info("bye — stay legal.")
            return 0
        try:
            _dispatch_menu(choice, cfg)
        except KeyboardInterrupt:
            print()
            ui.warn("interrupted")
        except Exception as exc:  # noqa: BLE001 - never crash the menu
            ui.error(f"{exc.__class__.__name__}: {exc}")


def _dispatch_menu(choice: str, cfg) -> None:
    if choice == "1":
        _menu_scan(cfg)
    elif choice == "2":
        target = ui.prompt("domain or IP")
        if target:
            cmd_dns(_ns(target=target), cfg)
    elif choice == "3":
        target = ui.prompt("domain or IP")
        if target:
            cmd_whois(_ns(target=target), cfg)
    elif choice == "4":
        target = ui.prompt("IP, domain or blank for your own IP")
        cmd_ip(_ns(target=target or None, me=not target), cfg)
    elif choice == "5":
        target = ui.prompt("URL or host", default="example.com")
        if target:
            cmd_web(_ns(target=target), cfg)
    elif choice == "6":
        target = ui.prompt("host[:port]", default="example.com")
        if target:
            cmd_ssl(_ns(target=target), cfg)
    elif choice == "7":
        target = ui.prompt("domain")
        if target:
            cmd_subdomains(_ns(target=target, no_crtsh=False), cfg)
    elif choice == "8":
        target = ui.prompt("base URL", default="https://example.com")
        if target:
            cmd_dirscan(_ns(target=target), cfg)
    elif choice == "9":
        cmd_sysinfo(_ns(), cfg)
    elif choice == "10":
        target = ui.prompt("domain or URL")
        if target:
            _quick_recon(target, cfg)
    elif choice == "11":
        _menu_settings(cfg)
    elif choice == "12":
        ui.header("About", "ℹ")
        ui.kv_table({"name": APP_NAME, "version": VERSION,
                     "license": "MIT (see LICENSE)",
                     "config": cfgmod.CONFIG_FILE,
                     "reports": cfg.get("report_dir")})
        print()
        for line in LEGAL_NOTICE.splitlines():
            print("  " + ui.paint(line, "yellow"))
    else:
        ui.warn("unknown option")


def _menu_scan(cfg) -> None:
    target = ui.prompt("target host or IP")
    if not target:
        return
    preset = ui.prompt("ports (top / all / 22,80,100-200)", default="top")
    threads = int(ui.prompt("threads", default=str(cfg.get("threads", 60))) or 60)
    banners = ui.confirm("grab service banners?", default=False)
    save = ui.confirm("save a JSON report?", default=False)
    args = _ns(target=target, port=preset, threads=threads, banners=banners,
               timeout=cfg.get("timeout"), rate=cfg.get("rate"),
               out=("output/scan.json" if save else None))
    cmd_scan(args, cfg)


def _menu_settings(cfg) -> None:
    ui.header("Settings", "⚙")
    ui.kv_table(cfg, title=cfgmod.CONFIG_FILE)
    key = ui.prompt("setting to change (blank = cancel)")
    if not key:
        return
    current = cfg.get(key)
    value = ui.prompt(f"new value for {key}", default=str(current))
    if value:
        cfg = set_value(key, _coerce(value))
        ui.success(f"{key} = {cfg.get(key)}")


def _quick_recon(target: str, cfg) -> None:
    ui.header(f"Quick recon · {target}", "⚡")
    host = normalize_target(target)

    ui.info("1/4 DNS")
    try:
        args = _ns(target=host)
        cmd_dns(args, cfg)
    except Exception as exc:  # noqa: BLE001
        ui.warn(f"dns failed: {exc}")

    ui.info("2/4 common ports")
    try:
        args = _ns(target=host, port="22,80,443,8080,8443", threads=40)
        cmd_scan(args, cfg)
    except Exception as exc:  # noqa: BLE001
        ui.warn(f"scan failed: {exc}")

    ui.info("3/4 HTTP headers")
    try:
        args = _ns(target=target)
        cmd_web(args, cfg)
    except Exception as exc:  # noqa: BLE001
        ui.warn(f"web audit failed: {exc}")

    ui.info("4/4 TLS certificate")
    try:
        args = _ns(target=host)
        cmd_ssl(args, cfg)
    except Exception as exc:  # noqa: BLE001
        ui.warn(f"tls check failed: {exc}")


def _ns(**kwargs):
    """Build a simple namespace with defaults for menu-driven calls."""
    defaults = {
        "target": None, "port": None, "as_json": False, "out": None, "format": None,
        "quiet": False, "timeout": None, "threads": None, "rate": None,
        "banners": False, "wordlist": None, "codes": None, "no_crtsh": False,
        "record": None, "server": None, "me": False, "headers_only": False,
        "no_redirect": False, "insecure": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ruk_hacker",
        description=f"{APP_NAME} v{VERSION} — Termux security toolkit "
                    "(authorised testing only)",
        epilog="Run 'ruk_hacker' with no arguments for the interactive menu.",
    )
    parser.add_argument("-v", "--version", action="version",
                        version=f"{APP_NAME} {VERSION}")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--accept-terms", action="store_true",
                        help="accept the authorised-use notice for this run")

    subs = parser.add_subparsers(dest="command")

    p_scan = subs.add_parser("scan", help="TCP port scan")
    p_scan.add_argument("target", help="hostname or IP")
    p_scan.add_argument("-p", "--port", default="top",
                        help="ports: top | all | 22,80 | 1-1024")
    p_scan.add_argument("-b", "--banners", action="store_true", help="grab service banners")
    _common_options(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_ports = subs.add_parser("ports", help="quick top-ports scan (alias of scan)")
    p_ports.add_argument("target")
    p_ports.add_argument("-p", "--port", default="top")
    p_ports.add_argument("-b", "--banners", action="store_true")
    _common_options(p_ports)
    p_ports.set_defaults(func=cmd_ports)

    p_dns = subs.add_parser("dns", help="DNS records / reverse lookup")
    p_dns.add_argument("target", help="domain or IP")
    p_dns.add_argument("--record", help="specific record type (A, MX, TXT, ...)")
    p_dns.add_argument("--server", help="custom resolver IP")
    _common_options(p_dns)
    p_dns.set_defaults(func=cmd_dns)

    p_whois = subs.add_parser("whois", help="WHOIS lookup")
    p_whois.add_argument("target", help="domain or IP")
    _common_options(p_whois)
    p_whois.set_defaults(func=cmd_whois)

    p_ip = subs.add_parser("ip", help="IP geolocation and ASN")
    p_ip.add_argument("target", nargs="?", help="IP or domain")
    p_ip.add_argument("--me", action="store_true", help="show your own public IP")
    _common_options(p_ip)
    p_ip.set_defaults(func=cmd_ip)

    p_web = subs.add_parser("web", help="HTTP header and security audit")
    p_web.add_argument("target", help="URL or host")
    p_web.add_argument("--headers-only", action="store_true", help="dump all raw headers")
    p_web.add_argument("--no-redirect", action="store_true", help="do not follow redirects")
    p_web.add_argument("-k", "--insecure", action="store_true",
                       help="ignore TLS certificate errors (audit only)")
    _common_options(p_web)
    p_web.set_defaults(func=cmd_web)

    p_ssl = subs.add_parser("ssl", help="TLS certificate inspection")
    p_ssl.add_argument("target", help="host[:port] or https URL")
    _common_options(p_ssl)
    p_ssl.set_defaults(func=cmd_ssl)

    p_sub = subs.add_parser("subdomains", help="subdomain enumeration")
    p_sub.add_argument("target", help="root domain")
    p_sub.add_argument("-w", "--wordlist", help="custom wordlist path")
    p_sub.add_argument("--no-crtsh", action="store_true", help="skip crt.sh lookup")
    _common_options(p_sub)
    p_sub.set_defaults(func=cmd_subdomains)

    p_dir = subs.add_parser("dirscan", help="directory / path discovery")
    p_dir.add_argument("target", help="base URL")
    p_dir.add_argument("-w", "--wordlist", help="custom wordlist path")
    p_dir.add_argument("--codes", help="status codes to report (default: 200,204,301,...)")
    _common_options(p_dir)
    p_dir.set_defaults(func=cmd_dirscan)

    p_sys = subs.add_parser("sysinfo", help="local system information")
    p_sys.add_argument("--json", dest="as_json", action="store_true")
    p_sys.add_argument("--out")
    p_sys.add_argument("--format", choices=["json", "html", "txt", "all"])
    p_sys.add_argument("--quiet", action="store_true")
    p_sys.add_argument("--threads", type=int, default=None)
    p_sys.add_argument("--timeout", type=float, default=None)
    p_sys.add_argument("--rate", type=float, default=None)
    p_sys.set_defaults(func=cmd_sysinfo)

    p_rep = subs.add_parser("report", help="rebuild a report from saved JSON")
    p_rep.add_argument("input", help="JSON report from a previous run")
    p_rep.add_argument("--format", choices=["json", "html", "txt", "all"], default="html")
    p_rep.add_argument("--out", help="output path")
    p_rep.add_argument("--json", dest="as_json", action="store_true")
    p_rep.add_argument("--quiet", action="store_true")
    p_rep.add_argument("--threads", type=int, default=None)
    p_rep.add_argument("--timeout", type=float, default=None)
    p_rep.add_argument("--rate", type=float, default=None)
    p_rep.set_defaults(func=cmd_report)

    p_upd = subs.add_parser("update", help="check for a newer release")
    p_upd.add_argument("--apply", action="store_true", help="run the updater (git pull)")
    p_upd.add_argument("--json", dest="as_json", action="store_true")
    p_upd.add_argument("--quiet", action="store_true")
    p_upd.add_argument("--threads", type=int, default=None)
    p_upd.add_argument("--timeout", type=float, default=None)
    p_upd.add_argument("--rate", type=float, default=None)
    p_upd.set_defaults(func=cmd_update)

    p_ver = subs.add_parser("version", help="print the version")
    p_ver.add_argument("--json", dest="as_json", action="store_true")
    p_ver.add_argument("--quiet", action="store_true")
    p_ver.add_argument("--threads", type=int, default=None)
    p_ver.add_argument("--timeout", type=float, default=None)
    p_ver.add_argument("--rate", type=float, default=None)
    p_ver.set_defaults(func=cmd_version)

    p_cfg = subs.add_parser("config", help="view or change settings")
    p_cfg.add_argument("--set", metavar="KEY=VALUE", help="set a setting")
    p_cfg.add_argument("--unset", metavar="KEY", help="reset a setting to default")
    p_cfg.add_argument("--json", dest="as_json", action="store_true")
    p_cfg.add_argument("--quiet", action="store_true")
    p_cfg.add_argument("--threads", type=int, default=None)
    p_cfg.add_argument("--timeout", type=float, default=None)
    p_cfg.add_argument("--rate", type=float, default=None)
    p_cfg.set_defaults(func=cmd_config)

    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cfg = load_config()
    ui.set_color(ui.supports_color() and cfg.get("color", True))

    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "no_color", False):
        ui.set_color(False)

    if not getattr(args, "command", None):
        try:
            return interactive_menu(cfg)
        except KeyboardInterrupt:
            print()
            return 130

    if args.command in ("version", "config"):
        return args.func(args, cfg)

    accepted = legal_gate(interactive=bool(sys.stdin and sys.stdin.isatty()),
                          force_accept=getattr(args, "accept_terms", False))
    if not accepted:
        message = (
            "Authorised-use notice not accepted. Run 'ruk_hacker' once "
            "interactively, pass --accept-terms, or set RUK_ACCEPT_TERMS=1."
        )
        if getattr(args, "as_json", False):
            print(json.dumps({"module": args.command, "ok": False,
                              "error": "terms_not_accepted", "message": message},
                             indent=2))
        else:
            ui.error("Authorised-use notice not accepted.")
            ui.info("Accept it interactively by running 'ruk_hacker', or add --accept-terms")
            ui.info("(or export RUK_ACCEPT_TERMS=1) for scripted use.")
        return 3

    if not args.as_json and not getattr(args, "quiet", False):
        ui.banner()

    try:
        return args.func(args, cfg)
    except ValueError as exc:
        ui.error(str(exc))
        return 2
    except KeyboardInterrupt:
        print()
        ui.warn("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level guard
        ui.error(f"{exc.__class__.__name__}: {exc}")
        return 1
