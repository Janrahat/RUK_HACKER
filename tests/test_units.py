"""Unit tests — pure logic, no outbound network access."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ruk_hacker import dnsclient, ui, utils
from ruk_hacker import report, webaudit, whois_lookup
from ruk_hacker.dirscan import load_wordlist as load_paths
from ruk_hacker.portscan import summarize_risk
from ruk_hacker.subdomains import load_wordlist as load_subs


class TestPortParsing(unittest.TestCase):
    def test_single_ports(self):
        self.assertEqual(utils.parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(utils.parse_ports("20-24"), [20, 21, 22, 23, 24])

    def test_reversed_range_is_normalised(self):
        self.assertEqual(utils.parse_ports("24-20"), [20, 21, 22, 23, 24])

    def test_top_and_all(self):
        self.assertIn(443, utils.parse_ports("top"))
        all_ports = utils.parse_ports("all")
        self.assertEqual(len(all_ports), 65536)
        self.assertEqual(all_ports[0], 1)

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            utils.parse_ports("not-a-port")

    def test_deduplication_and_sorting(self):
        self.assertEqual(utils.parse_ports("80,22,80,22"), [22, 80])

    def test_service_names(self):
        self.assertEqual(utils.service_name(22), "ssh")
        self.assertEqual(utils.service_name(443), "https")
        self.assertEqual(utils.service_name(65000), "unknown")


class TestTargetValidation(unittest.TestCase):
    def test_is_ip(self):
        self.assertTrue(utils.is_ip("8.8.8.8"))
        self.assertTrue(utils.is_ip("2001:4860:4860::8888"))
        self.assertFalse(utils.is_ip("example.com"))
        self.assertFalse(utils.is_ip("999.1.1.1"))

    def test_is_domain(self):
        self.assertTrue(utils.is_domain("example.com"))
        self.assertTrue(utils.is_domain("sub.example.co.uk"))
        self.assertFalse(utils.is_domain("-bad.com"))
        self.assertFalse(utils.is_domain("bad..com"))
        self.assertFalse(utils.is_domain(""))

    def test_normalize_target(self):
        self.assertEqual(utils.normalize_target("https://example.com/path?q=1"), "example.com")
        self.assertEqual(utils.normalize_target("example.com:8080"), "example.com")
        self.assertEqual(utils.normalize_target("user:pass@example.com/x"), "example.com")
        self.assertEqual(utils.normalize_target("  example.com  "), "example.com")

    def test_normalize_target_rejects_bad(self):
        with self.assertRaises(ValueError):
            utils.normalize_target("bad domain with spaces")
        with self.assertRaises(ValueError):
            utils.normalize_target("")

    def test_normalize_url(self):
        self.assertEqual(utils.normalize_url("example.com"), "https://example.com")
        self.assertEqual(utils.normalize_url("http://example.com/a"), "http://example.com/a")
        with self.assertRaises(ValueError):
            utils.normalize_url("ftp://example.com")


class TestDNSWireFormat(unittest.TestCase):
    def test_encode_simple_name(self):
        encoded = dnsclient._encode_name("example.com")
        self.assertEqual(encoded, b"\x07example\x03com\x00")

    def test_encode_root(self):
        self.assertEqual(dnsclient._encode_name(""), b"\x00")

    def test_encode_label_too_long(self):
        with self.assertRaises(dnsclient.DNSError):
            dnsclient._encode_name("a" * 70 + ".com")

    def test_query_header(self):
        packet = dnsclient._build_query("example.com", "A", 0x1234)
        self.assertEqual(len(packet), 12 + 13 + 4)
        self.assertEqual(packet[:2], b"\x12\x34")
        self.assertEqual(packet[2:4], b"\x01\x00")  # recursion desired

    def test_unsupported_record_type(self):
        with self.assertRaises(dnsclient.DNSError):
            dnsclient._build_query("example.com", "BOGUS", 1)

    def test_parse_response_roundtrip(self):
        # Build a synthetic response with one A record for example.com
        import struct
        qid = 0x4242
        question = dnsclient._encode_name("example.com") + struct.pack(">HH", 1, 1)
        header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4)
                  + bytes([93, 184, 216, 34]))
        parsed = dnsclient._parse_response(header + question + answer, qid)
        self.assertEqual(parsed["status"], "NOERROR")
        self.assertEqual(parsed["answers"][0]["type"], "A")
        self.assertEqual(parsed["answers"][0]["value"], "93.184.216.34")
        self.assertEqual(parsed["answers"][0]["ttl"], 300)

    def test_parse_response_nxdomain(self):
        import struct
        qid = 1
        question = dnsclient._encode_name("nope.example") + struct.pack(">HH", 1, 1)
        header = struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0)
        parsed = dnsclient._parse_response(header + question, qid)
        self.assertEqual(parsed["status"], "NXDOMAIN")
        self.assertEqual(parsed["answers"], [])

    def test_transaction_mismatch_raises(self):
        import struct
        header = struct.pack(">HHHHHH", 1, 0, 0, 0, 0, 0)
        with self.assertRaises(dnsclient.DNSError):
            dnsclient._parse_response(header, 2)

    def test_mx_decode(self):
        import struct
        qid = 7
        question = dnsclient._encode_name("example.com") + struct.pack(">HH", 15, 1)
        rdata = struct.pack(">H", 10) + dnsclient._encode_name("mail.example.com")
        header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 60, len(rdata)) + rdata
        parsed = dnsclient._parse_response(header + question + answer, qid)
        self.assertEqual(parsed["answers"][0]["value"]["preference"], 10)
        self.assertEqual(parsed["answers"][0]["value"]["exchange"], "mail.example.com")

    def test_txt_decode(self):
        import struct
        qid = 9
        question = dnsclient._encode_name("example.com") + struct.pack(">HH", 16, 1)
        payload = b"v=spf1 -all"
        rdata = bytes([len(payload)]) + payload
        header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(rdata)) + rdata
        parsed = dnsclient._parse_response(header + question + answer, qid)
        self.assertEqual(parsed["answers"][0]["value"], "v=spf1 -all")


class TestRateLimiter(unittest.TestCase):
    def test_no_limit_is_fast(self):
        import time
        limiter = utils.RateLimiter(0)
        started = time.monotonic()
        for _ in range(200):
            limiter.wait()
        self.assertLess(time.monotonic() - started, 0.5)

    def test_interval_enforced(self):
        import time
        limiter = utils.RateLimiter(50)  # 20 ms interval
        started = time.monotonic()
        for _ in range(3):
            limiter.wait()
        self.assertGreaterEqual(time.monotonic() - started, 0.03)


class TestThreadedExecution(unittest.TestCase):
    def test_order_and_errors(self):
        def worker(value):
            if value == 3:
                raise ValueError("boom")
            return value * 2
        outcomes = utils.run_threaded(worker, [1, 2, 3, 4], threads=4)
        self.assertEqual([item for item, _, _ in outcomes], [1, 2, 3, 4])
        self.assertEqual(outcomes[0][1], 2)
        self.assertIsNotNone(outcomes[2][2])
        self.assertIsNone(outcomes[3][2])

    def test_empty(self):
        self.assertEqual(utils.run_threaded(lambda x: x, [], threads=4), [])


class TestWebAuditHelpers(unittest.TestCase):
    def test_grade_scale(self):
        self.assertEqual(webaudit._grade(13, 13), "A+")
        self.assertEqual(webaudit._grade(0, 13), "F")
        self.assertEqual(webaudit._grade(8, 13), "C")
        self.assertEqual(webaudit._grade(0, 0), "?")

    def test_cookie_analysis(self):
        weak = webaudit._analyse_cookie("sid=abc")
        self.assertIn("missing Secure", weak["issues"])
        strong = webaudit._analyse_cookie("sid=abc; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(strong["issues"], [])

    def test_technology_hints(self):
        hints = webaudit.technology_hints({
            "headers": {"server": "nginx/1.24", "x-powered-by": "PHP/8.2",
                        "x-nextjs-cache": "HIT"}
        })
        self.assertIn("Nginx", hints)
        self.assertIn("PHP", hints)
        self.assertIn("Next.js", hints)


class TestPortRisk(unittest.TestCase):
    def test_risky_services_flagged(self):
        findings = summarize_risk([
            {"port": 22}, {"port": 3389}, {"port": 6379}, {"port": 8080},
        ])
        ports = [item["port"] for item in findings]
        self.assertIn(3389, ports)
        self.assertIn(6379, ports)
        self.assertNotIn(8080, ports)
        self.assertEqual(findings[0]["severity"], "critical")

    def test_no_risk(self):
        self.assertEqual(summarize_risk([{"port": 80}]), [])


class TestWhosParsing(unittest.TestCase):
    def test_parse_fields(self):
        text = "\n".join([
            "% comment line",
            "Domain Name: EXAMPLE.COM",
            "Registrar: Example Registrar, Inc.",
            "Creation Date: 1995-08-14T04:00:00Z",
            "Registry Expiry Date: 2027-08-13T04:00:00Z",
            "Name Server: A.IANA-SERVERS.NET",
            "Name Server: B.IANA-SERVERS.NET",
            "Domain Status: clientDeleteProhibited",
            "Domain Status: clientTransferProhibited",
        ])
        fields = whois_lookup._parse_fields(text)
        self.assertEqual(fields["domain"], "EXAMPLE.COM")
        self.assertEqual(fields["registrar"], "Example Registrar, Inc.")
        self.assertIn("a.iana-servers.net", fields["nameservers"])
        self.assertEqual(len(fields["nameservers"]), 2)
        self.assertEqual(len(fields["status"]), 2)

    def test_days_until(self):
        self.assertIsNotNone(whois_lookup.days_until("2027-08-13T04:00:00Z"))
        self.assertIsNone(whois_lookup.days_until("not a date"))

    def test_invalid_domain(self):
        result = whois_lookup.whois_domain("bad domain")
        self.assertFalse(result["ok"])
        self.assertIn("invalid", result["error"])


class TestUiHelpers(unittest.TestCase):
    def test_strip_ansi(self):
        text = ui.paint("hello", "red", bold=True)
        self.assertEqual(ui.strip_ansi(text), "hello")

    def test_visible_len(self):
        self.assertEqual(ui.visible_len(ui.paint("abc", "green")), 3)

    def test_color_toggle(self):
        ui.set_color(True)
        self.assertIn("\033[", ui.paint("x", "red"))
        ui.set_color(False)
        self.assertEqual(ui.paint("x", "red"), "x")
        ui.set_color(True)


class TestWordlists(unittest.TestCase):
    def test_bundled_lists_load(self):
        self.assertGreater(len(load_paths()), 40)
        self.assertGreater(len(load_subs()), 80)
        self.assertIn("admin", load_paths())

    def test_comments_are_skipped(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write("# comment\nadmin\n\nrobots.txt\n")
            path = fh.name
        try:
            words = utils.read_wordlist(path)
            self.assertEqual(words, ["admin", "robots.txt"])
        finally:
            os.unlink(path)

    def test_missing_file_returns_default(self):
        self.assertEqual(utils.read_wordlist("/nonexistent/list.txt", default=["a"]), ["a"])


class TestReports(unittest.TestCase):
    SAMPLE = {
        "target": "example.com",
        "ip": "93.184.216.34",
        "ports_scanned": 3,
        "open": [{"port": 443, "service": "https", "banner": "", "latency_ms": 12.5}],
        "risk": [],
        "duration": 0.4,
    }

    def test_html_contains_data(self):
        html = report.build_html("scan", self.SAMPLE)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("example.com", html)
        self.assertIn("93.184.216.34", html)
        self.assertIn("Legal notice", html)

    def test_html_escapes_markup(self):
        html = report.build_html("scan", {"target": "<script>alert(1)</script>", "open": []})
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_text_report(self):
        text = report.build_text("scan", self.SAMPLE)
        self.assertIn("SCAN report", text)
        self.assertIn("example.com", text)

    def test_save_all_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = report.save_report("scan", self.SAMPLE, fmt="all",
                                        path=os.path.join(tmp, "out"))
            self.assertTrue(result["ok"])
            written = {os.path.basename(item["path"]) for item in result["written"]}
            self.assertEqual(written, {"out.json", "out.html", "out.txt"})
            with open(os.path.join(tmp, "out.json"), "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["module"], "scan")
            self.assertEqual(payload["tool"], "RUK_HACKER")

    def test_bad_format_rejected(self):
        result = report.save_report("scan", self.SAMPLE, fmt="pdf")
        self.assertFalse(result["ok"])

    def test_every_module_renders(self):
        samples = {
            "dns": {"domain": "example.com", "records": {"A": [{"value": "1.2.3.4", "ttl": 60}]}},
            "whois": {"query": "example.com", "fields": {"registrar": "X"}},
            "ip": {"query": "1.2.3.4", "ip": "1.2.3.4", "country": "US"},
            "web": {"url": "https://example.com", "status": 200, "security": [],
                    "missing": [], "cookies": []},
            "ssl": {"host": "example.com", "port": 443, "ok": True, "subject": {}, "issuer": {}},
            "subdomains": {"domain": "example.com", "found": [], "total_checked": 5},
            "dirscan": {"url": "https://example.com", "tested": 5, "found": [],
                        "baseline": {"status": 404}},
            "sysinfo": {"platform": "Linux", "cpu": {"cores": 8}},
        }
        for module, data in samples.items():
            with self.subTest(module=module):
                html = report.build_html(module, data)
                self.assertIn("<html", html)
                self.assertIn(module.upper() if module != "dirscan" else "PATH", html.upper())


class TestFormattingHelpers(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(utils.human_bytes(512), "512 B")
        self.assertEqual(utils.human_bytes(2048), "2.0 KB")

    def test_format_duration(self):
        self.assertEqual(utils.format_duration(0.25), "250 ms")
        self.assertIn("s", utils.format_duration(3.5))
        self.assertIn("m", utils.format_duration(125))

    def test_sanitize_filename(self):
        self.assertEqual(utils.sanitize_filename("a b/c?.txt"), "a_b_c_.txt")
        self.assertEqual(utils.sanitize_filename(""), "report")


if __name__ == "__main__":
    unittest.main(verbosity=2)
