"""Smoke tests — spin up local servers and exercise the real network paths.

Nothing here touches the public internet: an HTTP server and a TLS server are
started on localhost and scanned by the tool itself.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ruk_hacker import report, ui
from ruk_hacker.dirscan import dirscan
from ruk_hacker.net import get_certificate, http_request, tcp_connect
from ruk_hacker.portscan import scan_host, summarize_risk
from ruk_hacker.webaudit import cert_info, header_audit, technology_hints
from ruk_hacker.utils import parse_ports

FIXTURE_PATHS = ["admin", "login", "robots.txt", "api", "backup.zip", ".env"]


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def end_headers(self):
        self.send_header("Server", "RukTestServer/1.0")
        self.send_header("X-Powered-By", "PHP/8.2.0")
        self.send_header("Set-Cookie", "sid=abc123; Path=/")
        super().end_headers()


class LocalHTTPServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docroot = tempfile.mkdtemp(prefix="ruk_smoke_")
        for name in FIXTURE_PATHS:
            if name == "api":
                continue  # 'api' is created as a directory below
            full = os.path.join(cls.docroot, name.replace("/", "_"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            if os.path.isdir(full):
                continue
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(f"<html><body>{name}</body></html>")
        # /api is a directory index
        os.makedirs(os.path.join(cls.docroot, "api"), exist_ok=True)
        with open(os.path.join(cls.docroot, "api", "index.html"), "w") as fh:
            fh.write("<h1>api</h1>")

        handler = lambda *a, **kw: _Handler(*a, directory=cls.docroot, **kw)  # noqa: E731
        cls.port = _free_port()
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", cls.port), handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        shutil.rmtree(cls.docroot, ignore_errors=True)


class TestTcpAndScan(LocalHTTPServerCase):
    def test_tcp_connect_open(self):
        self.assertIsNotNone(tcp_connect("127.0.0.1", self.port, timeout=2))

    def test_tcp_connect_closed(self):
        self.assertIsNone(tcp_connect("127.0.0.1", _free_port(), timeout=0.5))

    def test_scan_finds_listening_port(self):
        ports = [self.port, _free_port(), _free_port()]
        result = scan_host("127.0.0.1", ports, timeout=1.0, threads=6)
        self.assertIsNone(result["error"])
        self.assertEqual(result["ip"], "127.0.0.1")
        found = [entry["port"] for entry in result["open"]]
        self.assertIn(self.port, found)

    def test_scan_records_service_and_latency(self):
        result = scan_host("127.0.0.1", [self.port], timeout=1.0, threads=2,
                           banners=True)
        entry = result["open"][0]
        self.assertIn("service", entry)
        self.assertGreaterEqual(entry["latency_ms"], 0)

    def test_scan_unresolvable_host(self):
        result = scan_host("no-such-host.invalid", [80], timeout=1.0)
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["open"], [])

    def test_risk_flags_integration(self):
        result = scan_host("127.0.0.1", [self.port], timeout=1.0, threads=2)
        self.assertEqual(summarize_risk(result["open"]), [])


class TestHttpLayer(LocalHTTPServerCase):
    def test_http_request(self):
        response = http_request(f"{self.base}/robots.txt", timeout=4)
        self.assertIsNone(response["error"])
        self.assertEqual(response["status"], 200)
        self.assertIn(b"robots.txt", response["body"])

    def test_http_404(self):
        response = http_request(f"{self.base}/does-not-exist", timeout=4)
        self.assertEqual(response["status"], 404)

    def test_header_audit_detects_missing_headers(self):
        data = header_audit(self.base, timeout=4)
        self.assertIsNone(data["error"])
        self.assertEqual(data["status"], 200)
        self.assertIn("RukTestServer/1.0", data["server"])
        missing = {item["header"] for item in data["missing"]}
        self.assertIn("content-security-policy", missing)
        self.assertIn("strict-transport-security", missing)
        self.assertIn(data["grade"], ("F", "E", "D"))
        self.assertTrue(data["cookies"])
        self.assertIn("missing Secure", data["cookies"][0]["issues"])
        self.assertEqual(data["disclosure"].get("x-powered-by"), "PHP/8.2.0")

    def test_technology_hints_from_real_headers(self):
        data = header_audit(self.base, timeout=4)
        hints = technology_hints(data)
        self.assertIn("PHP", hints)


class TestDirScan(LocalHTTPServerCase):
    def test_finds_existing_paths(self):
        result = dirscan(self.base, wordlist=["admin", "login", "robots.txt",
                                              "nope-xyz", "api"],
                         threads=5, timeout=4)
        self.assertIsNone(result["error"])
        found = {item["path"] for item in result["found"]}
        self.assertIn("/admin", found)
        self.assertIn("/login", found)
        self.assertIn("/robots.txt", found)
        self.assertEqual(result["baseline"]["status"], 404)

    def test_soft_404_suppressed(self):
        # A server that answers 200 for everything must not produce findings.
        class CatchAll(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"same body"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        port = _free_port()
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), CatchAll)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = dirscan(f"http://127.0.0.1:{port}",
                             wordlist=["admin", "login", "api"], threads=3, timeout=3)
            self.assertEqual(result["found"], [], "soft-404 pages should be filtered")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_invalid_url(self):
        result = dirscan("ftp://bad", wordlist=["admin"])
        self.assertIsNotNone(result["error"])


class TestTls(LocalHTTPServerCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.certfile = os.path.join(cls.docroot, "cert.pem")
        cls.keyfile = os.path.join(cls.docroot, "key.pem")
        cls.tls_port = _free_port()
        cls.tls_server = None
        cls.tls_thread = None
        if shutil.which("openssl") is None:
            return
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", cls.keyfile, "-out", cls.certfile, "-days", "3",
                "-subj", "/CN=localhost/O=RUK Test",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ], check=True, capture_output=True, timeout=60)
        except (subprocess.SubprocessError, OSError):
            return
        handler = lambda *a, **kw: _Handler(*a, directory=cls.docroot, **kw)  # noqa: E731
        cls.tls_server = http.server.ThreadingHTTPServer(("127.0.0.1", cls.tls_port), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.certfile, cls.keyfile)
        cls.tls_server.socket = context.wrap_socket(cls.tls_server.socket, server_side=True)
        cls.tls_thread = threading.Thread(target=cls.tls_server.serve_forever, daemon=True)
        cls.tls_thread.start()

    @classmethod
    def tearDownClass(cls):
        if cls.tls_server is not None:
            cls.tls_server.shutdown()
            cls.tls_server.server_close()
            if cls.tls_thread:
                cls.tls_thread.join(timeout=5)
        super().tearDownClass()

    def setUp(self):
        if self.tls_server is None:
            self.skipTest("openssl not available — TLS smoke test skipped")

    def test_certificate_retrieved(self):
        raw = get_certificate("127.0.0.1", self.tls_port, timeout=6)
        self.assertTrue(raw["ok"], raw.get("error"))
        self.assertIsNotNone(raw["der"])
        self.assertIn(raw.get("version"), ("TLSv1.2", "TLSv1.3"))

    def test_cert_info_structure(self):
        info = cert_info("127.0.0.1", port=self.tls_port, timeout=6)
        self.assertTrue(info["ok"], info.get("error"))
        self.assertEqual(info["subject"].get("commonName"), "localhost")
        self.assertTrue(info["self_signed"])
        self.assertFalse(info["chain_trusted"])
        self.assertIn("127.0.0.1", info["san"])
        self.assertTrue(any("self-signed" in w for w in info["protocol_warnings"]))
        self.assertEqual(len(info["sha256"]), 64)

    def test_https_header_audit(self):
        data = header_audit(f"https://127.0.0.1:{self.tls_port}", timeout=6)
        # The self-signed certificate is rejected by the default trust store,
        # so the audit must report a clean SSL error rather than crash.
        self.assertTrue(data["error"] is not None or data["status"] == 200)

    def test_https_header_audit_insecure(self):
        data = header_audit(f"https://127.0.0.1:{self.tls_port}", timeout=6, insecure=True)
        self.assertIsNone(data["error"], data["error"])
        self.assertEqual(data["status"], 200)
        self.assertIn("RukTestServer/1.0", data["server"])


class TestCliEndToEnd(unittest.TestCase):
    """Drive the real CLI in a subprocess, exactly as a user would."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ruk_cli_")
        cls.env = dict(os.environ)
        cls.env["HOME"] = cls.tmp
        cls.env["NO_COLOR"] = "1"
        cls.env["RUK_ACCEPT_TERMS"] = "1"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, *args, timeout=90):
        return subprocess.run([sys.executable, os.path.join(ROOT, "ruk_hacker.py"), *args],
                              capture_output=True, text=True, timeout=timeout, env=self.env)

    def test_version(self):
        out = self._run("version")
        self.assertEqual(out.returncode, 0)
        self.assertIn("RUK_HACKER v", out.stdout)

    def test_help_lists_all_commands(self):
        out = self._run("--help")
        for command in ("scan", "ports", "dns", "whois", "web", "ssl", "ip",
                        "subdomains", "dirscan", "sysinfo", "report", "update"):
            self.assertIn(command, out.stdout)

    def test_sysinfo_json(self):
        out = self._run("sysinfo", "--json")
        self.assertEqual(out.returncode, 0, out.stderr)
        payload = json.loads(out.stdout)
        self.assertEqual(payload["module"], "sysinfo")
        self.assertIn("platform", payload["data"])

    def test_invalid_port_spec_is_reported(self):
        out = self._run("scan", "127.0.0.1", "-p", "not-a-port")
        self.assertEqual(out.returncode, 2)
        self.assertIn("invalid port", out.stderr + out.stdout)


class TestReportSmoke(unittest.TestCase):
    def test_end_to_end_report_files(self):
        data = {"target": "127.0.0.1", "ip": "127.0.0.1", "ports_scanned": 1,
                "open": [{"port": 80, "service": "http", "banner": "test", "latency_ms": 1.0}],
                "duration": 0.1}
        with tempfile.TemporaryDirectory() as tmp:
            result = report.save_report("scan", data, fmt="all",
                                        path=os.path.join(tmp, "smoke"))
            self.assertTrue(result["ok"])
            for item in result["written"]:
                self.assertTrue(os.path.isfile(item["path"]))
                self.assertGreater(item["bytes"], 100)
            html_path = [i["path"] for i in result["written"] if i["path"].endswith(".html")][0]
            with open(html_path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("Port Scan", content)
            self.assertIn("<table>", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
