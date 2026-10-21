"""Low-level network primitives: TCP connect, banner grab, HTTP requests."""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import tempfile
import time
from urllib.parse import urlparse

from .config import USER_AGENT


def tcp_connect(host: str, port: int, timeout: float = 3.0):
    """Attempt a TCP connection. Returns elapsed seconds or None."""
    started = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return time.monotonic() - started
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def grab_banner(host: str, port: int, timeout: float = 3.0, probe: bool = True) -> str:
    """Read a service banner. Optionally send a light HTTP probe first."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if probe and port in (80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000):
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\r\n"
            sock.sendall(request.encode("ascii", "ignore"))
        data = sock.recv(1024)
        text = data.decode("utf-8", "replace")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return lines[0][:120] if lines else ""
    except (socket.timeout, OSError):
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def http_request(url: str, method: str = "GET", timeout: float = 8.0,
                 headers: dict = None, allow_redirects: bool = True, max_redirects: int = 5,
                 insecure: bool = False):
    """Minimal HTTP client built on http.client.

    Returns a dict: status, reason, headers (list of tuples), body (bytes),
    url (final), redirects (list), elapsed, error.
    """
    result = {
        "url": url,
        "status": None,
        "reason": "",
        "headers": [],
        "body": b"",
        "redirects": [],
        "elapsed": 0.0,
        "error": None,
    }
    started = time.monotonic()
    current = url
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    if headers:
        request_headers.update(headers)

    for _hop in range(max_redirects + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            result["error"] = f"invalid URL: {current}"
            break
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        context = None
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            if insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

        conn = None
        try:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request(method, path, headers=request_headers)
            response = conn.getresponse()
            body = response.read() if method != "HEAD" else b""
            result["status"] = response.status
            result["reason"] = response.reason or ""
            result["headers"] = response.getheaders()
            result["body"] = body
            result["url"] = current

            location = ""
            for key, value in response.getheaders():
                if key.lower() == "location":
                    location = value
                    break
            if (allow_redirects and location and response.status in (301, 302, 303, 307, 308)
                    and len(result["redirects"]) < max_redirects):
                result["redirects"].append(current)
                if location.startswith("http://") or location.startswith("https://"):
                    current = location
                elif location.startswith("/"):
                    current = f"{parsed.scheme}://{parsed.netloc}{location}"
                else:
                    current = f"{parsed.scheme}://{parsed.netloc}/{location}"
                continue
            break
        except ssl.SSLError as exc:
            result["error"] = f"SSL error: {exc}"
            break
        except socket.timeout:
            result["error"] = "timeout"
            break
        except (OSError, http.client.HTTPException) as exc:
            result["error"] = str(exc) or exc.__class__.__name__
            break
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    result["elapsed"] = time.monotonic() - started
    return result


def decode_der_certificate(der: bytes) -> dict:
    """Decode a DER certificate into the same dict shape as getpeercert().

    Uses the stdlib decoder (no cryptography dependency). Returns {} on failure.
    """
    if not der:
        return {}
    path = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if decoder is None:
            return {}
        return decoder(path) or {}
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def get_certificate(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Fetch the peer TLS certificate and its parsed metadata."""
    info = {"ok": False, "error": None, "der": None, "meta": {}}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = None
    tls = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        tls = context.wrap_socket(sock, server_hostname=host)
        der = tls.getpeercert(binary_form=True)
        info["der"] = der
        info["ok"] = True
        # getpeercert() returns {} in CERT_NONE mode, so decode the DER directly.
        info["meta"] = decode_der_certificate(der)
        if not info["meta"]:
            try:
                info["meta"] = tls.getpeercert() or {}
            except (ValueError, ssl.SSLError):
                info["meta"] = {}
        info["version"] = tls.version()
        info["cipher"] = tls.cipher()
    except ssl.SSLError as exc:
        info["error"] = f"SSL error: {exc}"
    except socket.timeout:
        info["error"] = "timeout"
    except OSError as exc:
        info["error"] = str(exc)
    finally:
        for handle in (tls, sock):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
    return info


def udp_probe(host: str, port: int, payload: bytes = b"\x00", timeout: float = 3.0):
    """Send a UDP datagram and wait for a reply. Returns reply bytes or None."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        data, _addr = sock.recvfrom(2048)
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def raw_socket_read(host: str, port: int, payload: bytes = b"", timeout: float = 4.0,
                    read_bytes: int = 65535) -> bytes:
    """Open a TCP socket, optionally send payload, read up to read_bytes."""
    sock = None
    chunks = []
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) >= read_bytes:
                break
        return b"".join(chunks)
    except (socket.timeout, OSError):
        return b"".join(chunks)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
