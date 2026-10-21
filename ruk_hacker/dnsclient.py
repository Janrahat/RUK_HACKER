"""A tiny pure-stdlib DNS client (UDP with TCP fallback).

Supports A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR queries without
requiring dnspython. If dnspython happens to be installed, callers may use it,
but nothing here depends on it.
"""

from __future__ import annotations

import random
import socket
import struct
import time

TYPE_CODES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257, "ANY": 255,
}
CODE_TYPES = {v: k for k, v in TYPE_CODES.items()}

RCODE_TEXT = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

DEFAULT_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class DNSError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    out = b""
    if not name:
        return b"\x00"
    for label in name.split("."):
        encoded = label.encode("idna") if any(ord(ch) > 127 for ch in label) else label.encode("ascii")
        if len(encoded) > 63:
            raise DNSError(f"label too long: {label}")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _build_query(name: str, qtype: str, qid: int, recursion: bool = True) -> bytes:
    if qtype.upper() not in TYPE_CODES:
        raise DNSError(f"unsupported record type: {qtype}")
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", TYPE_CODES[qtype.upper()], 1)
    return header + question


def _read_name(data: bytes, offset: int, depth: int = 0):
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    if depth > 10:
        raise DNSError("compression loop detected")
    labels = []
    jumped = False
    original_offset = offset
    while True:
        if offset >= len(data):
            raise DNSError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            sub_name, _ = _read_name(data, pointer, depth + 1)
            if sub_name:
                labels.append(sub_name)
            offset = original_offset if jumped else offset + 2
            if jumped:
                break
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (original_offset if jumped else offset)


def _parse_response(data: bytes, qid: int) -> dict:
    if len(data) < 12:
        raise DNSError("short response")
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        raise DNSError("transaction id mismatch")
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    result = {
        "rcode": rcode,
        "status": RCODE_TEXT.get(rcode, str(rcode)),
        "answers": [],
        "authority": [],
        "additional": [],
        "truncated": truncated,
        "flags": {
            "authoritative": bool(flags & 0x0400),
            "recursion_available": bool(flags & 0x0080),
            "truncated": truncated,
        },
    }
    offset = 12
    for _ in range(qdcount):
        _qname, offset = _read_name(data, offset)
        offset += 4

    def _read_section(count):
        nonlocal offset
        records = []
        for _ in range(count):
            rname, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                raise DNSError("truncated resource record")
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata_start = offset
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            type_name = CODE_TYPES.get(rtype, f"TYPE{rtype}")
            value = _decode_rdata(type_name, data, rdata_start, rdlength, rdata)
            records.append({
                "name": rname,
                "type": type_name,
                "ttl": ttl,
                "value": value,
            })
        return records

    result["answers"] = _read_section(ancount)
    result["authority"] = _read_section(nscount)
    result["additional"] = _read_section(arcount)
    return result


def _decode_rdata(type_name: str, data: bytes, start: int, length: int, rdata: bytes):
    try:
        if type_name == "A":
            return socket.inet_ntop(socket.AF_INET, rdata)
        if type_name == "AAAA":
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if type_name in ("CNAME", "NS", "PTR"):
            name, _ = _read_name(data, start)
            return name
        if type_name == "MX":
            preference = struct.unpack(">H", rdata[:2])[0]
            name, _ = _read_name(data, start + 2)
            return {"preference": preference, "exchange": name}
        if type_name == "TXT":
            parts = []
            pos = 0
            while pos < len(rdata):
                size = rdata[pos]
                pos += 1
                parts.append(rdata[pos:pos + size].decode("utf-8", "replace"))
                pos += size
            return "".join(parts)
        if type_name == "SOA":
            mname, pos = _read_name(data, start)
            rname, pos = _read_name(data, pos)
            serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[pos:pos + 20])
            return {
                "mname": mname, "rname": rname, "serial": serial, "refresh": refresh,
                "retry": retry, "expire": expire, "minimum": minimum,
            }
        if type_name == "SRV":
            priority, weight, port = struct.unpack(">HHH", rdata[:6])
            target, _ = _read_name(data, start + 6)
            return {"priority": priority, "weight": weight, "port": port, "target": target}
        if type_name == "CAA":
            flags = rdata[0]
            tag_len = rdata[1]
            tag = rdata[2:2 + tag_len].decode("ascii", "replace")
            value = rdata[2 + tag_len:].decode("utf-8", "replace")
            return {"flags": flags, "tag": tag, "value": value}
    except (struct.error, IndexError, OSError):
        return rdata.hex()
    return rdata.hex()


def query(name: str, qtype: str = "A", server: str = None, timeout: float = 5.0,
          tcp: bool = False, retries: int = 1) -> dict:
    """Send a single DNS query and return the parsed response."""
    server = server or DEFAULT_SERVERS[0]
    last_error = None
    for attempt in range(max(1, retries)):
        qid = random.randint(0, 0xFFFF)
        try:
            packet = _build_query(name, qtype, qid)
        except DNSError:
            raise
        try:
            if tcp:
                data = _query_tcp(packet, server, timeout)
            else:
                data = _query_udp(packet, server, timeout)
            parsed = _parse_response(data, qid)
            if parsed.get("truncated") and not tcp:
                return query(name, qtype, server=server, timeout=timeout, tcp=True, retries=retries)
            return parsed
        except (socket.timeout, OSError, DNSError) as exc:
            last_error = exc
            if attempt + 1 < max(1, retries):
                time.sleep(0.3)
    raise DNSError(str(last_error) if last_error else "dns query failed")


def _query_udp(packet: bytes, server: str, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def _query_tcp(packet: bytes, server: str, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 53))
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        header = _recv_exact(sock, 2)
        length = struct.unpack(">H", header)[0]
        return _recv_exact(sock, length)
    finally:
        sock.close()


def _recv_exact(sock, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise DNSError("connection closed early")
        buf += chunk
    return buf


def resolve(name: str, qtype: str = "A", server: str = None, timeout: float = 5.0) -> list:
    """Return the list of answer values for name/qtype."""
    response = query(name, qtype, server=server, timeout=timeout)
    return [record["value"] for record in response["answers"]
            if record["type"] in (qtype.upper(), "CNAME")]


def resolve_a(name: str, server: str = None, timeout: float = 5.0) -> list:
    try:
        return [value for value in resolve(name, "A", server=server, timeout=timeout)
                if isinstance(value, str) and value.count(".") == 3]
    except DNSError:
        return []


def resolve_aaaa(name: str, server: str = None, timeout: float = 5.0) -> list:
    try:
        return [value for value in resolve(name, "AAAA", server=server, timeout=timeout)
                if isinstance(value, str) and ":" in value]
    except DNSError:
        return []


def reverse(ip: str, server: str = None, timeout: float = 5.0) -> list:
    """PTR lookup for an IP address."""
    try:
        import ipaddress
        address = ipaddress.ip_address(ip)
        if address.version == 4:
            arpa = ".".join(reversed(str(address).split("."))) + ".in-addr.arpa"
        else:
            nibbles = address.exploded.replace(":", "")
            arpa = ".".join(reversed(list(nibbles))) + ".ip6.arpa"
    except ValueError:
        raise DNSError(f"invalid IP: {ip}")
    response = query(arpa, "PTR", server=server, timeout=timeout)
    return [record["value"] for record in response["answers"] if record["type"] == "PTR"]


def trace(name: str, timeout: float = 3.0, max_hops: int = 25) -> list:
    """Follow CNAME chains for a name (best-effort, no recursion beyond 20)."""
    chain = []
    current = name
    seen = set()
    for _ in range(max_hops):
        if current in seen:
            break
        seen.add(current)
        try:
            response = query(current, "CNAME", timeout=timeout)
        except DNSError:
            break
        target = None
        for record in response["answers"]:
            if record["type"] == "CNAME":
                target = record["value"]
                break
        if not target:
            break
        chain.append({"from": current, "to": target})
        current = target
    return chain
