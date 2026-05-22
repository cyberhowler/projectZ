"""
ProjectZ - DNS Compatibility Layer v2
Fast, no-hang DNS resolution.

Strategy:
  A/AAAA records  → socket.getaddrinfo() via thread executor (OS DNS, instant)
  MX/TXT/NS/SOA   → DNS-over-HTTPS with strict 5s timeout
  Brute-force use → always socket (sub-second per lookup)

Usage:
    from src.core import dns_compat as dns
    resolver = dns.asyncresolver.Resolver()
    answers  = await resolver.resolve("example.com", "A")
"""

import asyncio
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

import requests
import urllib3
urllib3.disable_warnings()

_executor = ThreadPoolExecutor(max_workers=100)

DOH_PROVIDERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

RDTYPE_MAP = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257, "PTR": 12,
}

# ── Exceptions ────────────────────────────────────────────────────────────
class DNSException(Exception): pass
class NXDOMAIN(DNSException):  pass
class NoAnswer(DNSException):  pass
class Timeout(DNSException):   pass

# ── Fake record classes ───────────────────────────────────────────────────
class _ARecord:
    def __init__(self, addr): self._addr = addr
    def __str__(self): return self._addr
    address = property(lambda self: self._addr)

class _AAAARecord:
    def __init__(self, addr): self._addr = addr
    def __str__(self): return self._addr
    address = property(lambda self: self._addr)

class _MXRecord:
    def __init__(self, pref, exch):
        self.preference = pref
        self.exchange   = type("E", (), {"__str__": lambda s: exch, "to_text": lambda s: exch})()
    def __str__(self): return f"{self.preference} {self.exchange}"

class _TXTRecord:
    def __init__(self, data):
        b = data.encode() if isinstance(data, str) else data
        self.strings = [b]
    def __str__(self):
        return b"".join(self.strings).decode("utf-8", errors="ignore")

class _NSRecord:
    def __init__(self, name): self._name = str(name).rstrip(".")
    def __str__(self): return self._name
    target = property(lambda self: self)

class _SOARecord:
    def __init__(self, mname, rname, serial):
        self.mname  = mname
        self.rname  = rname
        self.serial = serial

class _CAARecord:
    def __init__(self, data): self._data = data
    def __str__(self): return self._data

class _SRVRecord:
    def __init__(self, pri, wt, port, target):
        self.priority = pri; self.weight = wt
        self.port = port;    self.target = target


# ── Socket-based resolver (A / AAAA — uses OS DNS, instant) ──────────────
def _socket_resolve_a(name: str, timeout: float = 2.0):
    """Blocking socket resolution — run in executor."""
    try:
        import socket as _s
        results = _s.getaddrinfo(name, None, _s.AF_INET, _s.SOCK_STREAM)
        return [r[4][0] for r in results]
    except _s.gaierror:
        return []

def _socket_resolve_aaaa(name: str, timeout: float = 2.0):
    try:
        import socket as _s
        results = _s.getaddrinfo(name, None, _s.AF_INET6, _s.SOCK_STREAM)
        return [r[4][0] for r in results]
    except _s.gaierror:
        return []


# ── DoH resolver (MX, TXT, NS, SOA, CAA, CNAME) ──────────────────────────
def _doh_query(name: str, rtype: str, timeout: float = 5.0) -> list:
    """Blocking DoH request — run in executor."""
    rtype_code = RDTYPE_MAP.get(rtype.upper(), 1)
    for provider in DOH_PROVIDERS:
        try:
            r = requests.get(
                provider,
                params={"name": name, "type": rtype_code},
                headers={"Accept": "application/dns-json"},
                timeout=timeout,
                verify=False,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("Status") == 0:
                    return data.get("Answer", [])
        except Exception:
            continue
    return []


# ── Async Resolver ────────────────────────────────────────────────────────
class Resolver:
    def __init__(self):
        self.timeout  = 2.0
        self.lifetime = 4.0

    async def resolve(self, name: str, rdtype: str = "A") -> list:
        name   = str(name).rstrip(".")
        rdu    = rdtype.upper()
        loop   = asyncio.get_event_loop()
        tout   = min(float(self.timeout), 4.0)

        # ── A records → socket (instant, no HTTP) ────────────────────────
        if rdu == "A":
            try:
                ips = await asyncio.wait_for(
                    loop.run_in_executor(_executor, _socket_resolve_a, name, tout),
                    timeout=tout,
                )
                if not ips:
                    raise NoAnswer(f"No A records for {name}")
                return [_ARecord(ip) for ip in ips]
            except asyncio.TimeoutError:
                raise Timeout(f"A timeout: {name}")
            except NoAnswer:
                raise
            except Exception as e:
                raise NoAnswer(str(e))

        # ── AAAA records → socket ─────────────────────────────────────────
        if rdu == "AAAA":
            try:
                ips = await asyncio.wait_for(
                    loop.run_in_executor(_executor, _socket_resolve_aaaa, name, tout),
                    timeout=tout,
                )
                if not ips:
                    raise NoAnswer(f"No AAAA records for {name}")
                return [_AAAARecord(ip) for ip in ips]
            except asyncio.TimeoutError:
                raise Timeout(f"AAAA timeout: {name}")
            except NoAnswer:
                raise
            except Exception as e:
                raise NoAnswer(str(e))

        # ── All other types → DoH ─────────────────────────────────────────
        doh_timeout = min(self.lifetime, 5.0)
        try:
            answers = await asyncio.wait_for(
                loop.run_in_executor(_executor, _doh_query, name, rdtype, doh_timeout),
                timeout=doh_timeout + 1,
            )
        except asyncio.TimeoutError:
            raise Timeout(f"{rdu} timeout: {name}")

        if not answers:
            raise NoAnswer(f"No {rdu} records for {name}")

        return _parse_answers(rdu, answers)

    async def resolve_address(self, ip: str) -> list:
        """Reverse DNS lookup (PTR)."""
        loop = asyncio.get_event_loop()
        try:
            host, _, _ = await asyncio.wait_for(
                loop.run_in_executor(_executor,
                    lambda: socket.gethostbyaddr(ip)),
                timeout=3.0,
            )
            return [_NSRecord(host)]
        except Exception:
            raise NoAnswer(f"No PTR for {ip}")


def _parse_answers(rtype: str, raw: list) -> list:
    records = []
    for a in raw:
        data = a.get("data", "")
        t    = a.get("type", 0)
        try:
            if rtype in ("A", "AAAA"):
                records.append(_ARecord(data))
            elif rtype == "MX":
                parts = data.split()
                pref  = int(parts[0]) if parts else 10
                exch  = parts[1] if len(parts) > 1 else data
                records.append(_MXRecord(pref, exch.rstrip(".")))
            elif rtype == "TXT":
                # strip surrounding quotes
                text = data.strip('"')
                records.append(_TXTRecord(text))
            elif rtype in ("NS", "CNAME"):
                records.append(_NSRecord(data))
            elif rtype == "SOA":
                parts = data.split()
                mname  = parts[0] if parts else data
                rname  = parts[1] if len(parts) > 1 else ""
                serial = int(parts[2]) if len(parts) > 2 else 0
                records.append(_SOARecord(mname, rname, serial))
            elif rtype == "CAA":
                records.append(_CAARecord(data))
            elif rtype == "SRV":
                parts = data.split()
                pri, wt, port = int(parts[0]), int(parts[1]), int(parts[2])
                tgt = parts[3] if len(parts) > 3 else ""
                records.append(_SRVRecord(pri, wt, port, tgt))
            else:
                records.append(_TXTRecord(str(data)))
        except Exception:
            continue
    if not records:
        raise NoAnswer(f"No parseable {rtype} records")
    return records


# ── AXFR stub ──────────────────────────────────────────────────────────────
class _AXFRIter:
    def __aiter__(self): return self
    async def __anext__(self): raise StopAsyncIteration

class _Zone:
    def __init__(self, domain: str): self.origin = domain
    def iterate_rdatasets(self): return []

async def zone_transfer(nameserver: str, domain: str) -> _Zone:
    return _Zone(domain)


# ── Public interface (matches dnspython API surface used in modules) ───────
class _AsyncResolver:
    Resolver = Resolver


asyncresolver = _AsyncResolver()
