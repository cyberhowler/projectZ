from __future__ import annotations
"""
ProjectZ - Module 24: Banner Grabbing
Grab service banners from open ports via raw socket + HTTP probes.
Self-coded — no external API, works on any open port.
"""

import asyncio
import re
import socket
import ssl
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config
from src.modules.network.nmap_wrapper import SERVICE_MAP

# Protocol-specific probe payloads
_PROBES: dict[int, bytes] = {
    21:    b"",                         # FTP sends banner on connect
    22:    b"",                         # SSH sends banner on connect
    25:    b"EHLO projectz\r\n",        # SMTP
    80:    b"HEAD / HTTP/1.0\r\n\r\n",  # HTTP
    110:   b"",                         # POP3
    143:   b"",                         # IMAP
    443:   b"",                         # HTTPS (handled separately)
    3306:  b"",                         # MySQL
    5432:  b"",                         # PostgreSQL
    6379:  b"INFO server\r\n",          # Redis
    9200:  b"",                         # Elasticsearch
    27017: b"",                         # MongoDB
}

_COMMON_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090, 4000, 3000}


class BannerModule(BaseModule):
    MODULE_NAME = "banner"
    DESCRIPTION = "Service banner grabbing — raw socket probes + HTTP title extraction"

    async def run(self) -> dict:
        target = self._clean(self.target)
        ports  = self.options.get("ports", None)
        self.log.info(f"Banner grab: {target}")

        cached = cache.get("banner", target)
        if cached:
            return cached

        ip = target if self._is_ip(target) else await self._resolve(target)
        if not ip:
            return {"target": target, "error": "Could not resolve IP"}

        # If specific ports not given, do a quick TCP scan first
        if ports:
            port_list = self._parse_ports(ports)
        else:
            port_list = await self._quick_scan(ip)

        self.log.info(f"Grabbing banners on {len(port_list)} ports")

        # Grab all banners concurrently
        sem      = asyncio.Semaphore(20)
        banners  = await asyncio.gather(
            *[self._grab(ip, port, target, sem) for port in port_list],
            return_exceptions=True,
        )
        banner_results = [b for b in banners
                         if isinstance(b, dict) and b.get("banner")]

        result = {
            "target":          target,
            "total":           len(banner_results),
            "ip":              ip,
            "banners":         banner_results,
            "banner_count":    len(banner_results),
            "ports_checked":   len(port_list),
            "http_titles":     [b["http_title"] for b in banner_results if b.get("http_title")],
            "services_found":  list({b["service"] for b in banner_results if b.get("service")}),
        }

        self._log_findings(result)
        cache.set("banner", target, result)
        await self._persist_db(result)
        return result

    # ── Quick TCP scan to find open ports ─────────────────────────────────
    async def _quick_scan(self, ip: str) -> list[int]:
        common = [21,22,23,25,53,80,110,143,443,445,587,993,995,
                  1433,3000,3306,3389,5432,5900,5984,5985,6379,
                  8000,8080,8443,8888,9000,9090,9200,27017]
        sem   = asyncio.Semaphore(100)
        found = []

        async def _probe(port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=1.0
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    found.append(port)
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in common], return_exceptions=True)
        return found

    # ── Banner grab per port ──────────────────────────────────────────────
    async def _grab(self, ip: str, port: int, domain: str,
                    sem: asyncio.Semaphore) -> Optional[dict]:
        async with sem:
            service    = SERVICE_MAP.get(port, "unknown")
            banner     = ""
            http_title = ""

            # HTTP/HTTPS ports — use aiohttp for full headers + title
            if port in _COMMON_HTTP_PORTS:
                scheme = "https" if port in {443, 8443} else "http"
                banner, http_title = await self._http_probe(domain, ip, port, scheme)
            else:
                banner = await self._raw_probe(ip, port)

            if not banner and not http_title:
                return None

            return {
                "port":       port,
                "service":    service,
                "banner":     banner[:300] if banner else "",
                "http_title": http_title[:200] if http_title else "",
                "ip":         ip,
            }

    # ── Raw socket probe ──────────────────────────────────────────────────
    async def _raw_probe(self, ip: str, port: int) -> str:
        probe = _PROBES.get(port, b"\r\n")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3.0
            )
            if probe:
                writer.write(probe)
                await writer.drain()
            data   = await asyncio.wait_for(reader.read(512), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data.decode("utf-8", errors="ignore").strip()[:300]
        except Exception:
            return ""

    # ── HTTP probe ─────────────────────────────────────────────────────────
    async def _http_probe(self, domain: str, ip: str, port: int,
                          scheme: str) -> tuple[str, str]:
        url = f"{scheme}://{domain}:{port}" if port not in {80, 443} \
              else f"{scheme}://{domain}"
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            body       = _r["text"]
            server_hdr = _r["headers"].get("Server", "")
            powered    = _r["headers"].get("X-Powered-By", "")
            banner     = f"HTTP/{resp.version} {_r["status"]} | Server: {server_hdr} | X-Powered-By: {powered}"

            title_m    = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            http_title = ""
            if title_m:
                http_title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:200]

            return banner.strip(" |"), http_title
        except Exception:
            return "", ""

    def _log_findings(self, r: dict) -> None:
        self.log.found("Banners Grabbed", str(r.get("banner_count", 0)))
        for b in r.get("banners", [])[:10]:
            if b.get("http_title"):
                self.log.found(f"Port {b['port']} Title", b["http_title"])
            elif b.get("banner"):
                self.log.found(f"Port {b['port']} Banner",
                               b["banner"][:80].replace("\n", " "))

    def _parse_ports(self, ports_str: str) -> list[int]:
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                ports.append(int(part))
        return ports

    async def _resolve(self, domain: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception:
            return ""

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
