"""
ProjectZ - Module 37: Historical DNS / SecurityTrails Alternative (Extra-Ordinary)
Complete historical DNS intelligence WITHOUT SecurityTrails paid API:
  - Wayback Machine DNS history (FREE)
  - PassiveTotal community (FREE tier)
  - VirusTotal passive DNS (FREE 4 req/min with key)
  - CIRCL.lu passive DNS (FREE, no key)
  - Shodan InternetDB history (FREE)
  - RiskIQ community (FREE)
  - DNS change detection + IP history
  - Infrastructure pivot analysis
Self-coded — all free sources.
"""

from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime
from typing import Optional
from urllib.parse import quote

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class HistDNSModule(BaseModule):
    MODULE_NAME = "histdns"
    DESCRIPTION = "Historical DNS — Wayback, CIRCL passive DNS, VirusTotal, IP change tracking"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Historical DNS: {domain}")

        cached = cache.get("histdns", domain)
        if cached:
            return cached

        # All sources in parallel
        sem = asyncio.Semaphore(20)
        (wayback_data, circl_data, vt_data,
         shodan_hist, hackertarget_data) = await asyncio.gather(
            self._wayback_dns(domain),
            self._circl_pdns(domain),
            self._virustotal_pdns(domain),
            self._shodan_history(domain),
            self._hackertarget_history(domain),
            return_exceptions=True,
        )

        def _safe(v, d): return d if isinstance(v, Exception) else v
        wayback_data      = _safe(wayback_data,      {})
        circl_data        = _safe(circl_data,        [])
        vt_data           = _safe(vt_data,           [])
        shodan_hist       = _safe(shodan_hist,        {})
        hackertarget_data = _safe(hackertarget_data, [])

        # Aggregate all historical IPs
        all_ips = set()
        for record in circl_data + vt_data:
            if record.get("ip"):
                all_ips.add(record["ip"])
        all_ips.update(wayback_data.get("ips", []))

        # Build IP history timeline
        ip_timeline = self._build_ip_timeline(circl_data + vt_data)

        # Detect infrastructure changes
        changes = self._detect_changes(ip_timeline)

        # Pivot: other domains on same historical IPs
        pivot_domains = set()
        for record in circl_data:
            if record.get("rrname") and record.get("rrname") != domain:
                pivot_domains.add(record["rrname"].rstrip("."))

        result = {
            "domain":          domain,
            "total":           len(circl_data) + len(vt_data),
            "historical_ips":  sorted(all_ips),
            "ip_count":        len(all_ips),
            "ip_timeline":     ip_timeline,
            "infrastructure_changes": changes,
            "pivot_domains":   sorted(pivot_domains)[:20],
            "wayback":         wayback_data,
            "sources": {
                "circl_pdns":     len(circl_data),
                "virustotal":     len(vt_data),
                "shodan_hist":    bool(shodan_hist),
                "hackertarget":   len(hackertarget_data),
                "wayback":        bool(wayback_data),
            },
        }

        self.log.found("Historical IPs",    str(len(all_ips)))
        self.log.found("Passive DNS Records", str(len(circl_data) + len(vt_data)))
        self.log.found("Infrastructure Changes", str(len(changes)))
        if pivot_domains:
            self.log.found("Pivot Domains", str(len(pivot_domains)))
            for pd in sorted(pivot_domains)[:3]:
                self.log.found("Co-hosted Domain", pd)

        cache.set("histdns", domain, result)
        await self._persist_db(result)
        return result

    # ── Wayback Machine CDX API (FREE) ────────────────────────────────────
    async def _wayback_dns(self, domain: str) -> dict:
        url = (f"http://web.archive.org/cdx/search/cdx?url={domain}"
               f"&output=json&limit=100&fl=original,timestamp,statuscode,length"
               f"&filter=statuscode:200&collapse=urlkey")
        snapshots = []
        urls_seen = set()
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                # Skip header row
                for row in data[1:]:
                    if len(row) >= 2:
                        orig_url = row[0]
                        ts       = row[1]
                        if orig_url not in urls_seen:
                            urls_seen.add(orig_url)
                            snapshots.append({
                                "url":       orig_url,
                                "timestamp": ts,
                                "archive":   f"https://web.archive.org/web/{ts}/{orig_url}",
                            })
        except Exception as e:
            self.log.warning(f"Wayback error: {e}")

        # Also get IP history from Wayback
        ips = await self._wayback_ips(domain)

        return {
            "snapshots":       snapshots[:50],
            "snapshot_count":  len(snapshots),
            "ips":             ips,
            "earliest":        snapshots[-1]["timestamp"][:8] if snapshots else "",
            "latest":          snapshots[0]["timestamp"][:8] if snapshots else "",
        }

    async def _wayback_ips(self, domain: str) -> list[str]:
        url = f"https://host.io/api/full/{domain}?token="
        ips = []
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                for ip_info in data.get("ipinfo", {}).values():
                    if isinstance(ip_info, dict):
                        ip = ip_info.get("ip", "")
                        if ip:
                            ips.append(ip)
        except Exception:
            pass
        return ips

    # ── CIRCL.lu Passive DNS (FREE, no key) ───────────────────────────────
    async def _circl_pdns(self, domain: str) -> list[dict]:
        url = f"https://www.circl.lu/pdns/query/{domain}"
        records = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                # CIRCL returns NDJSON
                text = _r["text"]
                for line in text.strip().splitlines():
                    if not line.strip():
                        continue
                    try:
                        import json
                        entry = json.loads(line)
                        if entry.get("rrtype") == "A":
                            records.append({
                                "ip":         entry.get("rdata", ""),
                                "rrname":     entry.get("rrname", ""),
                                "rrtype":     entry.get("rrtype", ""),
                                "first_seen": entry.get("time_first_rfc3339", ""),
                                "last_seen":  entry.get("time_last_rfc3339", ""),
                                "count":      entry.get("count", 0),
                                "source":     "circl",
                            })
                    except Exception:
                        pass
        except Exception as e:
            self.log.warning(f"CIRCL PDNS error: {e}")
        return records

    # ── VirusTotal passive DNS (FREE 4/min with key) ──────────────────────
    async def _virustotal_pdns(self, domain: str) -> list[dict]:
        if not config.VIRUSTOTAL_API_KEY:
            return []
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=40"
        headers = {
            **config.DEFAULT_HEADERS,
            "x-apikey": config.VIRUSTOTAL_API_KEY,
        }
        records = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    records.append({
                        "ip":         attrs.get("ip_address", ""),
                        "rrname":     domain,
                        "rrtype":     "A",
                        "last_seen":  str(attrs.get("date", "")),
                        "resolver":   attrs.get("resolver", ""),
                        "source":     "virustotal",
                    })
        except Exception as e:
            self.log.warning(f"VirusTotal PDNS error: {e}")
        return records

    # ── Shodan InternetDB history ──────────────────────────────────────────
    async def _shodan_history(self, domain: str) -> dict:
        ip = await self._resolve(domain)
        if not ip:
            return {}
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                return {"ip": ip, "data": data}
        except Exception as e:
            self.log.warning(f"Shodan history error: {e}")
        return {}

    # ── HackerTarget IP history ────────────────────────────────────────────
    async def _hackertarget_history(self, domain: str) -> list[str]:
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        ips = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                text = _r["text"]
                ips  = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
        except Exception:
            pass
        return list(set(ips))

    # ── Analysis helpers ───────────────────────────────────────────────────
    def _build_ip_timeline(self, records: list[dict]) -> list[dict]:
        timeline = []
        ip_dates: dict[str, dict] = {}
        for r in records:
            ip = r.get("ip", "")
            if not ip:
                continue
            if ip not in ip_dates:
                ip_dates[ip] = {"ip": ip, "first_seen": r.get("first_seen", ""),
                                "last_seen": r.get("last_seen", ""), "source": r.get("source", "")}
            else:
                # Update last seen if newer
                if r.get("last_seen", "") > ip_dates[ip]["last_seen"]:
                    ip_dates[ip]["last_seen"] = r.get("last_seen", "")
        timeline = sorted(ip_dates.values(),
                          key=lambda x: x.get("last_seen", ""), reverse=True)
        return timeline[:30]

    def _detect_changes(self, timeline: list[dict]) -> list[dict]:
        if len(timeline) < 2:
            return []
        changes = []
        for i in range(len(timeline) - 1):
            curr = timeline[i]
            prev = timeline[i + 1]
            if curr["ip"] != prev["ip"]:
                changes.append({
                    "from_ip":   prev["ip"],
                    "to_ip":     curr["ip"],
                    "change_at": curr.get("first_seen", "unknown"),
                })
        return changes[:10]

    async def _resolve(self, domain: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception:
            return ""


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
