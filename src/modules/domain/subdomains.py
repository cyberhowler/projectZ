"""
ProjectZ - Subdomain Enumeration v2
Sources (all run concurrently):
  1. crt.sh   — Certificate Transparency logs (most reliable, huge database)
  2. Certspotter — Another CT log
  3. HackerTarget API — free passive DNS
  4. RapidDNS — free passive DNS
  5. AlienVault OTX — passive DNS (free)
  6. DNS brute-force — socket-based (instant, no HTTP)
  7. ThreatMiner — passive DNS

All sources have hard timeouts — never hangs.
"""

from __future__ import annotations

import asyncio
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from src.core import async_http as aiohttp
from src.core.engine import BaseModule
from src.core.http_client import fetch, default_headers
from src.core.logger import OSINTLogger
from src.core.storage import cache, wordlists, DatabaseManager

_dns_executor = ThreadPoolExecutor(max_workers=200)


class SubdomainModule(BaseModule):
    MODULE_NAME = "subdomains"
    DESCRIPTION = "Subdomain enumeration — CT logs + passive DNS + brute-force"

    async def run(self) -> dict:
        domain = self.target.lower().strip().lstrip("www.").lstrip("*.")
        if "://" in domain:
            domain = domain.split("://", 1)[1].split("/")[0]
        self.log.info(f"Subdomain enumeration: {domain}")

        cached = cache.get("subdomains", domain)
        if cached and not self.options.get("no_cache"):
            self.log.info("Returning cached subdomains")
            return cached

        found: dict[str, str] = {}   # subdomain → ip

        # Run all sources concurrently with individual timeouts
        sources = await asyncio.gather(
            self._crtsh(domain),
            self._certspotter(domain),
            self._hackertarget(domain),
            self._rapiddns(domain),
            self._otx(domain),
            self._threatminer(domain),
            return_exceptions=True,
        )

        src_names = ["crtsh","certspotter","hackertarget","rapiddns","otx","threatminer"]
        src_counts = {}
        all_subs: set[str] = set()

        for name, result in zip(src_names, sources):
            if isinstance(result, Exception):
                src_counts[name] = 0
                continue
            subs = result if isinstance(result, set) else set()
            src_counts[name] = len(subs)
            all_subs.update(subs)
            if subs:
                self.log.info(f"{name}: found {len(subs)} subdomains")

        # DNS brute-force (concurrent socket, very fast)
        wordlist = wordlists.subdomains(limit=500)
        brute = await self._bruteforce_socket(domain, wordlist)
        src_counts["bruteforce"] = len(brute)
        all_subs.update(brute)

        self.log.info(f"Total unique before validation: {len(all_subs)}")

        # Resolve all to IPs concurrently
        resolved = await self._resolve_all(list(all_subs))
        self.log.info(f"Resolved: {len(resolved)} live subdomains")

        # Log top finds
        for sub, ip in sorted(resolved.items())[:20]:
            self.log.found("Subdomain", f"{sub} → {ip}")

        # Classify interesting subdomains
        interesting_patterns = [
            "admin","vpn","portal","dev","staging","test","qa","api","backend",
            "internal","intranet","gitlab","jenkins","jira","confluence","kibana",
            "grafana","db","database","smtp","mail","webmail","cpanel","phpmyadmin",
            "remote","secure","old","legacy","beta","preprod","uat","infra"
        ]
        interesting = {s: ip for s, ip in resolved.items()
                      if any(p in s.split(".")[0].lower() for p in interesting_patterns)}

        result = {
            "domain":      domain,
            "subdomains":  sorted(resolved.keys()),
            "subdomain_ips": resolved,
            "interesting": sorted(interesting.keys()),
            "total":       len(resolved),
            "sources":     src_counts,
            "total_unique_found": len(all_subs),
        }

        # Persist to DB
        for sub, ip in resolved.items():
            await DatabaseManager.insert_subdomain(domain, sub, ip=ip, source="subdomains")

        cache.set("subdomains", domain, result)
        return result

    # ── Source 1: crt.sh ──────────────────────────────────────────────────
    async def _crtsh(self, domain: str) -> set[str]:
        subs: set[str] = set()
        try:
            r = await asyncio.wait_for(
                fetch(f"https://crt.sh/?q=%.{domain}&output=json",
                      timeout=15, rotate_ua=False,
                      headers={"Accept": "application/json"}),
                timeout=18,
            )
            if r["ok"] and r["json"]:
                for entry in r["json"]:
                    for name in entry.get("name_value","").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") and self._valid(name):
                            subs.add(name)
        except Exception:
            pass
        return subs

    # ── Source 2: Certspotter ─────────────────────────────────────────────
    async def _certspotter(self, domain: str) -> set[str]:
        subs: set[str] = set()
        try:
            r = await asyncio.wait_for(
                fetch(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                      timeout=10),
                timeout=12,
            )
            if r["ok"] and r["json"]:
                for cert in r["json"]:
                    for name in cert.get("dns_names", []):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") and self._valid(name):
                            subs.add(name)
        except Exception:
            pass
        return subs

    # ── Source 3: HackerTarget ────────────────────────────────────────────
    async def _hackertarget(self, domain: str) -> set[str]:
        subs: set[str] = set()
        try:
            r = await asyncio.wait_for(
                fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10),
                timeout=12,
            )
            if r["ok"] and r["text"]:
                for line in r["text"].splitlines():
                    parts = line.strip().split(",")
                    if parts:
                        name = parts[0].strip().lower()
                        if name.endswith(f".{domain}") and self._valid(name):
                            subs.add(name)
        except Exception:
            pass
        return subs

    # ── Source 4: RapidDNS ────────────────────────────────────────────────
    async def _rapiddns(self, domain: str) -> set[str]:
        subs: set[str] = set()
        try:
            r = await asyncio.wait_for(
                fetch(f"https://rapiddns.io/subdomain/{domain}?full=1",
                      timeout=10, headers={"Accept": "text/html"}),
                timeout=12,
            )
            if r["ok"] and r["text"]:
                for m in re.finditer(rf'([\w.-]+\.{re.escape(domain)})', r["text"]):
                    name = m.group(1).lower()
                    if self._valid(name):
                        subs.add(name)
        except Exception:
            pass
        return subs

    # ── Source 5: AlienVault OTX ──────────────────────────────────────────
    async def _otx(self, domain: str) -> set[str]:
        subs: set[str] = set()
        try:
            r = await asyncio.wait_for(
                fetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                      timeout=10),
                timeout=12,
            )
            if r["ok"] and r["json"]:
                for entry in r["json"].get("passive_dns", []):
                    name = str(entry.get("hostname","")).lower().strip()
                    if name.endswith(f".{domain}") and self._valid(name):
                        subs.add(name)
        except Exception:
            pass
        return subs

    # ── Source 6: ThreatMiner ─────────────────────────────────────────────
    async def _threatminer(self, domain: str) -> set[str]:
        subs: set[str] = set()
        try:
            r = await asyncio.wait_for(
                fetch(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
                      timeout=8),
                timeout=10,
            )
            if r["ok"] and r["json"]:
                for entry in r["json"].get("results", []):
                    name = str(entry).lower().strip()
                    if name.endswith(f".{domain}") and self._valid(name):
                        subs.add(name)
        except Exception:
            pass
        return subs

    # ── Source 7: DNS brute-force (socket, very fast) ─────────────────────
    async def _bruteforce_socket(self, domain: str, wordlist: list) -> set[str]:
        found: set[str] = set()
        sem = asyncio.Semaphore(200)   # 200 concurrent — socket is fast
        loop = asyncio.get_event_loop()

        def _resolve(fqdn: str) -> str | None:
            try:
                socket.setdefaulttimeout(1.0)
                results = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                return results[0][4][0] if results else None
            except Exception:
                return None

        async def _check(word: str):
            fqdn = f"{word}.{domain}"
            async with sem:
                try:
                    ip = await asyncio.wait_for(
                        loop.run_in_executor(_dns_executor, _resolve, fqdn),
                        timeout=2.0,
                    )
                    if ip:
                        found.add(fqdn)
                except Exception:
                    pass

        await asyncio.gather(*[_check(w) for w in wordlist], return_exceptions=True)
        return found

    # ── Resolve all to IPs ────────────────────────────────────────────────
    async def _resolve_all(self, subdomains: list) -> dict[str, str]:
        resolved: dict[str, str] = {}
        sem  = asyncio.Semaphore(200)
        loop = asyncio.get_event_loop()

        def _res(name: str):
            try:
                socket.setdefaulttimeout(1.0)
                r = socket.getaddrinfo(name, None, socket.AF_INET)
                return r[0][4][0] if r else ""
            except Exception:
                return ""

        async def _check(name: str):
            async with sem:
                try:
                    ip = await asyncio.wait_for(
                        loop.run_in_executor(_dns_executor, _res, name),
                        timeout=2.0,
                    )
                    if ip:
                        resolved[name] = ip
                except Exception:
                    pass

        await asyncio.gather(*[_check(s) for s in subdomains], return_exceptions=True)
        return resolved

    def _valid(self, name: str) -> bool:
        if not name or len(name) > 253: return False
        if re.search(r"[^a-z0-9.\-]", name): return False
        return True
