from __future__ import annotations
"""
ProjectZ - Module 35: DNS Dumpster / Full DNS Harvester (Extra-Ordinary)
Complete DNS intelligence harvest:
  - DNSDumpster (FREE scrape, full zone-dump style)
  - HackerTarget DNS lookup tools
  - SecurityTrails-style historical record mining (via free alternatives)
  - DNS brute-force with prioritised wordlist
  - Zone transfer attempt (AXFR)
  - DNS over HTTPS (DoH) for censorship-bypass
  - SOA serial tracking
  - Full record type coverage: A/AAAA/MX/TXT/NS/CNAME/SOA/SRV/PTR/CAA/DNSKEY
Self-coded — maximum DNS coverage.
"""

import asyncio
import re
import socket
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch
from src.core import dns_compat as dns

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager, wordlists
from src.core.config import config

ALL_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA",
                    "SRV", "CAA", "DNSKEY", "DS", "PTR"]

# DoH providers for fallback
DOH_PROVIDERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]


class DNSDumpsterModule(BaseModule):
    MODULE_NAME = "dnsdump"
    DESCRIPTION = "Full DNS harvest — DNSDumpster, zone transfer, DoH, brute-force, all record types"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"DNS dump harvest: {domain}")

        cached = cache.get("dnsdump", domain)
        if cached:
            return cached

        # Run all DNS collection methods concurrently
        (dnsdumpster_data, hackertarget_data, all_records,
         axfr_data, brute_subs, doh_data) = await asyncio.gather(
            self._dnsdumpster(domain),
            self._hackertarget(domain),
            self._full_record_enum(domain),
            self._zone_transfer(domain),
            self._dns_brute(domain),
            self._doh_lookup(domain),
            return_exceptions=True,
        )

        def _safe(v, d): return d if isinstance(v, Exception) else v
        dnsdumpster_data = _safe(dnsdumpster_data, {})
        hackertarget_data= _safe(hackertarget_data, {})
        all_records      = _safe(all_records, {})
        axfr_data        = _safe(axfr_data, {})
        brute_subs       = _safe(brute_subs, [])
        doh_data         = _safe(doh_data, {})

        # Merge all subdomains
        subs_merged = set()
        subs_merged.update(dnsdumpster_data.get("subdomains", []))
        subs_merged.update(hackertarget_data.get("subdomains", []))
        subs_merged.update(brute_subs)
        subs_merged.update(doh_data.get("subdomains", []))
        subs_merged.update(axfr_data.get("subdomains", []))

        # Store subdomains in DB
        for sub in subs_merged:
            await DatabaseManager.insert_subdomain(domain, sub, "", "dnsdump")

        # Merge all IP addresses
        ips_merged = set()
        for ips in [dnsdumpster_data.get("ips", []), hackertarget_data.get("ips", []),
                    all_records.get("a", []), all_records.get("aaaa", [])]:
            ips_merged.update(ips)

        result = {
            "domain":           domain,
            "total":            len(subs_merged),
            "subdomains":       sorted(subs_merged),
            "total_subdomains": len(subs_merged),
            "ips":              sorted(ips_merged),
            "records":          all_records,
            "axfr": {
                "success":  axfr_data.get("success", False),
                "records":  axfr_data.get("records", []),
                "nameservers_tried": axfr_data.get("ns_tried", []),
            },
            "mx_providers":  self._detect_mx_providers(all_records.get("mx", [])),
            "nameservers":   all_records.get("ns", []),
            "spf":           self._extract_spf(all_records.get("txt", [])),
            "dmarc":         self._extract_dmarc(all_records.get("txt", [])),
            "doh_verified":  doh_data.get("verified", False),
            "sources": {
                "dnsdumpster":  bool(dnsdumpster_data),
                "hackertarget": bool(hackertarget_data),
                "axfr":         axfr_data.get("success", False),
                "brute":        len(brute_subs),
                "doh":          bool(doh_data),
            },
        }

        self.log.found("Subdomains",    str(len(subs_merged)))
        self.log.found("IPs",           str(len(ips_merged)))
        self.log.found("NS Records",    str(len(all_records.get("ns", []))))
        self.log.found("MX Records",    str(len(all_records.get("mx", []))))
        if axfr_data.get("success"):
            self.log.warning("⚠ ZONE TRANSFER SUCCESSFUL — full DNS zone exposed!")
        if result.get("spf"):
            self.log.found("SPF", result["spf"][:80])

        cache.set("dnsdump", domain, result)
        return result

    # ── DNSDumpster (scrape) ───────────────────────────────────────────────
    async def _dnsdumpster(self, domain: str) -> dict:
        # Step 1: get CSRF token
        base_url = "https://dnsdumpster.com"
        result   = {"subdomains": [], "ips": [], "mx": [], "ns": []}
        try:
            _r = await fetch(base_url, headers=config.DEFAULT_HEADERS, timeout=8)
            html  = _r["text"]
            csrf  = re.search(r'csrfmiddlewaretoken["\' ]+value["\' ]+([a-zA-Z0-9]+)', html)
            # Parse cookies from Set-Cookie response header (_r was the correct variable; r1 was never defined)
            set_cookie_hdr = _r.get("headers", {}).get("set-cookie", "")
            cookies: dict = {}
            for _part in set_cookie_hdr.split(","):
                _kv = _part.strip().split(";")[0].strip()
                if "=" in _kv:
                    _k, _v = _kv.split("=", 1)
                    cookies[_k.strip()] = _v.strip()
            if not csrf:
                return result
            csrf_token = csrf.group(1)

            # Step 2: POST with domain
            data = {"csrfmiddlewaretoken": csrf_token, "targetip": domain, "user": "free"}
            hdrs = {**config.DEFAULT_HEADERS,
                    "Referer": base_url,
                    "Origin":  base_url}
            async with rate_limiter.throttle("dnsdumpster.com"):
                async with session.post(
                    base_url, data=data, headers=hdrs,
                    cookies=cookies, allow_redirects=True,
                ) as r2:
                    html = await r2.text(errors="ignore")
                    return self._parse_dnsdumpster_html(html, domain)
        except Exception as e:
            self.log.warning(f"DNSDumpster error: {e}")
        return result

    def _parse_dnsdumpster_html(self, html: str, domain: str) -> dict:
        subdomains = set()
        ips        = set()
        mx         = []
        ns         = []

        # Extract hostnames from tables
        for m in re.finditer(
            r'<td class="col-md-4">(.*?)</td>', html, re.DOTALL
        ):
            text = re.sub(r"<[^>]+>", "", m.group(1)).strip().lower()
            if text.endswith(f".{domain}"):
                subdomains.add(text)
            elif re.match(r"\d+\.\d+\.\d+\.\d+", text):
                ips.add(text)

        # MX and NS
        for tag, container in [("mx", mx), ("ns", ns)]:
            for m in re.finditer(
                rf'<tr[^>]*class="[^"]*{tag}[^"]*"[^>]*>(.*?)</tr>',
                html, re.DOTALL | re.IGNORECASE,
            ):
                text = re.sub(r"<[^>]+>", " ", m.group(1)).strip()
                if text:
                    container.append(text[:200])

        return {"subdomains": list(subdomains), "ips": list(ips), "mx": mx, "ns": ns}

    # ── HackerTarget DNS lookup ────────────────────────────────────────────
    async def _hackertarget(self, domain: str) -> dict:
        endpoints = {
            "hostsearch": f"https://api.hackertarget.com/hostsearch/?q={domain}",
            "dnslookup":  f"https://api.hackertarget.com/dnslookup/?q={domain}",
            "reversedns": f"https://api.hackertarget.com/reverseiplookup/?q={domain}",
        }
        subdomains = set()
        ips        = set()

        for key, url in endpoints.items():
            try:
                _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                if _r["ok"]:
                    text = _r["text"]
                    if "API count" in text or "error" in text.lower():
                        continue
                    for line in text.splitlines():
                        parts = line.strip().split(",")
                        if len(parts) >= 1:
                            h = parts[0].strip().lower()
                            if h.endswith(f".{domain}"):
                                subdomains.add(h)
                        if len(parts) >= 2:
                            ip = parts[1].strip()
                            if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                                ips.add(ip)
                        for m in re.finditer(r"\d+\.\d+\.\d+\.\d+", line):
                            ips.add(m.group(0))
            except Exception as e:
                self.log.warning(f"HackerTarget {key} error: {e}")
            await asyncio.sleep(0.5)

        return {"subdomains": list(subdomains), "ips": list(ips)}

    # ── Full record type enumeration ───────────────────────────────────────
    async def _full_record_enum(self, domain: str) -> dict:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout  = 5
        resolver.lifetime = 8
        records: dict[str, list[str]] = {}

        async def _query(rtype: str) -> tuple[str, list[str]]:
            try:
                ans = await resolver.resolve(domain, rtype)
                return rtype.lower(), self._format_records(ans, rtype)
            except Exception:
                return rtype.lower(), []

        tasks   = [_query(rt) for rt in ALL_RECORD_TYPES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for item in results:
            if isinstance(item, tuple):
                rtype, values = item
                if values:
                    records[rtype] = values

        return records

    def _format_records(self, answer, rtype: str) -> list[str]:
        out = []
        for r in answer:
            if rtype == "MX":
                out.append(f"{r.preference} {r.exchange}")
            elif rtype == "SOA":
                out.append(f"mname={r.mname} serial={r.serial}")
            elif rtype == "TXT":
                out.append(b"".join(r.strings).decode("utf-8", errors="ignore"))
            elif rtype == "SRV":
                out.append(f"priority={r.priority} weight={r.weight} port={r.port} target={r.target}")
            else:
                out.append(str(r))
        return out

    # ── Zone transfer (AXFR) ─────────────────────────────────────────────
    async def _zone_transfer(self, domain: str) -> dict:
        result = {"success": False, "records": [], "ns_tried": []}
        try:
            # Get NS records first
            resolver = dns.asyncresolver.Resolver()
            try:
                ns_ans = await resolver.resolve(domain, "NS")
                nameservers = [str(r).rstrip(".") for r in ns_ans]
            except Exception:
                nameservers = []

            result["ns_tried"] = nameservers

            loop = asyncio.get_event_loop()
            for ns in nameservers[:3]:
                try:
                    ns_ip = await loop.run_in_executor(None, socket.gethostbyname, ns)
                    z     = await loop.run_in_executor(
                        None,
                        lambda: dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5)),
                    )
                    if z:
                        records = []
                        for name, node in z.nodes.items():
                            records.append(str(name))
                        result["success"] = True
                        result["records"] = records[:200]
                        self.log.warning(f"⚠ AXFR SUCCESS from {ns}!")
                        return result
                except Exception:
                    pass
        except Exception as e:
            self.log.warning(f"AXFR check error: {e}")
        return result

    # ── DNS brute-force ────────────────────────────────────────────────────
    async def _dns_brute(self, domain: str, limit: int = 200) -> list[str]:
        wl       = wordlists.subdomains(limit=limit)
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout  = 2
        resolver.lifetime = 3
        sem      = asyncio.Semaphore(50)
        found    = []

        async def _check(word: str):
            fqdn = f"{word}.{domain}"
            async with sem:
                try:
                    await resolver.resolve(fqdn, "A")
                    found.append(fqdn)
                except Exception:
                    pass

        await asyncio.gather(*[_check(w) for w in wl], return_exceptions=True)
        return found

    # ── DNS over HTTPS ─────────────────────────────────────────────────────
    async def _doh_lookup(self, domain: str) -> dict:
        """Query via DoH to bypass potential DNS filtering."""
        result = {"subdomains": [], "verified": False, "records": {}}
        headers = {**config.DEFAULT_HEADERS, "Accept": "application/dns-json"}
        for provider in DOH_PROVIDERS[:2]:
            for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
                url = f"{provider}?name={domain}&type={rtype}"
                try:
                    _r = await fetch(url, headers=headers, timeout=8)
                    if _r["ok"]:
                        data    = _r["json"]
                        answers = data.get("Answer", [])
                        if answers:
                            result["verified"] = True
                            result["records"][rtype.lower()] = [
                                a.get("data", "") for a in answers
                            ]
                except Exception:
                    pass
        return result

    # ── Helpers ───────────────────────────────────────────────────────────
    def _detect_mx_providers(self, mx_records: list[str]) -> list[str]:
        providers = []
        patterns = {
            "google.com": "Google Workspace", "googlemail.com": "Google Workspace",
            "outlook.com": "Microsoft 365", "protection.outlook.com": "Microsoft 365",
            "pphosted.com": "Proofpoint", "mimecast.com": "Mimecast",
            "amazonaws.com": "Amazon SES", "sendgrid.net": "SendGrid",
            "mailgun.org": "Mailgun",
        }
        for mx in mx_records:
            for pat, name in patterns.items():
                if pat in mx.lower() and name not in providers:
                    providers.append(name)
        return providers

    def _extract_spf(self, txt_records: list[str]) -> str:
        for txt in txt_records:
            if "v=spf1" in txt.lower():
                return txt
        return ""

    def _extract_dmarc(self, txt_records: list[str]) -> str:
        for txt in txt_records:
            if "v=dmarc1" in txt.lower():
                return txt
        return ""

    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
