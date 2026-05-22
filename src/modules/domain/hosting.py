"""
ProjectZ - Module 07: Hosting / Cloud Provider Detection
Detect AWS, GCP, Azure, Cloudflare, Fastly, etc. from IP ranges + headers.
Self-coded — uses public cloud IP range files + DNS patterns.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager, wordlists
from src.core.config import config


# ── Cloud provider detection patterns ────────────────────────────────────────
CLOUD_PATTERNS: dict[str, list[str]] = {
    "Cloudflare":   ["cloudflare", "cf-ray", "Server: cloudflare", ".cloudflare.net"],
    "AWS":          ["amazonaws.com", "aws", "x-amz-", "cloudfront.net", "elb.amazonaws.com"],
    "Google Cloud": ["googleapis.com", "appspot.com", "ghs.google.com", "ghs.googlehosted.com"],
    "Azure":        ["azure.com", "azurewebsites.net", "cloudapp.azure.com", "x-ms-request-id"],
    "Fastly":       ["fastly.net", "fastlylb.net", "X-Served-By"],
    "Akamai":       ["akamai", "akamaiedge.net", "akamaitechnologies.com"],
    "Vercel":       ["vercel.app", "x-vercel-id", "vercel.com"],
    "Netlify":      ["netlify.app", "netlify.com", "x-nf-request-id"],
    "Heroku":       ["heroku.com", "herokuapp.com"],
    "DigitalOcean": ["digitalocean.com", "ondigitalocean.app"],
    "Linode":       ["linode.com", "linodeobjects.com"],
    "Vultr":        ["vultr.com"],
    "GitHub Pages": ["github.io", "githubusercontent.com"],
    "Hetzner":      ["hetzner.com", "hetzner.de"],
}

# DNS hostname patterns that reveal hosting
HOSTNAME_PATTERNS: dict[str, str] = {
    r"\.cloudfront\.net$":      "AWS CloudFront",
    r"\.elb\.amazonaws\.com$":  "AWS ELB",
    r"\.s3\.amazonaws\.com$":   "AWS S3",
    r"ec2-[\d-]+\..*\.compute\.amazonaws\.com$": "AWS EC2",
    r"\.appspot\.com$":         "Google App Engine",
    r"\.run\.app$":             "Google Cloud Run",
    r"\.googleapis\.com$":      "Google APIs",
    r"\.azurewebsites\.net$":   "Azure App Service",
    r"\.cloudapp\.azure\.com$": "Azure VM",
    r"\.herokuapp\.com$":       "Heroku",
    r"\.netlify\.app$":         "Netlify",
    r"\.vercel\.app$":          "Vercel",
    r"\.github\.io$":           "GitHub Pages",
    r"\.fastly\.net$":          "Fastly CDN",
}


class HostingModule(BaseModule):
    MODULE_NAME = "hosting"
    DESCRIPTION = "Cloud/hosting provider detection — AWS/GCP/Azure/Cloudflare/CDN"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Hosting detection: {domain}")

        cached = cache.get("hosting", domain)
        if cached:
            return cached

        # Parallel: resolve IP, fetch HTTP headers, reverse DNS
        ip, headers_data, rdns = await asyncio.gather(
            self._to_ip(domain),
            self._fetch_headers(domain),
            self._reverse_dns(domain),
            return_exceptions=True,
        )

        if isinstance(ip, Exception):         ip           = ""
        if isinstance(headers_data, Exception): headers_data = {}
        if isinstance(rdns, Exception):        rdns         = ""

        providers = self._detect_providers(domain, ip, headers_data, rdns)
        cdn       = self._detect_cdn(headers_data, rdns)

        result = {
            "domain":          domain,
            "total":       1,
            "ip":              ip,
            "reverse_dns":     rdns,
            "providers":       providers,
            "cdn":             cdn,
            "primary_host":    providers[0] if providers else "Unknown",
            "is_behind_cdn":   bool(cdn),
            "server_header":   headers_data.get("server", ""),
            "headers_checked": list(headers_data.keys()),
        }

        for p in providers:
            self.log.found("Provider", p)
        if cdn:
            self.log.found("CDN", cdn)

        cache.set("hosting", domain, result)
        await self._persist_db(result)
        return result

    # ── HTTP header fetch ──────────────────────────────────────────────────
    async def _fetch_headers(self, domain: str) -> dict:
        url = f"https://{domain}"
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            _r = await fetch(url, method="head", headers=config.DEFAULT_HEADERS, timeout=8)
            return {k.lower(): v for k, v in _r["headers"].items()}
        except Exception:
            pass
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            _r = await fetch(f"http://{domain}", method="head", headers=config.DEFAULT_HEADERS, timeout=8)
            return {k.lower(): v for k, v in _r["headers"].items()}
        except Exception as e:
            self.log.warning(f"Header fetch failed: {e}")
            return {}

    # ── IP resolution ──────────────────────────────────────────────────────

    async def _to_ip(self, target: str) -> str:
        """Resolve domain to IP. Tries OS DNS first, then DoH fallback."""
        import re as _re
        if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        # Method 1: OS socket DNS
        import socket as _s, asyncio as _a
        loop = _a.get_event_loop()
        try:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=1) as ex:
                results = await _a.wait_for(
                    loop.run_in_executor(ex, _s.getaddrinfo, target, None, _s.AF_INET),
                    timeout=3.0)
                if results:
                    return results[0][4][0]
        except Exception:
            pass
        # Method 2: DoH (works when OS DNS is blocked/unavailable)
        for doh in ("https://cloudflare-dns.com/dns-query",
                    "https://dns.google/resolve"):
            try:
                r = await _a.wait_for(
                    fetch(doh, params={"name": target, "type": "A"},
                          headers={"Accept": "application/dns-json"}, timeout=5),
                    timeout=6)
                if r.get("ok") and r.get("json"):
                    answers = r["json"].get("Answer", [])
                    for ans in answers:
                        if ans.get("type") == 1:   # A record
                            return ans.get("data", "")
            except Exception:
                continue
        return ""

    async def _reverse_dns(self, domain: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            ip = await self._to_ip(domain)
            if not ip:
                return ""
            hostname, _, _ = await loop.run_in_executor(
                None, socket.gethostbyaddr, ip
            )
            return hostname
        except Exception:
            return ""

    # ── Provider detection ─────────────────────────────────────────────────
    def _detect_providers(self, domain: str, ip: str, headers: dict, rdns: str) -> list[str]:
        found = []
        haystack = (
            domain + " " +
            " ".join(f"{k}: {v}" for k, v in headers.items()) + " " +
            rdns
        ).lower()

        for provider, patterns in CLOUD_PATTERNS.items():
            if any(p.lower() in haystack for p in patterns):
                if provider not in found:
                    found.append(provider)

        # Hostname pattern matching
        for pattern, provider in HOSTNAME_PATTERNS.items():
            if re.search(pattern, rdns, re.IGNORECASE):
                if provider not in found:
                    found.append(provider)

        return found

    def _detect_cdn(self, headers: dict, rdns: str) -> str:
        cdn_headers = {
            "cf-ray":          "Cloudflare",
            "x-served-by":     "Fastly",
            "x-amz-cf-id":     "AWS CloudFront",
            "x-vercel-id":     "Vercel",
            "x-nf-request-id": "Netlify",
            "x-akamai-request-id": "Akamai",
            "x-cdn":           "CDN",
        }
        for header, cdn in cdn_headers.items():
            if header in headers:
                return cdn
        return ""


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
