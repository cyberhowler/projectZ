"""
ProjectZ - DNS Records Module v2
Fetches all DNS record types using system DNS (socket) + DoH fallback.
Fast, parallel, never hangs.
"""

import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor

from src.core import dns_compat as dns
from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache, DatabaseManager

_executor = ThreadPoolExecutor(max_workers=30)


class DNSModule(BaseModule):
    MODULE_NAME = "dns"
    DESCRIPTION = "Full DNS enumeration — A, AAAA, MX, TXT, NS, CNAME, SOA, CAA"

    async def run(self) -> dict:
        domain = self.target.strip().lower().lstrip("www.")
        if "://" in domain: domain = domain.split("://",1)[1].split("/")[0]
        self.log.info(f"DNS records: {domain}")

        cached = cache.get("dns", domain)
        if cached and not self.options.get("no_cache"):
            return cached

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout  = 3
        resolver.lifetime = 4

        result: dict = {
            "domain": domain,
            "a": [], "aaaa": [], "mx": [], "txt": [],
            "ns": [], "cname": "", "soa": {}, "caa": [],
        }

        async def _query(rtype: str):
            try:
                answers = await asyncio.wait_for(
                    resolver.resolve(domain, rtype), timeout=5
                )
                return rtype, answers
            except Exception:
                return rtype, []

        # All record types in parallel
        tasks   = [_query(t) for t in ["A","AAAA","MX","TXT","NS","CNAME","SOA","CAA"]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception): continue
            rtype, answers = r
            if not answers: continue

            if rtype == "A":
                result["a"]    = [str(a) for a in answers]
                result["ipv4"] = result["a"]
            elif rtype == "AAAA":
                result["aaaa"] = [str(a) for a in answers]
                result["ipv6"] = result["aaaa"]
            elif rtype == "MX":
                result["mx"] = [
                    {"priority": getattr(a,"preference",10), "exchange": str(a.exchange)}
                    for a in answers
                ]
            elif rtype == "TXT":
                result["txt"] = [str(a) for a in answers]
            elif rtype == "NS":
                result["ns"] = [str(a) for a in answers]
            elif rtype == "CNAME":
                result["cname"] = str(answers[0]) if answers else ""
            elif rtype == "SOA":
                a = answers[0]
                result["soa"] = {
                    "mname":  str(getattr(a, "mname", "")),
                    "rname":  str(getattr(a, "rname", "")),
                    "serial": getattr(a, "serial", 0),
                }
            elif rtype == "CAA":
                result["caa"] = [str(a) for a in answers]

        # Analysis helpers
        txt_all = " ".join(result["txt"]).lower()
        result["has_spf"]   = "v=spf1" in txt_all
        result["has_dmarc"] = "v=dmarc1" in txt_all
        result["has_dkim"]  = "v=dkim1" in txt_all or "k=rsa" in txt_all
        result["mx_provider"] = _detect_mx(result["mx"])

        total = len(result["a"]) + len(result["aaaa"]) + len(result["mx"]) + \
                len(result["txt"]) + len(result["ns"]) + (1 if result["soa"] else 0)
        result["total_records"] = total
        result["total"] = total

        # Log
        for ip in result["a"][:5]:
            self.log.found("A", ip)
        for mx in result["mx"][:3]:
            self.log.found("MX", f"{mx['priority']} {mx['exchange']}")
        for ns in result["ns"][:3]:
            self.log.found("NS", ns)
        for txt in result["txt"][:3]:
            self.log.found("TXT", txt[:80])

        # SPF/DMARC analysis
        if not result["has_spf"]:
            self.log.warning(f"{domain}: No SPF record — email spoofing possible!")
        if not result["has_dmarc"]:
            self.log.warning(f"{domain}: No DMARC record — domain spoofing risk!")

        cache.set("dns", domain, result)
        return result


def _detect_mx(mx_records: list) -> str:
    if not mx_records: return "none"
    exchanges = " ".join(str(m.get("exchange","")).lower() for m in mx_records)
    if "google" in exchanges or "googlemail" in exchanges: return "Google Workspace"
    if "outlook" in exchanges or "microsoft" in exchanges: return "Microsoft 365"
    if "proofpoint" in exchanges: return "Proofpoint"
    if "mimecast" in exchanges: return "Mimecast"
    if "mailgun" in exchanges: return "Mailgun"
    if "sendgrid" in exchanges: return "SendGrid"
    if "amazonses" in exchanges: return "Amazon SES"
    if "zoho" in exchanges: return "Zoho Mail"
    return "custom/unknown"
