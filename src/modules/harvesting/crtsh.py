"""
ProjectZ - crt.sh + Certspotter + CT log harvesting v2
Mines certificate transparency for subdomains + organization intel.
Multiple sources, concurrent, no hangs.
"""

from __future__ import annotations
import asyncio
import re
from datetime import datetime

from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache, DatabaseManager


class CRTShModule(BaseModule):
    MODULE_NAME = "crtsh"
    DESCRIPTION = "Certificate Transparency log mining — subdomains + org intel"

    async def run(self) -> dict:
        domain = self.target.strip().lower().lstrip("www.").lstrip("*.")
        if "://" in domain: domain = domain.split("://",1)[1].split("/")[0]
        self.log.info(f"CT log mining: {domain}")

        cached = cache.get("crtsh_full", domain)
        if cached and not self.options.get("no_cache"):
            return cached

        # All sources concurrently
        crtsh_data, certspotter_data, hackertarget_data = await asyncio.gather(
            self._crtsh_query(domain),
            self._certspotter(domain),
            self._hackertarget(domain),
            return_exceptions=True,
        )

        all_entries = []
        if isinstance(crtsh_data, list): all_entries.extend(crtsh_data)
        if isinstance(certspotter_data, list): all_entries.extend(certspotter_data)

        # Build subdomain set
        subdomains: set[str] = set()
        wildcards: set[str]  = set()
        orgs: set[str]       = set()
        issuers: dict        = {}
        dates: list          = []

        for entry in all_entries:
            name = entry.get("name","")
            if name.startswith("*."): wildcards.add(name)
            elif name.endswith(f".{domain}") or name == domain:
                subdomains.add(name.lower())
            org = entry.get("org","")
            if org: orgs.add(org)
            issuer = entry.get("issuer","")
            if issuer: issuers[issuer] = issuers.get(issuer,0) + 1
            date = entry.get("date","")
            if date: dates.append(date)

        # Add hackertarget results
        if isinstance(hackertarget_data, set): subdomains.update(hackertarget_data)

        # Find interesting subdomains
        interesting = [s for s in subdomains if any(
            p in s.split(".")[0] for p in [
                "admin","api","dev","staging","test","vpn","internal","portal",
                "mail","smtp","gitlab","jenkins","jira","confluence","kibana",
                "grafana","backup","old","beta","preprod","uat","phpmyadmin"]
        )]

        result = {
            "domain":        domain,
            "subdomains":    sorted(subdomains),
            "wildcards":     sorted(wildcards),
            "organizations": sorted(orgs),
            "interesting":   sorted(interesting),
            "issuers":       dict(sorted(issuers.items(), key=lambda x: -x[1])[:10]),
            "cert_timeline": {
                "first_cert": min(dates) if dates else "",
                "last_cert":  max(dates) if dates else "",
                "total_certs": len(all_entries),
            },
            "total": len(subdomains),
        }

        for s in sorted(subdomains)[:15]: self.log.found("Subdomain", s)
        if wildcards: self.log.found("Wildcards", ", ".join(sorted(wildcards)[:5]))
        if orgs: self.log.found("Organizations", ", ".join(sorted(orgs)[:5]))

        # Persist
        for sub in subdomains:
            await DatabaseManager.insert_subdomain(domain, sub, source="crtsh")

        cache.set("crtsh_full", domain, result)
        return result

    async def _crtsh_query(self, domain: str) -> list:
        entries = []
        try:
            r = await asyncio.wait_for(
                fetch(f"https://crt.sh/?q=%.{domain}&output=json",
                      timeout=15, headers={"Accept": "application/json"}),
                timeout=18,
            )
            if r["ok"] and r["json"]:
                for cert in r["json"]:
                    for name in cert.get("name_value","").split("\n"):
                        name = name.strip().lower()
                        issuer = cert.get("issuer_name","")
                        # Extract org from issuer
                        org = ""
                        m = re.search(r"O=([^,/]+)", issuer)
                        if m: org = m.group(1).strip()
                        entries.append({
                            "name":   name.lstrip("*."),
                            "issuer": issuer[:100],
                            "org":    org,
                            "date":   cert.get("entry_timestamp","")[:10],
                        })
        except Exception:
            pass
        return entries

    async def _certspotter(self, domain: str) -> list:
        entries = []
        try:
            r = await asyncio.wait_for(
                fetch(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names,issuer",
                      timeout=10),
                timeout=12,
            )
            if r["ok"] and r["json"]:
                for cert in r["json"]:
                    issuer = cert.get("issuer",{})
                    issuer_str = issuer.get("organization","") if isinstance(issuer,dict) else str(issuer)
                    for name in cert.get("dns_names",[]):
                        entries.append({
                            "name":   name.lower().lstrip("*."),
                            "issuer": issuer_str,
                            "org":    issuer_str,
                            "date":   cert.get("not_before","")[:10],
                        })
        except Exception:
            pass
        return entries

    async def _hackertarget(self, domain: str) -> set:
        subs: set = set()
        try:
            r = await asyncio.wait_for(
                fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=8),
                timeout=10,
            )
            if r["ok"] and r["text"]:
                for line in r["text"].splitlines():
                    parts = line.split(",")
                    if parts:
                        name = parts[0].strip().lower()
                        if name.endswith(f".{domain}"):
                            subs.add(name)
        except Exception:
            pass
        return subs
