"""
ProjectZ - WHOIS Module v2
Sources: Raw WHOIS socket (port 43) + RDAP API + IANA fallback
All with proper timeouts, no hangs.
"""

import asyncio
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache, DatabaseManager

_executor = ThreadPoolExecutor(max_workers=10)


class WhoisModule(BaseModule):
    MODULE_NAME = "whois"
    DESCRIPTION = "Full WHOIS lookup — registrar, dates, nameservers, contacts"

    # WHOIS server map for common TLDs
    WHOIS_SERVERS = {
        "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",          "io":  "whois.nic.io",
        "co":  "whois.nic.co",           "uk":  "whois.nic.uk",
        "de":  "whois.denic.de",         "fr":  "whois.nic.fr",
        "nl":  "whois.domain-registry.nl", "au": "whois.auda.org.au",
        "ca":  "whois.cira.ca",          "us":  "whois.nic.us",
        "info":"whois.afilias.net",       "biz": "whois.biz",
        "me":  "whois.nic.me",           "in":  "whois.registry.in",
        "ru":  "whois.tcinet.ru",        "cn":  "whois.cnnic.cn",
        "jp":  "whois.jprs.jp",          "br":  "whois.registro.br",
        "dev": "whois.nic.google",       "app": "whois.nic.google",
        "tech":"whois.nic.tech",         "ai":  "whois.nic.ai",
        "xyz": "whois.nic.xyz",
    }

    async def run(self) -> dict:
        domain = self.target.strip().lower()
        if "://" in domain: domain = domain.split("://",1)[1].split("/")[0]
        self.log.info(f"WHOIS lookup: {domain}")

        cached = cache.get("whois", domain)
        if cached and not self.options.get("no_cache"):
            self.log.info("Returning cached WHOIS data")
            return cached

        result = {"domain": domain, "registrar": "", "registrant_org": "",
                  "registrant_country": "", "creation_date": "", "expiration_date": "",
                  "updated_date": "", "nameservers": [], "emails": [],
                  "status": [], "dnssec": "unsigned", "raw": ""}

        # Try all sources concurrently
        raw_whois, rdap_data = await asyncio.gather(
            self._raw_whois(domain),
            self._rdap(domain),
            return_exceptions=True,
        )

        # Parse raw WHOIS
        if isinstance(raw_whois, str) and raw_whois:
            result["raw"] = raw_whois[:3000]
            self._parse_whois(raw_whois, result)
            self.log.found("Registrar", result.get("registrar","?"))

        # RDAP fills missing fields
        if isinstance(rdap_data, dict) and rdap_data:
            self._merge_rdap(rdap_data, result)

        # Count total populated fields
        filled = sum(1 for v in result.values()
                     if v and v not in ("unsigned",""))
        result["total"] = filled

        if result.get("registrar"):
            self.log.found("Registrar", result["registrar"])
        if result.get("creation_date"):
            self.log.found("Created", result["creation_date"])
        if result.get("expiration_date"):
            self.log.found("Expires", result["expiration_date"])
        if result.get("nameservers"):
            self.log.found("Nameservers", ", ".join(result["nameservers"][:3]))

        # Persist domain info
        await DatabaseManager.upsert_domain(
            domain,
            registrar   = result.get("registrar",""),
            created     = str(result.get("creation_date","")),
            expires     = str(result.get("expiration_date","")),
            nameservers = json.dumps(result.get("nameservers",[])),
        )

        cache.set("whois", domain, result)
        return result

    async def _raw_whois(self, domain: str) -> str:
        """Raw WHOIS query via TCP socket."""
        tld = domain.rsplit(".",1)[-1].lower()
        server = self.WHOIS_SERVERS.get(tld, "whois.iana.org")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, 43), timeout=8
            )
            writer.write(f"{domain}\r\n".encode())
            await asyncio.wait_for(writer.drain(), timeout=3)
            raw = await asyncio.wait_for(reader.read(65535), timeout=10)
            writer.close()
            text = raw.decode("utf-8", errors="ignore")
            # If response says "refer: X", follow referral once
            for line in text.splitlines():
                if line.lower().startswith("refer:"):
                    ref_server = line.split(":",1)[1].strip()
                    if ref_server and ref_server != server:
                        try:
                            r2, w2 = await asyncio.wait_for(
                                asyncio.open_connection(ref_server, 43), timeout=8
                            )
                            w2.write(f"{domain}\r\n".encode())
                            await asyncio.wait_for(w2.drain(), timeout=3)
                            raw2 = await asyncio.wait_for(r2.read(65535), timeout=10)
                            w2.close()
                            text = raw2.decode("utf-8", errors="ignore")
                        except Exception:
                            pass
                    break
            return text
        except asyncio.TimeoutError:
            return ""
        except Exception as e:
            self.log.debug(f"Raw WHOIS error: {e}")
            return ""

    async def _rdap(self, domain: str) -> dict:
        """RDAP lookup — structured JSON response."""
        urls = [
            f"https://rdap.org/domain/{domain}",
            f"https://rdap.verisign.com/com/v1/domain/{domain}",
        ]
        for url in urls:
            try:
                r = await asyncio.wait_for(
                    fetch(url, timeout=8, headers={"Accept":"application/rdap+json"}),
                    timeout=10,
                )
                if r["ok"] and r["json"]:
                    return r["json"]
            except Exception:
                continue
        return {}

    def _parse_whois(self, text: str, result: dict):
        patterns = {
            "registrar":        [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"],
            "creation_date":    [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)"],
            "expiration_date":  [r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)", r"expires:\s*(.+)"],
            "updated_date":     [r"Updated Date:\s*(.+)", r"last-modified:\s*(.+)"],
            "registrant_org":   [r"Registrant Organization:\s*(.+)", r"org:\s*(.+)"],
            "registrant_country":[r"Registrant Country:\s*(.+)", r"country:\s*(.+)"],
            "dnssec":           [r"DNSSEC:\s*(.+)"],
        }
        for field, pats in patterns.items():
            for pat in pats:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    val = m.group(1).strip()
                    if val and val.lower() not in ("redacted for privacy","not disclosed"):
                        result[field] = val[:200]
                        break

        # Nameservers
        ns_list = re.findall(r"Name Server:\s*(.+)", text, re.IGNORECASE)
        if not ns_list:
            ns_list = re.findall(r"nserver:\s*(.+)", text, re.IGNORECASE)
        result["nameservers"] = [ns.strip().lower().rstrip(".") for ns in ns_list[:8]]

        # Status
        statuses = re.findall(r"Domain Status:\s*(.+)", text, re.IGNORECASE)
        result["status"] = [s.strip().split()[0] for s in statuses[:5]]

        # Emails
        emails = list(set(re.findall(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", text, re.IGNORECASE)))
        result["emails"] = [e.lower() for e in emails if "abuse" not in e.lower()][:5]

    def _merge_rdap(self, rdap: dict, result: dict):
        if not result.get("registrar"):
            for e in rdap.get("entities", []):
                roles = e.get("roles", [])
                if "registrar" in roles:
                    vcard = e.get("vcardArray", [])
                    for item in vcard[1] if len(vcard)>1 else []:
                        if isinstance(item, list) and item[0] == "fn":
                            result["registrar"] = str(item[3])[:100]
                            break

        if not result.get("creation_date"):
            for ev in rdap.get("events", []):
                if ev.get("eventAction") == "registration":
                    result["creation_date"] = ev.get("eventDate","")[:10]
                elif ev.get("eventAction") == "expiration":
                    result["expiration_date"] = ev.get("eventDate","")[:10]

        if not result.get("nameservers"):
            result["nameservers"] = [
                ns.get("ldhName","").lower()
                for ns in rdap.get("nameservers", [])
                if ns.get("ldhName")
            ][:8]
