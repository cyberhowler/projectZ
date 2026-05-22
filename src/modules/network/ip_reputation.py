"""
ProjectZ - IP Reputation Module v2
5 free sources, all concurrent, no API keys required for basics.
Never hangs — all wrapped with asyncio.wait_for.
"""
import asyncio
import re
import socket

from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class IPReputationModule(BaseModule):
    MODULE_NAME = "iprep"
    DESCRIPTION = "IP reputation — abuse score, blocklists, open ports, CVEs"


    async def _to_ip(self, target: str) -> str:
        """Resolve domain to IP. Tries OS DNS first, then DoH HTTP fallback."""
        import re as _re
        if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
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
        from src.core.http_client import fetch
        for doh in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
            try:
                import asyncio as _a2
                r = await _a2.wait_for(
                    fetch(doh, params={"name": target, "type": "A"},
                          headers={"Accept": "application/dns-json"}, timeout=5),
                    timeout=6)
                if r.get("ok") and r.get("json"):
                    for ans in r["json"].get("Answer", []):
                        if ans.get("type") == 1:
                            return ans.get("data", "")
            except Exception:
                continue
        return ""


    async def run(self) -> dict:
        target = self.target.strip()
        # Resolve to IP if domain
        ip = await self._to_ip(target)
        self.log.info(f"IP reputation check: {ip}")

        if not ip:
            return {"target": target, "error": "Could not resolve IP", "total": 0}

        cached = cache.get("iprep", ip)
        if cached and not self.options.get("no_cache"):
            return cached

        # All sources concurrently
        results = await asyncio.gather(
            self._shodan_interdb(ip),
            self._abuseipdb(ip),
            self._greynoise(ip),
            self._spamhaus(ip),
            self._virustotal_ip(ip),
            return_exceptions=True,
        )

        names = ["shodan","abuseipdb","greynoise","spamhaus","virustotal"]
        merged = {
            "target": target, "ip": ip,
            "abuse_score": 0, "total_reports": 0,
            "categories": [], "is_whitelisted": False,
            "open_ports": [], "cves": [], "services": {},
            "blocklists": [], "tags": [], "verdict": "UNKNOWN",
            "sources": {}
        }

        for name, r in zip(names, results):
            if isinstance(r, Exception):
                merged["sources"][name] = {"error": str(r)[:50]}
                continue
            if isinstance(r, dict) and r:
                merged["sources"][name] = r
                # Merge key fields
                if name == "shodan" and r.get("open_ports"):
                    merged["open_ports"].extend(r["open_ports"])
                    merged["cves"].extend(r.get("cves",[]))
                    merged["services"].update(r.get("services",{}))
                    merged["tags"].extend(r.get("tags",[]))
                if name == "abuseipdb":
                    merged["abuse_score"]   = max(merged["abuse_score"], r.get("abuse_confidence",0))
                    merged["total_reports"] = max(merged["total_reports"], r.get("total_reports",0))
                    cats = r.get("categories",[])
                    merged["categories"] = list(set(merged["categories"] + cats))
                    if r.get("is_whitelisted"): merged["is_whitelisted"] = True
                if name == "greynoise" and r.get("tags"):
                    merged["tags"].extend(r["tags"])
                if name == "spamhaus" and r.get("listed"):
                    merged["blocklists"].append("Spamhaus ZEN")

        # Dedup
        merged["open_ports"] = sorted(set(merged["open_ports"]))
        merged["cves"]       = list(set(merged["cves"]))[:20]
        merged["tags"]       = list(set(merged["tags"]))[:15]

        # Verdict
        score = merged["abuse_score"]
        if score >= 75 or len(merged["cves"]) > 3:
            merged["verdict"] = "MALICIOUS"
        elif score >= 25 or merged["blocklists"]:
            merged["verdict"] = "SUSPICIOUS"
        elif score == 0 and merged["is_whitelisted"]:
            merged["verdict"] = "CLEAN"
        else:
            merged["verdict"] = "NEUTRAL"

        merged["total"] = len(merged["open_ports"]) + len(merged["cves"])

        # Log key findings
        self.log.found("IP", ip)
        self.log.found("Abuse Score", f"{score}%")
        self.log.found("Verdict", merged["verdict"])
        if merged["open_ports"]:
            self.log.found("Open Ports", str(merged["open_ports"][:10]))
        if merged["cves"]:
            self.log.warning(f"CVEs found: {', '.join(merged['cves'][:5])}")

        cache.set("iprep", ip, merged)
        return merged

    async def _resolve(self, target: str) -> str:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target): return target
        try:
            loop = asyncio.get_event_loop()
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=1) as ex:
                r = await asyncio.wait_for(
                    loop.run_in_executor(ex, socket.getaddrinfo, target, None, socket.AF_INET),
                    timeout=3.0)
                return r[0][4][0]
        except Exception:
            return ""

    async def _shodan_interdb(self, ip: str) -> dict:
        """Shodan InternetDB — free, no key, returns ports/CVEs/tags."""
        try:
            r = await asyncio.wait_for(
                fetch(f"https://internetdb.shodan.io/{ip}", timeout=6,
                      headers={"Accept":"application/json"}),
                timeout=8)
            if r["ok"] and r["json"]:
                d = r["json"]
                return {
                    "open_ports": d.get("ports",[]),
                    "cves":       d.get("vulns",[]),
                    "tags":       d.get("tags",[]),
                    "hostnames":  d.get("hostnames",[]),
                    "services":   {str(p): "unknown" for p in d.get("ports",[])},
                    "source":     "Shodan InternetDB",
                }
        except Exception:
            pass
        return {}

    async def _abuseipdb(self, ip: str) -> dict:
        api_key = getattr(config, "ABUSEIPDB_API_KEY", "")
        if not api_key:
            # Free endpoint (no key — limited)
            try:
                r = await asyncio.wait_for(
                    fetch(f"https://www.abuseipdb.com/check/{ip}",
                          timeout=6, headers={"Accept":"text/html"}),
                    timeout=8)
                if r["ok"]:
                    text = r["text"]
                    score_m = re.search(r"(\d+)%\s*confidence", text, re.I)
                    return {
                        "abuse_confidence": int(score_m.group(1)) if score_m else 0,
                        "total_reports": 0,
                        "source": "AbuseIPDB (no key)",
                    }
            except Exception:
                pass
            return {}
        try:
            r = await asyncio.wait_for(
                fetch("https://api.abuseipdb.com/api/v2/check",
                      params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": api_key, "Accept": "application/json"},
                      timeout=8),
                timeout=10)
            if r["ok"] and r["json"]:
                d = r["json"].get("data",{})
                cats = d.get("reports",[])
                all_cats = []
                for rep in cats[:20]:
                    all_cats.extend(rep.get("categories",[]))
                CAT_NAMES = {
                    3:"Fraud Orders",4:"DDoS Attack",9:"Open Proxy",10:"Web Spam",
                    11:"Email Spam",14:"Port Scan",15:"Hacking",18:"Brute Force",
                    19:"Bad Web Bot",20:"Exploited Host",21:"Web App Attack",
                    22:"SSH",23:"IoT Targeted",
                }
                return {
                    "abuse_confidence": d.get("abuseConfidenceScore",0),
                    "total_reports":    d.get("totalReports",0),
                    "is_whitelisted":   d.get("isWhitelisted",False),
                    "isp":              d.get("isp",""),
                    "usage_type":       d.get("usageType",""),
                    "categories":       list(set(CAT_NAMES.get(c,str(c)) for c in all_cats)),
                    "source":           "AbuseIPDB API",
                }
        except Exception:
            pass
        return {}

    async def _greynoise(self, ip: str) -> dict:
        try:
            r = await asyncio.wait_for(
                fetch(f"https://api.greynoise.io/v3/community/{ip}",
                      timeout=6, headers={"Accept":"application/json"}),
                timeout=8)
            if r["ok"] and r["json"]:
                d = r["json"]
                return {
                    "noise":       d.get("noise",False),
                    "riot":        d.get("riot",False),
                    "tags":        [d.get("name","")] if d.get("name") else [],
                    "classification": d.get("classification",""),
                    "source":      "Greynoise Community",
                }
        except Exception:
            pass
        return {}

    async def _spamhaus(self, ip: str) -> dict:
        """Check Spamhaus ZEN via DNS lookup."""
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.zen.spamhaus.org"
            loop = asyncio.get_event_loop()
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=1) as ex:
                result = await asyncio.wait_for(
                    loop.run_in_executor(ex, socket.gethostbyname, query),
                    timeout=4.0)
            return {"listed": True, "response": result, "source": "Spamhaus ZEN"}
        except Exception:
            return {"listed": False, "source": "Spamhaus ZEN"}

    async def _virustotal_ip(self, ip: str) -> dict:
        api_key = getattr(config, "VIRUSTOTAL_API_KEY", "")
        if not api_key: return {}
        try:
            r = await asyncio.wait_for(
                fetch(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                      headers={"x-apikey": api_key}, timeout=8),
                timeout=10)
            if r["ok"] and r["json"]:
                stats = r["json"].get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                return {
                    "malicious":  stats.get("malicious",0),
                    "suspicious": stats.get("suspicious",0),
                    "source":     "VirusTotal",
                }
        except Exception:
            pass
        return {}