"""
ProjectZ - Production Engine v2.0
- Concurrent module execution (asyncio.gather across all modules)
- Real-time progress tracking with ETA
- Target type auto-detection → smart module routing
- API key preflight check at startup
- Auto-persist all findings to DB (subdomains, emails, ports, IOCs, people)
- Session tracking with start/end timestamps
"""

from __future__ import annotations

import asyncio
import importlib
import json
import time
from typing import Any, Optional

from colorama import Fore, Style

from src.core.config import config
from src.core.http_client import detect_target_type, check_api_keys
from src.core.logger import OSINTLogger, console, print_module_start, print_module_done, print_module_error
from src.core.output import OutputManager
from src.core.storage import DatabaseManager, ResultsManager

log = OSINTLogger("core.engine")
ENGINE_VERSION = "2.0.0"

# ── Module Registry ───────────────────────────────────────────────────────
MODULE_REGISTRY: dict[str, tuple[str, str]] = {
    "whois":      ("src.modules.domain.whois",        "WhoisModule"),
    "dns":        ("src.modules.domain.dns_records",  "DNSModule"),
    "subdomains": ("src.modules.domain.subdomains",   "SubdomainModule"),
    "ssl":        ("src.modules.domain.ssl_certs",    "SSLModule"),
    "tech":       ("src.modules.domain.tech_stack",   "TechStackModule"),
    "asn":        ("src.modules.domain.asn_info",     "ASNModule"),
    "hosting":    ("src.modules.domain.hosting",      "HostingModule"),
    "reverseip":  ("src.modules.domain.reverse_ip",   "ReverseIPModule"),
    "spfdmarc":   ("src.modules.domain.spf_dmarc",    "SPFDMARCModule"),
    "emails":     ("src.modules.people.emails",          "EmailModule"),
    "phones":     ("src.modules.people.phones",          "PhoneModule"),
    "linkedin":   ("src.modules.people.social_linkedin", "LinkedInModule"),
    "twitter":    ("src.modules.people.social_twitter",  "TwitterModule"),
    "github":     ("src.modules.people.social_github",   "GitHubModule"),
    "usernames":  ("src.modules.people.usernames",       "UsernameModule"),
    "breach":     ("src.modules.people.breach_check",    "BreachModule"),
    "employees":  ("src.modules.people.employee_enum",   "EmployeeModule"),
    "portscan":   ("src.modules.network.nmap_wrapper",   "NmapModule"),
    "masscan":    ("src.modules.network.masscan",        "MasscanModule"),
    "geo":        ("src.modules.network.geolocation",    "GeoModule"),
    "iprep":      ("src.modules.network.ip_reputation",  "IPReputationModule"),
    "shodan":     ("src.modules.network.shodan_alt",     "ShodanAltModule"),
    "censys":     ("src.modules.network.censys_alt",     "CensysAltModule"),
    "banner":     ("src.modules.network.onyphe_alt",     "BannerModule"),
    "zoomeye":    ("src.modules.network.zoomeye_alt",    "ZoomEyeModule"),
    "files":      ("src.modules.dorking.files_enum",      "FilesEnumModule"),
    "admin":      ("src.modules.dorking.admin_panels",    "AdminPanelModule"),
    "errors":     ("src.modules.dorking.error_messages",  "ErrorMsgModule"),
    "creds":      ("src.modules.dorking.credentials",     "CredentialsModule"),
    "vulns":      ("src.modules.dorking.vulns_dorks",     "VulnsDorksModule"),
    "dirbust":    ("src.modules.dorking.directory_brute", "DirBruteModule"),
    "google":     ("src.modules.harvesting.google_harvest",     "GoogleHarvestModule"),
    "bing":       ("src.modules.harvesting.bing_harvest",       "BingHarvestModule"),
    "crtsh":      ("src.modules.harvesting.crtsh",              "CRTShModule"),
    "dnsdump":    ("src.modules.harvesting.dnsdumpster",        "DNSDumpsterModule"),
    "leaks":      ("src.modules.harvesting.leakcheck",          "LeakCheckModule"),
    "histdns":    ("src.modules.harvesting.securitytrails_alt", "HistDNSModule"),
    "hunter":     ("src.modules.harvesting.hunter_alt",         "HunterAltModule"),
    "virustotal": ("src.modules.cybersec.virustotal_alt",  "VTAltModule"),
    "urlscan":    ("src.modules.cybersec.urlscanio_alt",   "URLScanModule"),
    "hibp":       ("src.modules.cybersec.haveibeenpwned",  "HIBPModule"),
    "pastebin":   ("src.modules.cybersec.pastebin_dump",   "PastebinModule"),
    "exploitdb":  ("src.modules.cybersec.exploitdb",       "ExploitDBModule"),
    "otx":        ("src.modules.cybersec.otx_alt",         "OTXModule"),
    "abuseipdb":  ("src.modules.cybersec.abuseipdb_alt",   "AbuseIPDBModule"),
    "urlhaus":    ("src.modules.cybersec.urlhaus",         "URLHausModule"),
    "intelx":     ("src.modules.cybersec.intelx_alt",      "IntelXModule"),
    "yara":       ("src.modules.cybersec.hybrid_alt",      "YARAModule"),
    "threatcrowd":("src.modules.cybersec.threatcrowd_alt", "ThreatCrowdModule"),
    "packetstorm":("src.modules.cybersec.packetstorm",     "PacketstormModule"),
    "fiveeyes":   ("src.modules.cybersec.fiveeyes",        "FiveEyesModule"),
    # ── New modules added in v1.0 ─────────────────────────────────────────
    "waf":        ("src.modules.network.waf_detect",       "WAFDetectModule"),
    "headers":    ("src.modules.domain.headers_check",     "HeadersCheckModule"),
    "cors":       ("src.modules.domain.cors_check",        "CORSCheckModule"),
    "cms":        ("src.modules.domain.cms_detect",        "CMSDetectModule"),
    "s3buckets":  ("src.modules.harvesting.s3_buckets",    "S3BucketModule"),
}

MODULE_GROUPS: dict[str, list[str]] = {
    "domain":     ["whois","dns","subdomains","ssl","tech","asn","hosting","spfdmarc",
                   "headers","cors","cms","reverseip"],
    "people":     ["emails","phones","linkedin","twitter","github","usernames","breach","employees"],
    "network":    ["portscan","masscan","geo","iprep","shodan","censys","zoomeye","banner","waf"],
    "dorking":    ["files","admin","errors","creds","vulns","dirbust"],
    "harvesting": ["google","bing","crtsh","dnsdump","leaks","histdns","hunter","s3buckets"],
    "cybersec":   ["virustotal","urlscan","hibp","otx","abuseipdb","urlhaus","exploitdb",
                   "pastebin","intelx","threatcrowd","packetstorm","yara","fiveeyes"],
    "quick":      ["whois","dns","subdomains","ssl","emails","tech","geo","waf","headers"],
    "full":       list(MODULE_REGISTRY.keys()),
}

# ── Smart target routing: which modules make sense for each target type ───
TARGET_TYPE_GROUPS: dict[str, list[str]] = {
    "domain":     ["whois","dns","subdomains","ssl","tech","asn","hosting","spfdmarc",
                   "headers","cors","cms","waf",
                   "emails","employees","breach","google","bing","crtsh","dnsdump",
                   "leaks","histdns","hunter","s3buckets","virustotal","urlscan","hibp","pastebin"],
    "ipv4":       ["geo","iprep","abuseipdb","shodan","censys","banner","portscan",
                   "zoomeye","otx","urlhaus","threatcrowd","reverseip","asn"],
    "ipv6":       ["geo","iprep","abuseipdb","shodan","censys","reverseip","asn"],
    "email":      ["breach","hibp","leaks","emails","people","hunter"],
    "hash_md5":   ["virustotal","yara","urlhaus","otx","hybridanalysis"],
    "hash_sha1":  ["virustotal","yara","urlhaus","otx"],
    "hash_sha256":["virustotal","yara","urlhaus","otx","hybridanalysis"],
    "url":        ["virustotal","urlscan","urlhaus","abuseipdb","otx","google"],
    "username":   ["usernames","github","twitter","linkedin","social"],
}


def _resolve_dotted(token: str) -> list[str]:
    if "." not in token:
        if token in MODULE_GROUPS:  return MODULE_GROUPS[token]
        if token in MODULE_REGISTRY: return [token]
        raise ValueError(f"Unknown module or group: {token!r}")
    group, sub = token.split(".", 1)
    if sub == "all":
        if group not in MODULE_GROUPS:
            raise ValueError(f"Unknown group: {group!r}")
        return MODULE_GROUPS[group]
    if sub in MODULE_REGISTRY: return [sub]
    raise ValueError(f"Unknown module {sub!r}  (group {group!r})\n"
                     f"  Run: python3 projectz.py modules  to see all modules")


def resolve_modules(tokens) -> list[str]:
    if isinstance(tokens, str):
        tokens = [t.strip() for t in tokens.replace(",", " ").split()]
    result, seen = [], set()
    for tok in tokens:
        for name in _resolve_dotted(tok):
            if name not in seen:
                seen.add(name); result.append(name)
    return result


def smart_modules_for(target: str) -> list[str]:
    """Auto-select appropriate modules based on target type."""
    ttype = detect_target_type(target)
    mods  = TARGET_TYPE_GROUPS.get(ttype, MODULE_GROUPS["quick"])
    return [m for m in mods if m in MODULE_REGISTRY]


# ── Base Module ───────────────────────────────────────────────────────────
class BaseModule:
    MODULE_NAME: str = ""
    DESCRIPTION: str = ""

    def __init__(self, target: str, options: dict = None):
        self.target  = target
        self.options = options or {}
        self.log     = OSINTLogger(self.MODULE_NAME or self.__class__.__name__)

    async def run(self) -> dict:
        raise NotImplementedError(f"{self.__class__.__name__}.run() not implemented")

    async def execute(self) -> dict:
        t0 = time.monotonic()
        try:
            result = await self.run()
        except Exception as e:
            self.log.error(f"{self.MODULE_NAME} failed: {e}")
            result = {"domain": self.target, "total": 0, "error": str(e)}
        result["_elapsed"] = round(time.monotonic() - t0, 2)
        return result

    # ── Shared helpers (available in every module — no need to redefine) ──
    def _clean(self, t: str) -> str:
        """Strip protocol/www prefix, return bare hostname."""
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p):
                t = t[len(p):]
        return t.split("/")[0].split("?")[0].split("#")[0]

    def _is_ip(self, s: str) -> bool:
        import re as _re
        return bool(_re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(s).strip()))

    async def _to_ip(self, target: str) -> str:
        """Resolve domain → IPv4. Returns '' on failure."""
        import asyncio as _asyncio, socket as _socket
        if self._is_ip(target):
            return target
        loop = _asyncio.get_event_loop()
        try:
            return await _asyncio.wait_for(
                loop.run_in_executor(None, _socket.gethostbyname, target),
                timeout=6,
            )
        except Exception:
            return ""

    async def _resolve(self, target: str) -> str:
        """Alias for _to_ip — backward compat for modules that use _resolve."""
        return await self._to_ip(target)

    async def _persist_db(self, result: dict) -> None:
        """
        Persist key findings to database.
        Called by modules after run() completes.
        This single correct implementation replaces the 29 identical buggy
        copies that were scattered across modules.
        """
        if not isinstance(result, dict):
            return
        from src.core.storage import DatabaseManager
        try:
            # ── Subdomains ──────────────────────────────────────────────────
            for sub in result.get("subdomains", []):
                if isinstance(sub, str) and sub:
                    await DatabaseManager.insert_subdomain(
                        self.target, sub, source=self.MODULE_NAME)
                elif isinstance(sub, dict):
                    await DatabaseManager.insert_subdomain(
                        self.target,
                        sub.get("subdomain", sub.get("name", "")),
                        ip=sub.get("ip", ""),
                        source=self.MODULE_NAME)

            # ── Emails ──────────────────────────────────────────────────────
            for em in result.get("emails", result.get("commit_emails", [])):
                addr = em.get("email", em) if isinstance(em, dict) else em
                if isinstance(addr, str) and "@" in addr:
                    await DatabaseManager.insert_email(
                        addr.lower(), domain=self.target, source=self.MODULE_NAME)

            # ── Open ports ──────────────────────────────────────────────────
            for port in result.get("open_ports", []):
                if isinstance(port, int):
                    await DatabaseManager.insert_port(self.target, port)
                elif isinstance(port, dict) and port.get("port"):
                    await DatabaseManager.insert_port(
                        self.target,
                        port=port["port"],
                        protocol=port.get("protocol", "tcp"),
                        service=port.get("service", ""),
                        version=port.get("version", ""),
                        banner=port.get("banner", ""))

            # ── IOCs ─────────────────────────────────────────────────────────
            for ioc in result.get("malicious_urls", result.get("iocs", [])):
                val = ioc if isinstance(ioc, str) else ioc.get("url", str(ioc))
                if val:
                    await DatabaseManager.insert_ioc(
                        "url", val, source=self.MODULE_NAME)

            # ── Findings (critical + high) ──────────────────────────────────
            crits = result.get("critical_findings", [])
            highs = result.get("high_findings", [])
            for finding in crits + highs:
                if not isinstance(finding, dict):
                    continue
                sev = "critical" if finding in crits else "high"
                await DatabaseManager.insert_finding(
                    target=self.target,
                    module=self.MODULE_NAME,
                    title=finding.get("title", finding.get("label", "Finding"))[:200],
                    severity=sev,
                    url=str(finding.get("url", finding.get("evidence", "")))[:500])

            # ── People ──────────────────────────────────────────────────────
            for person in result.get("people", []):
                if isinstance(person, dict):
                    await DatabaseManager.insert_person(
                        domain=self.target,
                        full_name=person.get("name", ""),
                        email=person.get("email", ""),
                        role=person.get("role", ""),
                        linkedin=person.get("linkedin", ""),
                        source=self.MODULE_NAME)
        except Exception:
            pass



# ── Progress Tracker ──────────────────────────────────────────────────────
class _Progress:
    def __init__(self, total: int):
        self.total    = total
        self.done     = 0
        self.start_ts = time.monotonic()
        self._lock    = asyncio.Lock()

    async def tick(self, name: str, ok: bool, found: int, elapsed: float):
        async with self._lock:
            self.done += 1
            pct    = int(self.done / self.total * 100)
            filled = pct // 5
            bar    = f"{Fore.GREEN}{'█' * filled}{Style.DIM}{'░' * (20 - filled)}{Style.RESET_ALL}"
            icon   = f"{Fore.GREEN}+{Style.RESET_ALL}" if ok else f"{Fore.RED}-{Style.RESET_ALL}"
            ts     = time.strftime("%H:%M:%S")
            eta_s  = ""
            if self.done > 0 and self.done < self.total:
                rate  = (time.monotonic() - self.start_ts) / self.done
                eta   = rate * (self.total - self.done)
                eta_s = f"  {Style.DIM}ETA {int(eta)}s{Style.RESET_ALL}" if eta > 1 else ""
            found_col = f"{Fore.GREEN}{found}{Style.RESET_ALL}" if found > 0 else f"{Style.DIM}{found}{Style.RESET_ALL}"
            print(
                f"  {Style.DIM}{ts}{Style.RESET_ALL} "
                f"[{icon}] [{self.done:>2}/{self.total}] "
                f"[{bar}] {pct:>3}%  "
                f"{Fore.CYAN}{Style.BRIGHT}{name:<14}{Style.RESET_ALL}"
                f"  {found_col} results  "
                f"{Style.DIM}{elapsed}s{Style.RESET_ALL}{eta_s}"
            )


# ── Engine ────────────────────────────────────────────────────────────────
class Engine:
    def __init__(self, target: str, output_format: str = "json",
                 output_file: str = None, verbose: bool = False,
                 timeout: int = None, concurrent: bool = True,
                 max_workers: int = 10):
        self.target        = target
        self.output_format = output_format
        self.output_file   = output_file
        self.verbose       = verbose
        self.timeout       = timeout or config.REQUEST_TIMEOUT
        self.concurrent    = concurrent
        self.max_workers   = max_workers
        self.results: dict = {}
        self._session_id   = 0
        self.target_type   = detect_target_type(target)

    def _load_module(self, name: str) -> Optional[BaseModule]:
        if name not in MODULE_REGISTRY:
            log.error(f"Module not found: {name!r}")
            return None
        path, cls_name = MODULE_REGISTRY[name]
        try:
            mod = importlib.import_module(path)
            cls = getattr(mod, cls_name)
            return cls(target=self.target)
        except ImportError as e:
            log.error(f"Import {path}: {e}")
            return None
        except AttributeError as e:
            log.error(f"Class {cls_name} in {path}: {e}")
            return None

    async def run_modules(self, module_names: list[str]) -> dict:
        total = len(module_names)
        self._session_id = DatabaseManager.start_session(self.target, module_names)

        ttype = self.target_type
        print(f"\n{Fore.CYAN}{Style.BRIGHT}  Target     :{Style.RESET_ALL} {self.target}  "
              f"{Fore.WHITE}[{ttype}]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}  Modules    :{Style.RESET_ALL} {total}  "
              f"{Fore.WHITE}({'concurrent' if self.concurrent else 'sequential'}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}  Session    :{Style.RESET_ALL} #{self._session_id}\n")

        log.info(f"Session #{self._session_id} — target={self.target} "
                 f"type={ttype} modules={total} concurrent={self.concurrent}")

        progress = _Progress(total)
        results  = {}

        if self.concurrent:
            results = await self._run_concurrent(module_names, progress)
        else:
            results = await self._run_sequential(module_names, progress)

        self.results = results
        return results

    async def _run_concurrent(self, names: list[str],
                               progress: _Progress) -> dict:
        """Run all modules concurrently with a semaphore cap."""
        sem = asyncio.Semaphore(self.max_workers)
        results = {}
        MODULE_TIMEOUT = 120   # max 120s per module — never freeze forever

        async def _run_one(name: str):
            mod = self._load_module(name)
            if mod is None:
                return name, {"total": 0, "error": "Module load failed", "_elapsed": 0}
            ts = time.strftime("%H:%M:%S"); print(f"  {Style.DIM}{ts}{Style.RESET_ALL} {Fore.CYAN}[*]{Style.RESET_ALL}  {name:<16}", flush=True)
            async with sem:
                try:
                    result = await asyncio.wait_for(mod.execute(), timeout=MODULE_TIMEOUT)
                except asyncio.TimeoutError:
                    result = {"total": 0,
                              "error": f"Timed out after {MODULE_TIMEOUT}s",
                              "_elapsed": MODULE_TIMEOUT}
            await self._persist(name, result)
            await progress.tick(
                name, not result.get("error"),
                result.get("total", 0), result.get("_elapsed", 0)
            )
            if self.verbose:
                OutputManager.print_result(name, result)
            return name, result

        tasks = [asyncio.create_task(_run_one(n)) for n in names]
        for coro in asyncio.as_completed(tasks):
            name, result = await coro
            results[name] = result
            await DatabaseManager.save_scan(self.target, name, result)
            err = result.get("error","")
            if err: log.error(f"{name}: {err[:100]}")
            else:   log.found(name, f"{result.get('total',0)} results in {result.get('_elapsed',0)}s")

        return results

    async def _run_sequential(self, names: list[str],
                               progress: _Progress) -> dict:
        """Run modules one at a time (use when --no-concurrent)."""
        results = {}
        MODULE_TIMEOUT = 120

        for name in names:
            mod = self._load_module(name)
            if mod is None:
                results[name] = {"total": 0, "error": "Module load failed", "_elapsed": 0}
                continue
            ts = time.strftime("%H:%M:%S"); print(f"  {Style.DIM}{ts}{Style.RESET_ALL} {Fore.CYAN}[*]{Style.RESET_ALL}  {name:<16}", flush=True)
            try:
                result = await asyncio.wait_for(mod.execute(), timeout=MODULE_TIMEOUT)
            except asyncio.TimeoutError:
                result = {"total": 0,
                          "error": f"Timed out after {MODULE_TIMEOUT}s",
                          "_elapsed": MODULE_TIMEOUT}
            results[name] = result
            await self._persist(name, result)
            await DatabaseManager.save_scan(self.target, name, result)
            await progress.tick(
                name, not result.get("error"),
                result.get("total", 0), result.get("_elapsed", 0)
            )
            if self.verbose:
                OutputManager.print_result(name, result)
        return results

    async def _persist(self, module: str, result: dict):
        """Auto-extract and save all typed findings to correct DB tables."""
        if not isinstance(result, dict): return
        t = self.target

        for sub in result.get("subdomains", []):
            if isinstance(sub, str): await DatabaseManager.insert_subdomain(t, sub, source=module)
            elif isinstance(sub, dict):
                await DatabaseManager.insert_subdomain(
                    t, sub.get("subdomain", sub.get("name", "")),
                    ip=sub.get("ip",""), source=module)

        for em in result.get("emails", []):
            addr = em.get("email", em) if isinstance(em, dict) else em
            if "@" in str(addr): await DatabaseManager.insert_email(str(addr), domain=t, source=module)

        for p in result.get("open_ports", []):
            if isinstance(p, dict):
                await DatabaseManager.insert_port(
                    t, port=p.get("port",0), protocol=p.get("protocol","tcp"),
                    service=p.get("service",""), version=p.get("version",""),
                    banner=p.get("banner",""))
            elif isinstance(p, int):
                await DatabaseManager.insert_port(t, port=p)

        for ioc in result.get("iocs", []):
            if isinstance(ioc, dict):
                await DatabaseManager.insert_ioc(
                    ioc_type=ioc.get("type","unknown"), value=ioc.get("value",""),
                    source=module, severity=ioc.get("severity","info"), metadata=ioc)

        risk = result.get("risk_score", 0)
        verdict = result.get("verdict", "")
        if risk >= 50 or verdict in ("MALICIOUS","SUSPICIOUS"):
            await DatabaseManager.insert_finding(
                target=t, module=module,
                title=f"{module.upper()}: {verdict or 'High Risk'}",
                description=f"Risk score: {risk}",
                severity="critical" if risk>=75 else "high",
                evidence=str(result.get("malware_families", result.get("flagging_vendors","")))[:300])

        for f in result.get("critical_findings", []) + result.get("high_findings", []):
            sev = "critical" if f in result.get("critical_findings",[]) else "high"
            url = f.get("url","") if isinstance(f, dict) else str(f)
            ttl = f.get("title", url) if isinstance(f, dict) else str(f)
            await DatabaseManager.insert_finding(
                target=t, module=module, title=ttl[:200],
                severity=sev, url=url[:500])

        for person in result.get("people", []):
            if isinstance(person, dict):
                await DatabaseManager.insert_person(
                    domain=t, full_name=person.get("name",""),
                    email=person.get("email",""), role=person.get("role",""),
                    linkedin=person.get("linkedin",""), source=module)

        if module == "whois" and not result.get("error"):
            await DatabaseManager.upsert_domain(
                t, registrar=result.get("registrar",""),
                created=str(result.get("creation_date","")),
                expires=str(result.get("expiration_date","")),
                nameservers=_jdump(result.get("nameservers",[])))

    def save_output(self) -> str:
        if not self.results: return ""
        db_summary = DatabaseManager.get_target_summary(self.target)
        if self.output_format == "html":
            path = OutputManager.save_html(self.target, self.results, db_summary, self.output_file)
        elif self.output_format == "txt":
            path = OutputManager.save_txt(self.target, self.results, self.output_file)
        elif self.output_format == "csv":
            path = OutputManager.save_csv(self.target, self.results, self.output_file)
        else:
            path = OutputManager.save_json(self.target, self.results, self.output_file)
        DatabaseManager.end_session(self._session_id, path)
        log.info(f"Session #{self._session_id} complete → {path}")
        return path


def _jdump(v) -> str:
    try: return json.dumps(v, default=str)
    except: return str(v)
