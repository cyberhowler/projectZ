"""
ProjectZ - Correlation Engine
Reads all stored findings from DB after a scan and cross-references them
to surface high-confidence threats that individual modules missed alone.

Examples of correlations made:
  - IP flagged in shodan + OTX + AbuseIPDB → confirmed malicious node
  - Email in breach DB + pastebin → active leak risk
  - Subdomain running outdated service + matching ExploitDB CVE → exploitable
  - Domain in virustotal + urlhaus + phishtank → multi-source malware flag
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from src.core.storage import DatabaseManager
from src.core.logger import OSINTLogger

log = OSINTLogger("correlator")

# Risk weights for multi-source correlation
WEIGHTS = {
    "virustotal_malicious":  40,
    "otx_pulses":            20,
    "abuseipdb_flagged":     25,
    "urlhaus_listed":        30,
    "phishtank_verified":    35,
    "breach_found":          20,
    "pastebin_hit":          15,
    "github_exposure":       25,
    "open_dangerous_port":   15,
    "cve_match":             30,
    "subdomain_exposure":    10,
}

DANGEROUS_PORTS = {
    21: "FTP (cleartext auth)",
    23: "Telnet (cleartext)",
    1433: "MSSQL (exposed DB)",
    3306: "MySQL (exposed DB)",
    3389: "RDP (brute-force target)",
    5432: "PostgreSQL (exposed DB)",
    5900: "VNC (remote desktop)",
    6379: "Redis (auth-less default)",
    9200: "Elasticsearch (unauth access)",
    27017: "MongoDB (auth-less default)",
    2375: "Docker daemon (unauthenticated)",
    50070: "Hadoop NameNode",
    8888: "Jupyter Notebook",
}


class Correlator:
    """Cross-references all DB findings for a target and produces a risk report."""

    def __init__(self, target: str):
        self.target  = target
        self.summary = DatabaseManager.get_target_summary(target)

    def run(self) -> dict:
        log.info(f"Running correlation engine for {self.target}")

        alerts        = []
        risk_score    = 0
        correlations  = []

        # ── 1. Multi-source IOC correlation ──────────────────────────────
        iocs   = self.summary.get("iocs", [])
        scans  = self.summary.get("scans", [])

        # Find modules that flagged malicious/suspicious
        flagging_modules = []
        for scan in scans:
            module = scan.get("module", "")
            # Parse result JSON inline
            if scan.get("status") == "ok":
                for ioc in iocs:
                    if ioc.get("severity") in ("high", "critical"):
                        flagging_modules.append(module)

        # Confirmed malicious only if 2+ threat sources ACTUALLY flagged the target
        # (not just ran — must have returned malicious=True or iocs with high/critical severity)
        threat_modules = []
        for s in scans:
            if s.get("status") != "ok":
                continue
            if s["module"] not in {"virustotal", "otx", "abuseipdb", "urlhaus", "hibp"}:
                continue
            result = s.get("result", {})
            # Check explicit malicious flags
            is_malicious = (
                result.get("is_malicious") is True or
                result.get("malicious") is True or
                result.get("malicious_count", 0) > 0 or
                result.get("abuse_confidence_score", 0) > 50 or
                result.get("threat_score", 0) > 50 or
                any(
                    ioc.get("severity") in ("high", "critical")
                    for ioc in iocs
                    if ioc.get("module") == s["module"]
                )
            )
            if is_malicious:
                threat_modules.append(s["module"])

        if len(set(threat_modules)) >= 2:
            score_add = 35
            risk_score += score_add
            alerts.append({
                "level":   "critical",
                "title":   "Multi-source threat confirmation",
                "detail":  f"Target flagged MALICIOUS by {len(set(threat_modules))} independent "
                           f"threat intel sources: {', '.join(sorted(set(threat_modules)))}",
                "modules": list(set(threat_modules)),
                "score_contribution": score_add,
            })
            correlations.append(("multi_source_ioc", list(set(threat_modules))))

        # ── 2. Breach + paste correlation ────────────────────────────────
        findings    = self.summary.get("findings", [])
        breach_find = [f for f in findings if "breach" in f.get("module","").lower()
                       or "hibp" in f.get("module","").lower()]
        paste_find  = [f for f in findings if "pastebin" in f.get("module","").lower()
                       or "leaks" in f.get("module","").lower()]

        if breach_find and paste_find:
            risk_score += 30
            alerts.append({
                "level":  "critical",
                "title":  "Active leak: breach data + paste exposure",
                "detail": f"Credentials found in {len(breach_find)} breach source(s) AND "
                          f"{len(paste_find)} paste/leak source(s). Active exposure risk.",
                "modules": ["breach","hibp","pastebin","leaks"],
                "score_contribution": 30,
            })
            correlations.append(("breach_paste_overlap", True))

        # ── 3. Dangerous open ports ───────────────────────────────────────
        ports = self.summary.get("ports", [])
        dangerous_open = [
            (p["port"], DANGEROUS_PORTS[p["port"]])
            for p in ports
            if p.get("port") in DANGEROUS_PORTS
        ]
        if dangerous_open:
            score_add = min(len(dangerous_open) * 15, 45)
            risk_score += score_add
            for port, service in dangerous_open[:5]:
                alerts.append({
                    "level":  "high",
                    "title":  f"Dangerous port exposed: {port}/tcp ({service})",
                    "detail": f"Port {port} ({service}) is publicly accessible. "
                              f"This service type is frequently targeted by automated attacks.",
                    "modules": ["portscan"],
                    "score_contribution": 15,
                })
            correlations.append(("dangerous_ports", dangerous_open))

        # ── 4. Subdomain exposure patterns ────────────────────────────────
        subdomains  = self.summary.get("subdomains", [])
        sub_names   = [s.get("subdomain","") for s in subdomains]
        risky_subs  = [s for s in sub_names if any(
            kw in s.lower() for kw in
            ["dev","staging","test","qa","admin","jenkins","gitlab","jira",
             "confluence","kibana","grafana","vpn","internal","intranet"]
        )]
        if risky_subs:
            score_add = min(len(risky_subs) * 5, 20)
            risk_score += score_add
            alerts.append({
                "level":  "medium",
                "title":  f"{len(risky_subs)} sensitive subdomain(s) exposed",
                "detail": f"Subdomains indicating internal/dev/admin infrastructure: "
                          f"{', '.join(risky_subs[:8])}",
                "modules": ["subdomains"],
                "score_contribution": score_add,
            })
            correlations.append(("sensitive_subdomains", risky_subs[:10]))

        # ── 5. Email exposure ─────────────────────────────────────────────
        emails = self.summary.get("emails", [])
        if len(emails) >= 5:
            risk_score += 10
            alerts.append({
                "level":  "medium",
                "title":  f"{len(emails)} corporate email(s) harvested",
                "detail": f"Large email exposure enables targeted phishing campaigns. "
                          f"Sample: {', '.join(e['email'] for e in emails[:3])}",
                "modules": ["emails","hunter","employees"],
                "score_contribution": 10,
            })

        # ── 6. High/critical findings summary ────────────────────────────
        critical_finds = [f for f in findings if f.get("severity") == "critical"]
        high_finds     = [f for f in findings if f.get("severity") == "high"]
        if critical_finds:
            # Filter out header module findings — missing headers are medium severity max
            real_critical = [f for f in critical_finds
                             if f.get("module","") not in ("headers","cors","cms","waf")]
            risk_score += min(len(real_critical) * 10, 40)
            for f in real_critical[:5]:
                alerts.append({
                    "level":  "critical",
                    "title":  f.get("title","Critical finding")[:150],
                    "detail": f"Module: {f.get('module','')} | URL: {f.get('url','')}",
                    "modules": [f.get("module","")],
                    "score_contribution": 10,
                })

        risk_score = min(risk_score, 100)

        if risk_score >= 75:     verdict = "CRITICAL"
        elif risk_score >= 50:   verdict = "HIGH RISK"
        elif risk_score >= 25:   verdict = "MEDIUM RISK"
        elif risk_score > 0:     verdict = "LOW RISK"
        else:                    verdict = "CLEAN"

        report = {
            "target":            self.target,
            "risk_score":        risk_score,
            "verdict":           verdict,
            "alerts":            sorted(alerts, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x["level"],4)),
            "alert_count":       len(alerts),
            "correlations_made": len(correlations),
            "summary": {
                "subdomains_found":  len(subdomains),
                "emails_found":      len(emails),
                "ports_found":       len(ports),
                "dangerous_ports":   len(dangerous_open) if dangerous_open else 0,
                "findings_critical": len(critical_finds),
                "findings_high":     len(high_finds),
                "iocs_found":        len(iocs),
                "breach_hits":       len(breach_find),
            },
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        if alerts:
            log.warning(f"Correlation: {verdict} (score={risk_score}) — {len(alerts)} alerts")
        else:
            log.info(f"Correlation: {verdict} — no alerts")

        return report

    @staticmethod
    def print_report(report: dict):
        """Pretty-print correlation report to console."""
        from colorama import Fore, Style

        LEVEL_COLOR = {
            "critical": Fore.RED + Style.BRIGHT,
            "high":     Fore.YELLOW + Style.BRIGHT,
            "medium":   Fore.CYAN,
            "low":      Fore.WHITE,
        }
        VERDICT_COLOR = {
            "CRITICAL":    Fore.RED + Style.BRIGHT,
            "HIGH RISK":   Fore.YELLOW + Style.BRIGHT,
            "MEDIUM RISK": Fore.CYAN,
            "LOW RISK":    Fore.GREEN,
            "CLEAN":       Fore.GREEN + Style.BRIGHT,
        }

        score   = report.get("risk_score", 0)
        verdict = report.get("verdict", "")
        vc      = VERDICT_COLOR.get(verdict, Fore.WHITE)

        print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  ◈ CORRELATION ENGINE REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
        print(f"  Target    : {report.get('target')}")
        print(f"  Verdict   : {vc}{verdict}{Style.RESET_ALL}")
        print(f"  Risk Score: {vc}{score}/100{Style.RESET_ALL}")
        print(f"  Alerts    : {report.get('alert_count', 0)}")

        summ = report.get("summary", {})
        print(f"\n  {Fore.WHITE}Intelligence Summary:{Style.RESET_ALL}")
        for k, v in summ.items():
            if v:
                label = k.replace("_", " ").title()
                print(f"    {label:<25}: {v}")

        alerts = report.get("alerts", [])
        if alerts:
            print(f"\n  {Fore.WHITE}Alerts:{Style.RESET_ALL}")
            for alert in alerts:
                lc = LEVEL_COLOR.get(alert["level"], Fore.WHITE)
                print(f"  {lc}[{alert['level'].upper()}]{Style.RESET_ALL} {alert['title']}")
                print(f"    {alert['detail'][:120]}")

        print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")
