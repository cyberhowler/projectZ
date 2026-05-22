"""
ProjectZ OSINT Framework v1.0 — CLI
=====================================
Usage:
  python3 projectz.py <target> <module>          # run scan
  python3 projectz.py <target> quick             # 9-module fast scan
  python3 projectz.py <target> full — 56 modules
  python3 projectz.py <target> --profile pentest # named profile
  python3 projectz.py <target> quick --watch 6   # re-scan every 6h
  python3 projectz.py modules                    # full module guide
  python3 projectz.py modules domain             # section guide
  python3 projectz.py --list-modules             # compact list
  python3 projectz.py --list-profiles            # show all profiles
  python3 projectz.py --commands                 # full command reference
  python3 projectz.py --db-stats                 # database stats
  python3 projectz.py --db-summary <target>      # stored intel
  python3 projectz.py --compare <target>         # diff last two scans
  python3 projectz.py --preflight                # API key + system check
"""

from __future__ import annotations

import asyncio
import sys
import time

import click
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

from src.core.engine         import (Engine, MODULE_GROUPS, MODULE_REGISTRY,
                                      resolve_modules, smart_modules_for)
from src.core.http_client    import detect_target_type, check_api_keys
from src.core.logger         import OSINTLogger, print_module_start, print_module_done, print_module_error
from src.core.module_guide   import (MODULES, print_full_guide,
                                      print_compact_list, _print_module, _print_section)
from src.core.output         import OutputManager
from src.core.storage        import DatabaseManager, ResultsManager
from src.core.correlator     import Correlator
from src.core.profiles       import ProfileManager

log = OSINTLogger("cli")

R  = Style.RESET_ALL
B  = Style.BRIGHT
DM = Style.DIM
G  = Fore.GREEN   + B
C  = Fore.CYAN    + B
Y  = Fore.YELLOW  + B
RE = Fore.RED     + B
W  = Fore.WHITE   + B
M  = Fore.MAGENTA + B

CONTEXT = dict(help_option_names=["-h", "--help"], max_content_width=100)

SECTION_ALIASES = {
    "domain":     "DOMAIN INTELLIGENCE",
    "people":     "PEOPLE & OSINT",
    "network":    "NETWORK & INFRASTRUCTURE",
    "dorking":    "SEARCH ENGINE DORKING",
    "harvesting": "DATA HARVESTING",
    "cybersec":   "CYBERSEC & THREAT INTEL",
}


# ═══════════════════════════════════════════════════════════════════════════
#  COMMAND REFERENCE
# ═══════════════════════════════════════════════════════════════════════════
def _cmd_commands():
    """Print full command reference — every flag, every mode."""
    W2 = Fore.WHITE + B
    divider  = lambda: print(f"  {DM}{'─'*72}{R}")
    hdivider = lambda: print(f"  {DM}{'═'*72}{R}")

    print()
    hdivider()
    print(f"  {C}  ProjectZ v1.0  —  Full Command Reference{R}")
    print(f"  {DM}  by cyberhowler (R.G)  ·  53 Modules  ·  14 Profiles{R}")
    hdivider()

    sections = [
        ("CORE SCAN", [
            ("python3 projectz.py <target> <module>",      "Run a specific module"),
            ("python3 projectz.py <target> quick",         "Fast 9-module scan (no API keys needed)"),
            ("python3 projectz.py <target> full",          "All 56 modules"),
            ("python3 projectz.py <target> domain.all",    "All domain intelligence modules"),
            ("python3 projectz.py <target> network.all",   "All network modules"),
            ("python3 projectz.py <target> people.all",    "All people/OSINT modules"),
            ("python3 projectz.py <target> dorking.all",   "All dorking modules"),
            ("python3 projectz.py <target> harvesting.all","All harvesting modules"),
            ("python3 projectz.py <target> cybersec.all",  "All cybersec/threat intel modules"),
            ("python3 projectz.py <target> waf,cors,headers,cms", "Multiple modules comma-separated"),
        ]),
        ("PROFILES (--profile)", [
            ("python3 projectz.py <target> --profile quick",         "9-module fast scan"),
            ("python3 projectz.py <target> --profile full",          "All 56 modules"),
            ("python3 projectz.py <target> --profile pentest",       "Full recon + vuln hints (28 modules)"),
            ("python3 projectz.py <target> --profile red_team",      "Complete red team surface (38 modules)"),
            ("python3 projectz.py <target> --profile bug_bounty",    "Bug bounty focused (22 modules)"),
            ("python3 projectz.py <target> --profile passive_recon", "100%% passive — OPSEC safe (20 modules)"),
            ("python3 projectz.py <target> --profile web_audit",     "Web security audit (14 modules)"),
            ("python3 projectz.py <target> --profile social_eng",    "Social engineering prep (12 modules)"),
            ("python3 projectz.py <target> --profile osint",         "People + social + breaches (9 modules)"),
            ("python3 projectz.py <target> --profile threat_intel",  "Cybersec + threat feeds (9 modules)"),
            ("python3 projectz.py <target> --profile domain",        "Domain intelligence (11 modules)"),
            ("python3 projectz.py <target> --profile quick_ip",      "Fast IP intel (6 modules)"),
            ("python3 projectz.py <target> --profile recon",         "Classic recon (10 modules)"),
        ]),
        ("OUTPUT & FORMAT (-f / -o)", [
            ("python3 projectz.py <target> full -f json",            "JSON output (default)"),
            ("python3 projectz.py <target> full -f html",            "Full HTML report"),
            ("python3 projectz.py <target> full -f csv",             "CSV spreadsheet"),
            ("python3 projectz.py <target> full -f txt",             "Plain text"),
            ("python3 projectz.py <target> full -f html -o rep.html","Custom output filename"),
        ]),
        ("SCAN CONTROL", [
            ("python3 projectz.py <target> <mod> -v",                "Verbose — print full results to terminal"),
            ("python3 projectz.py <target> <mod> --no-cache",        "Skip cache — always fetch fresh data"),
            ("python3 projectz.py <target> <mod> --no-concurrent",   "Sequential mode (debugging)"),
            ("python3 projectz.py <target> <mod> --workers 5",       "Limit concurrent workers"),
            ("python3 projectz.py <target> <mod> --timeout 30",      "HTTP timeout per request (seconds)"),
            ("python3 projectz.py <target> <mod> --no-correlate",    "Skip correlation engine"),
            ("python3 projectz.py <target> <mod> --no-notify",       "Skip webhook notifications"),
        ]),
        ("MONITORING (--watch)", [
            ("python3 projectz.py <target> quick --watch 6",         "Re-scan every 6 hours, show diffs"),
            ("python3 projectz.py <target> dns --watch 1",           "Monitor DNS every 1 hour"),
            ("python3 projectz.py <target> quick --watch 24",        "Daily monitoring"),
        ]),
        ("PROFILES (management)", [
            ("python3 projectz.py --list-profiles",                  "List all built-in + custom profiles"),
            ("python3 projectz.py <t> waf,cors,headers --save-profile webcheck", "Save custom profile"),
            ("python3 projectz.py <target> --profile webcheck",      "Use saved custom profile"),
        ]),
        ("DATABASE & HISTORY", [
            ("python3 projectz.py --db-stats",                       "Database statistics (all targets)"),
            ("python3 projectz.py --db-summary example.com",         "All stored intel for one target"),
            ("python3 projectz.py --compare example.com",            "Diff last 2 scans for a target"),
            ("python3 projectz.py --list-results example.com",       "List all saved result files"),
        ]),
        ("MODULE GUIDE", [
            ("python3 projectz.py modules",                          "Full module guide (all 53)"),
            ("python3 projectz.py modules domain",                   "Domain intelligence section only"),
            ("python3 projectz.py modules network",                  "Network section only"),
            ("python3 projectz.py modules people",                   "People/OSINT section only"),
            ("python3 projectz.py modules dorking",                  "Dorking section only"),
            ("python3 projectz.py modules harvesting",               "Harvesting section only"),
            ("python3 projectz.py modules cybersec",                 "Cybersec section only"),
            ("python3 projectz.py modules waf",                      "Single module detail (any name)"),
            ("python3 projectz.py --list-modules",                   "Compact one-liner list"),
        ]),
        ("SYSTEM", [
            ("python3 projectz.py --preflight",                      "Check API keys + system tools"),
            ("python3 projectz.py --commands",                       "This command reference"),
            ("python3 projectz.py -h / --help",                      "Main help"),
        ]),
        ("TARGET TYPES", [
            ("python3 projectz.py example.com quick",                "Domain target"),
            ("python3 projectz.py 8.8.8.8 quick_ip",                 "IPv4 address target"),
            ("python3 projectz.py admin@example.com breach,hibp",    "Email target"),
            ("python3 projectz.py johndoe usernames",                "Username target"),
            ("python3 projectz.py d41d8cd98f00b204e9800998ecf8427e virustotal,yara", "MD5 hash target"),
            ("python3 projectz.py https://evil.com virustotal,urlscan","URL target"),
        ]),
    ]

    for section_title, cmds in sections:
        print()
        divider()
        print(f"  {M}  {section_title}{R}")
        divider()
        for cmd, desc in cmds:
            print(f"  {C}{cmd:<58}{R}  {DM}{desc}{R}")

    print()
    hdivider()
    print(f"  {DM}Config: .env  ·  Logs: data/logs/  ·  DB: data/db/projectz.db  ·  Results: data/results/{R}")
    hdivider()
    print()


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN COMMAND
# ═══════════════════════════════════════════════════════════════════════════
@click.command(context_settings=CONTEXT)
@click.argument("target", default="")
@click.argument("module", default="quick")
@click.option("-o", "--output",         default=None,  metavar="FILE",
              help="Output file path (default: auto-generated in data/results/)")
@click.option("-f", "--format",         default="json",
              type=click.Choice(["json", "txt", "csv", "html"]),
              help="Output format  [json|txt|csv|html]  default: json")
@click.option("-v", "--verbose",        is_flag=True,
              help="Print full module results to terminal")
@click.option("--timeout",              default=12, show_default=True, metavar="SECS",
              help="HTTP timeout per request (seconds)")
@click.option("--no-cache",             is_flag=True,
              help="Skip 24h cache — always fetch fresh data")
@click.option("--no-concurrent",        is_flag=True,
              help="Run modules sequentially (use for debugging)")
@click.option("--workers",              default=10, show_default=True, metavar="N",
              help="Max concurrent module workers")
@click.option("--profile",              default=None,  metavar="NAME",
              help="Use a named scan profile  (e.g. red_team, bug_bounty, pentest)")
@click.option("--watch",               default=0, metavar="HOURS", type=int,
              help="Continuous monitoring — re-run scan every N hours, show diffs")
@click.option("--correlate/--no-correlate", default=True,
              help="Run correlation engine after scan (default: on)")
@click.option("--notify/--no-notify",  default=True,
              help="Send webhook notifications on critical findings")
@click.option("--list-modules",         is_flag=True,
              help="Show compact module list and exit")
@click.option("--list-profiles",        is_flag=True,
              help="List all available scan profiles")
@click.option("--commands",             is_flag=True,
              help="Print full command reference and exit")
@click.option("--db-stats",             is_flag=True,
              help="Show database statistics across all targets")
@click.option("--db-summary",           default=None,  metavar="TARGET",
              help="Show all stored intel for TARGET")
@click.option("--compare",              default=None,  metavar="TARGET",
              help="Diff the two most recent scans for TARGET")
@click.option("--list-results",         is_flag=True,
              help="List saved result files for TARGET")
@click.option("--preflight",            is_flag=True,
              help="Check API keys and system tool availability")
@click.option("--save-profile",         default=None,  metavar="NAME",
              help="Save current module/options as a named profile")
def cli(target, module, output, format, verbose, timeout,
        no_cache, no_concurrent, workers, profile, watch,
        correlate, notify, list_modules, list_profiles, commands,
        db_stats, db_summary, compare, list_results, preflight, save_profile):
    """
    \b
    ProjectZ v1.0 — OSINT & Pentest Recon Framework
    ══════════════════════════════════════════════════
    TARGET  : domain · IP · email · username · hash · URL
    MODULE  : module_name  OR  group  OR  profile_name
    \b
    ┌─ Quick start ─────────────────────────────────────────────┐
    │  python3 projectz.py example.com quick                    │
    │  python3 projectz.py example.com --profile red_team       │
    │  python3 projectz.py example.com full -f html             │
    │  python3 projectz.py 8.8.8.8    quick_ip                  │
    │  python3 projectz.py example.com waf,headers,cors,cms     │
    │  python3 projectz.py --commands   (full command list)     │
    │  python3 projectz.py modules     (all 53 modules)         │
    └───────────────────────────────────────────────────────────┘
    """
    # ── Standalone commands (no target needed) — handle FIRST ───────────
    if commands:
        _cmd_commands(); return

    if list_modules:
        print_compact_list(); return

    if list_profiles:
        ProfileManager.print_all(); return

    if db_stats:
        _cmd_db_stats(); return

    if db_summary:
        _cmd_db_summary(db_summary); return

    if compare:
        _cmd_compare(compare); return

    if preflight:
        _cmd_preflight(); return

    if target == "modules":
        _cmd_modules(module); return

    if list_results:
        _cmd_list_results(target or None); return

    # ── Target is required beyond this point ─────────────────────────────
    if not target:
        import click as _click
        print(f"\n  {RE}[-]{R}  No target specified.")
        print(f"  {DM}    Usage:  python3 projectz.py <target> [module]{R}")
        print(f"  {DM}    Help:   python3 projectz.py -h{R}")
        print(f"  {DM}    Cmds:   python3 projectz.py --commands{R}\n")
        raise SystemExit(1)

    # ── Profile resolution ────────────────────────────────────────────────
    if profile:
        p = ProfileManager.get(profile)
        if not p:
            print(f"\n  {RE}[-]{R} Profile not found: {profile!r}")
            print(f"  {DM}    Run:  python3 projectz.py --list-profiles{R}\n")
            sys.exit(1)
        module  = ",".join(p.get("modules", ["quick"]))
        workers = p.get("options", {}).get("max_workers", workers)

    # ── Save profile ──────────────────────────────────────────────────────
    if save_profile:
        mod_list = [m.strip() for m in module.replace(",", " ").split()]
        path = ProfileManager.save(save_profile, mod_list, options={"max_workers": workers})
        print(f"\n  {G}[+]{R} Profile saved: {Y}{save_profile}{R} → {DM}{path}{R}\n")

    # ── Banner ────────────────────────────────────────────────────────────
    OutputManager.print_banner()

    # ── Header info block ─────────────────────────────────────────────────
    keys      = check_api_keys()
    set_count = sum(1 for v in keys.values() if "SET" in v)
    mis_count = len(keys) - set_count

    ttype = detect_target_type(target)
    type_colour = {
        "domain":     Fore.CYAN,
        "ipv4":       Fore.YELLOW,
        "ipv6":       Fore.YELLOW,
        "email":      Fore.MAGENTA,
        "hash_md5":   Fore.RED,
        "hash_sha1":  Fore.RED,
        "hash_sha256":Fore.RED,
        "url":        Fore.BLUE,
        "username":   Fore.GREEN,
    }.get(ttype, Fore.WHITE)

    print(f"  {DM}{'─'*64}{R}")
    if profile:
        print(f"  {C}[*]{R}  Profile   {W}{profile}{R}  {DM}{p.get('description','')}{R}")
    print(f"  {C}[*]{R}  Target    {type_colour}{B}{target}{R}  {DM}[{ttype}]{R}")
    print(f"  {C}[*]{R}  API Keys  {G if set_count else Y}{set_count} configured{R}  "
          f"{DM}{mis_count} not set  (edit .env for more results){R}")

    # ── Module resolution ─────────────────────────────────────────────────
    try:
        module_list = resolve_modules(module)
    except ValueError as e:
        print(f"\n  {RE}[-]{R} {e}")
        print(f"  {DM}    Run:  python3 projectz.py modules{R}\n")
        sys.exit(1)

    if not module_list:
        print(f"\n  {RE}[-]{R} No modules resolved from: {module!r}\n")
        sys.exit(1)

    mod_display = ", ".join(module_list[:10])
    if len(module_list) > 10:
        mod_display += f" +{len(module_list)-10} more"

    print(f"  {C}[*]{R}  Modules   {W}{mod_display}{R}")
    print(f"  {C}[*]{R}  Format    {DM}{format}{R}  "
          f"Workers {DM}{workers}{R}  "
          f"Cache {DM}{'off' if no_cache else 'on'}{R}  "
          f"Timeout {DM}{timeout}s{R}")
    if watch:
        print(f"  {Y}[!]{R}  Watch mode — re-scanning every {watch}h")
    print(f"  {DM}{'─'*64}{R}")
    print()

    if no_cache:
        from src.core.storage import cache
        cache.clear()

    # ── Watch mode ────────────────────────────────────────────────────────
    if watch:
        asyncio.run(_watch_loop(
            target, module_list, format, output, verbose, timeout,
            not no_concurrent, workers, correlate, notify, watch
        ))
        return

    # ── Single scan ───────────────────────────────────────────────────────
    asyncio.run(_run_once(
        target, module_list, format, output, verbose, timeout,
        not no_concurrent, workers, correlate, notify
    ))


async def _run_once(target, module_list, fmt, output, verbose, timeout,
                    concurrent, workers, correlate, notify):
    t0     = time.monotonic()
    engine = Engine(
        target        = target,
        output_format = fmt,
        output_file   = output,
        verbose       = verbose,
        timeout       = timeout,
        concurrent    = concurrent,
        max_workers   = workers,
    )

    results = await engine.run_modules(module_list)
    saved   = engine.save_output()
    elapsed = round(time.monotonic() - t0, 1)

    ok_n  = sum(1 for v in results.values()
                if isinstance(v, dict) and not v.get("error"))
    err_n = len(results) - ok_n
    db    = DatabaseManager.stats()

    print()
    print(f"  {DM}{'═'*64}{R}")
    print(f"  {G}[+]{R}  Scan complete  ·  {elapsed}s  ·  {time.strftime('%H:%M:%S')}")
    print(f"  {DM}{'─'*64}{R}")
    print(f"  {C}[*]{R}  Modules    {G}{ok_n} OK{R}  {RE if err_n else DM}{err_n} errors{R}  "
          f"{DM}/ {len(results)} total{R}")
    if saved:
        print(f"  {C}[*]{R}  Saved      {DM}{saved}{R}")
    print(f"  {C}[*]{R}  Database   "
          f"{DM}{db.get('scans',0)} scans · "
          f"{db.get('subdomains',0)} subdomains · "
          f"{db.get('emails',0)} emails · "
          f"{db.get('ports',0)} ports · "
          f"{db.get('findings',0)} findings · "
          f"{db.get('iocs',0)} IOCs{R}")

    if verbose:
        _print_verbose_results(results)

    # ── Correlation engine ────────────────────────────────────────────────
    if correlate:
        try:
            report = Correlator(target).run()
            _print_correlation(report)
            if notify and report.get("risk_score", 0) >= 50:
                try:
                    from src.core.notifier import notifier
                    await notifier.notify_scan_complete(
                        target      = target,
                        risk_score  = report["risk_score"],
                        verdict     = report["verdict"],
                        alert_count = report.get("alert_count", 0),
                    )
                except Exception:
                    pass
        except Exception as e:
            log.debug(f"Correlator error: {e}")

    print(f"  {DM}{'═'*64}{R}")
    print()
    return results


def _print_verbose_results(results: dict):
    import json
    print(f"\n  {DM}{'─'*64}{R}")
    print(f"  {C}[*]{R}  Verbose module output:")
    print(f"  {DM}{'─'*64}{R}")
    for mod_name, res in results.items():
        if not isinstance(res, dict):
            continue
        err = res.get("error", "")
        tot = res.get("total", 0)
        print(f"\n  {G}  {mod_name.upper()}{R}  {DM}({tot} results){R}")
        if err:
            print(f"  {RE}    error: {err}{R}")
        else:
            # Print key fields
            skip = {"_elapsed", "domain", "target", "error", "total",
                    "critical_findings", "_ts"}
            for k, v in res.items():
                if k in skip:
                    continue
                if isinstance(v, list):
                    if v:
                        print(f"  {DM}    {k}: [{len(v)} items] {str(v[:3])[:80]}...{R}"
                              if len(v) > 3 else
                              f"  {DM}    {k}: {v}{R}")
                elif isinstance(v, dict):
                    pass
                elif v:
                    print(f"  {DM}    {k}: {str(v)[:80]}{R}")
    print()


def _print_correlation(report: dict):
    score   = report.get("risk_score", 0)
    verdict = report.get("verdict", "UNKNOWN")
    alerts  = report.get("alerts", [])

    score_col = (RE if score >= 70 else
                 Y  if score >= 40 else
                 G)

    print(f"  {DM}{'─'*64}{R}")
    print(f"  {C}[~]{R}  Correlation Engine")
    print(f"  {DM}{'─'*64}{R}")
    print(f"  {C}[*]{R}  Risk Score  {score_col}{score}/100{R}  ·  "
          f"Verdict  {score_col}{verdict}{R}")

    if alerts:
        print(f"  {C}[*]{R}  Alerts     {len(alerts)} findings")
        for a in alerts[:8]:
            lvl = a.get("level", "info").upper()
            lvl_col = (RE if lvl == "CRITICAL" else
                       Y  if lvl in ("HIGH", "WARNING") else
                       C)
            title = a.get("title", "")[:60]
            print(f"  {DM}    {lvl_col}[{lvl}]{R}  {DM}{title}{R}")
    print()


async def _watch_loop(target, module_list, fmt, output, verbose, timeout,
                      concurrent, workers, correlate, notify, interval_hours):
    scan_num   = 0
    last_subs  = set()
    last_ports = set()
    last_finds = set()

    while True:
        scan_num += 1
        print(f"\n  {Y}{'━'*64}{R}")
        print(f"  {Y}[!]{R}  WATCH MODE  ·  Scan #{scan_num}  ·  {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {Y}{'━'*64}{R}\n")

        results = await _run_once(
            target, module_list, fmt, output, verbose, timeout,
            concurrent, workers, correlate, notify
        )

        summary    = DatabaseManager.get_target_summary(target)
        curr_subs  = {s["subdomain"] for s in summary.get("subdomains", [])}
        curr_ports = {f"{p['port']}/{p.get('protocol','tcp')}"
                      for p in summary.get("ports", [])}
        curr_finds = {f["title"] for f in summary.get("findings", [])}

        if scan_num > 1:
            new_subs  = curr_subs  - last_subs
            new_ports = curr_ports - last_ports
            gone_subs = last_subs  - curr_subs
            new_finds = curr_finds - last_finds

            if new_subs or new_ports or new_finds or gone_subs:
                print(f"  {Y}[!]{R}  Changes detected since last scan:")
                for s in sorted(new_subs)[:10]:
                    print(f"        {G}+{R} NEW subdomain: {s}")
                for s in sorted(gone_subs)[:5]:
                    print(f"        {RE}−{R} GONE subdomain: {s}")
                for p in sorted(new_ports)[:10]:
                    print(f"        {G}+{R} NEW port: {p}")
                for f in sorted(new_finds)[:10]:
                    print(f"        {RE}!{R} NEW finding: {f[:70]}")
                print()
            else:
                print(f"  {DM}[~]  No changes detected since last scan.{R}\n")

        last_subs  = curr_subs
        last_ports = curr_ports
        last_finds = curr_finds

        nxt = time.strftime("%H:%M:%S", time.localtime(time.time() + interval_hours * 3600))
        print(f"  {DM}[~]  Sleeping {interval_hours}h — next scan at {nxt}{R}")
        await asyncio.sleep(interval_hours * 3600)


# ═══════════════════════════════════════════════════════════════════════════
#  SUB-COMMANDS
# ═══════════════════════════════════════════════════════════════════════════
def _cmd_modules(section: str = "quick"):
    if section in ("quick", "all", "", "full"):
        print_full_guide()
        return
    sec_key = section.lower()

    # BUG 8 FIX: handle dot notation — "cybersec.virustotal", "domain.whois" etc.
    if "." in sec_key:
        parts = sec_key.split(".", 1)
        mod_name = parts[1]  # the module name after the dot
        for sec_mods in MODULES.values():
            if mod_name in sec_mods:
                from src.core.module_guide import _header, _print_module_block, _footer
                _header()
                _print_module_block(mod_name, sec_mods[mod_name])
                _footer()
                return
        # dot notation but module not found — fall through to section
        sec_key = parts[0]

    if sec_key in SECTION_ALIASES:
        _print_section(sec_key)
        return
    # Try exact module name
    for sec_mods in MODULES.values():
        if sec_key in sec_mods:
            from src.core.module_guide import _header, _print_module_block, _footer
            _header()
            _print_module_block(sec_key, sec_mods[sec_key])
            _footer()
            return
    # Fallback
    print_full_guide()


def _cmd_preflight():
    print()
    print(f"  {DM}{'═'*64}{R}")
    print(f"  {C}[~]{R}  ProjectZ v1.0  —  Preflight Check")
    print(f"  {DM}{'─'*64}{R}")

    keys = check_api_keys()
    print(f"\n  {C}[*]{R}  API Keys:")
    for k, v in sorted(keys.items()):
        col = G if "SET" in v else DM
        print(f"  {DM}      {k:<30}{R}  {col}{v}{R}")

    print(f"\n  {C}[*]{R}  System Tools:")
    import shutil
    tools = [
        ("nmap",     "Port scanning (nmap_wrapper module)"),
        ("masscan",  "Mass port scanning (masscan module)"),
        ("whois",    "WHOIS CLI fallback"),
    ]
    for tool, purpose in tools:
        found = shutil.which(tool)
        col   = G if found else Y
        note  = found or "not found — built-in fallback active"
        print(f"  {DM}      {tool:<14}{R}  {col}{note}{R}")
        if not found:
            print(f"  {DM}              → {purpose}{R}")

    print(f"\n  {C}[*]{R}  Framework:")
    print(f"  {DM}      Modules registered   {len(MODULE_REGISTRY)}{R}")
    print(f"  {DM}      Profiles available   {len(ProfileManager.list_all())}{R}")
    db = DatabaseManager.stats()
    print(f"  {DM}      Database             {db.get('scans',0)} scans stored{R}")
    print(f"\n  {DM}{'═'*64}{R}\n")


def _cmd_db_stats():
    db = DatabaseManager.stats()
    print()
    print(f"  {DM}{'═'*64}{R}")
    print(f"  {C}[~]{R}  Database Statistics  ·  data/db/projectz.db")
    print(f"  {DM}{'─'*64}{R}")
    for k, v in db.items():
        print(f"  {C}[*]{R}  {k:<20} {W}{v}{R}")
    print(f"  {DM}{'═'*64}{R}\n")


def _cmd_db_summary(target: str):
    summary = DatabaseManager.get_target_summary(target)
    print()
    print(f"  {DM}{'═'*64}{R}")
    print(f"  {C}[~]{R}  Stored Intel  ·  {Y}{target}{R}")
    print(f"  {DM}{'─'*64}{R}")
    subs  = summary.get("subdomains", [])
    emails= summary.get("emails", [])
    ports = summary.get("ports", [])
    finds = summary.get("findings", [])
    iocs  = summary.get("iocs", [])
    print(f"  {C}[*]{R}  Subdomains   {W}{len(subs)}{R}")
    for s in subs[:15]:
        print(f"  {DM}      {s.get('subdomain','')}{R}")
    print(f"  {C}[*]{R}  Emails       {W}{len(emails)}{R}")
    for e in emails[:10]:
        print(f"  {DM}      {e.get('email','')}{R}")
    print(f"  {C}[*]{R}  Open Ports   {W}{len(ports)}{R}")
    for p in ports[:10]:
        print(f"  {DM}      {p.get('port','')}/{p.get('protocol','tcp')}  {p.get('service','')}{R}")
    print(f"  {C}[*]{R}  Findings     {W}{len(finds)}{R}")
    for f in finds[:10]:
        sev = f.get("severity","info")
        col = RE if sev == "critical" else Y if sev == "high" else DM
        print(f"  {DM}      {col}[{sev}]{R}  {DM}{f.get('title','')[:60]}{R}")
    print(f"  {C}[*]{R}  IOCs         {W}{len(iocs)}{R}")
    print(f"  {DM}{'═'*64}{R}\n")


def _cmd_compare(target: str):
    files = ResultsManager.list_results(target)
    if len(files) < 2:
        print(f"\n  {Y}[!]{R}  Need at least 2 scans to compare. "
              f"Run the same scan twice.\n")
        return
    import json
    try:
        r1 = json.loads(open(files[-2]).read())
        r2 = json.loads(open(files[-1]).read())
    except Exception as e:
        print(f"\n  {RE}[-]{R}  Could not load scan files: {e}\n")
        return

    print()
    print(f"  {DM}{'═'*64}{R}")
    print(f"  {C}[~]{R}  Scan Diff  ·  {Y}{target}{R}")
    print(f"  {DM}    {files[-2]}{R}")
    print(f"  {DM}    vs")
    print(f"  {DM}    {files[-1]}{R}")
    print(f"  {DM}{'─'*64}{R}")

    mods1 = set(r1.keys()) if isinstance(r1, dict) else set()
    mods2 = set(r2.keys()) if isinstance(r2, dict) else set()
    new_mods = mods2 - mods1
    if new_mods:
        print(f"  {G}[+]{R}  New modules in scan 2: {', '.join(new_mods)}")
    print(f"  {DM}{'═'*64}{R}\n")


def _cmd_list_results(target=None):
    import os, glob
    if target:
        files = ResultsManager.list_results(target)
        label = target
    else:
        # No target — list ALL result files across all targets
        results_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "results"
        )
        results_dir = os.path.normpath(results_dir)
        files = sorted(glob.glob(os.path.join(results_dir, "*.json")))
        label = "all targets"
    if not files:
        print(f"\n  {DM}[~]  No saved results found for: {label}{R}\n")
        return
    print(f"\n  {C}[*]{R}  Saved results ({label}):")
    for f in files:
        size = os.path.getsize(f)
        print(f"  {DM}      {os.path.basename(f)}  ({size:,} bytes){R}")
    print()


def main():
    cli()


if __name__ == "__main__":
    main()
