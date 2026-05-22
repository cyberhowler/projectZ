"""
ProjectZ - Output Manager v1
Handles: terminal, JSON, TXT, CSV, HTML report generation.
"""

import csv
import io
import json
import time
from pathlib import Path
from typing import Any

from colorama import Fore, Style
from tabulate import tabulate

_root   = Path(__file__).resolve().parents[2]
_re_dir = _root / "data" / "results"
_re_dir.mkdir(parents=True, exist_ok=True)


class OutputManager:

    @staticmethod
    def print_banner():
        from src.core.banners import get_random_banner
        print(get_random_banner())
        return

        # ── legacy below (unreachable — kept for reference) ──────────────
        W  = Fore.WHITE  + Style.BRIGHT
        C  = Fore.CYAN   + Style.BRIGHT
        B  = Fore.BLUE   + Style.BRIGHT
        DM = Style.DIM
        RS = Style.RESET_ALL
        WH = Fore.WHITE
        CY = Fore.CYAN

        wolf = f"""
{DM}                        . . .  . . .                        {RS}
{DM}                   .  '               '  .                  {RS}
{DM}                .     /^\\           /^\\     .               {RS}
{B}              (       /^^^\\__     __/^^^\\       )            {RS}
{B}             ( `·.  /  /\\  /^\\   /^\\  /\\  .·´ )           {RS}
{B}            (       | /  \\/   \\ /   \\/  \\ |      )         {RS}
{B}           (   ◈    ||  /\\  /\\ X /\\  /\\  ||   ◈   )        {RS}
{B}          (         | \\/  \\/  / \\  \\/  \\/ |         )      {RS}
{W}         (    ╱|    |/\\__/\\__/ _ \\__/\\__/\\|    |╲    )     {RS}
{W}        (    ╱ |   /  \\  /\\  (___)  /\\  /  \\   | ╲    )    {RS}
{W}       (   ╱  ╱   | /\\ \\/ /\\ /_\\ /\\ \\/ /\\ |   ╲  ╲   )   {RS}
{W}      (   /  ╱    |/  \\/\\/  V   V  \\/\\/  \\|    ╲  \\   )   {RS}
{W}     (   / .·     \\  /\\  /  |   |  \\  /\\  /     ·. \\   )  {RS}
{C}    (   /·´        \\/  \\/   |   |   \\/  \\/        `·\\   ) {RS}
{C}   (   (    ╔═══╗   \\__/    |___|    \\__/   ╔═══╗    )   ) {RS}
{C}    (   \\   ╚═══╝  /    \\___/   \\___/    \\  ╚═══╝   /   ) {RS}
{C}     (   `·._____./  /\\    \\ _ /    /\\  \\._____..·´   )   {RS}
{DM}      (             \\/  \\  (   )  /  \\/             )      {RS}
{DM}       `·.          /\\   \\_/ \\_/   /\\          .·´        {RS}
{DM}           `·-.____/  \\_____________/  \\____.-·´           {RS}
{DM}                   .  ` · . _ . · ´  .                      {RS}
{DM}                      .   .   .   .                          {RS}"""

        projectz = f"""
{C}  ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗ ███████╗{RS}
{C}  ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝ ╚════██║{RS}
{W}  ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║        ██╔╝ {RS}
{W}  ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║       ██╔╝  {RS}
{B}  ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║      ██║   {RS}
{B}  ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝      ╚═╝  {RS}"""

        tagline = f"""
{DM}  ╼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╾{RS}
  {DM}     Open Source Intelligence Framework  ·  50 Modules  ·  v1.0{RS}
  {DM}                      developed by{RS} {W}cyberhowler{RS} {Fore.YELLOW}{Style.BRIGHT}(R.G){RS}
{DM}  ╼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╾{RS}
"""
        print(wolf)
        print(projectz)
        print(tagline)

    @staticmethod
    def print_result(module_name: str, result: dict):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═'*60}\n  {module_name.upper()}\n{'═'*60}{Style.RESET_ALL}")
        def _flat(obj, prefix=""):
            rows = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(k).startswith("_"): continue
                    key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, (dict, list)) and v: rows.extend(_flat(v, key))
                    else: rows.append((key, str(v)[:120]))
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:8]): rows.extend(_flat(item, f"{prefix}[{i}]"))
            else: rows.append((prefix, str(obj)[:120]))
            return rows
        rows = [(str(k), str(v)) for k, v in _flat(result)]
        if rows: print(tabulate(rows, headers=["Key", "Value"], tablefmt="simple"))
        print()

    @staticmethod
    def save_json(target: str, results: dict, filepath: str = None) -> str:
        ts = time.strftime("%Y%m%d_%H%M%S")
        name = filepath or str(_re_dir / f"{target.replace('.','_')}_{ts}.json")
        Path(name).parent.mkdir(parents=True, exist_ok=True)
        Path(name).write_text(json.dumps(results, indent=2, default=str))
        return name

    @staticmethod
    def save_txt(target: str, results: dict, filepath: str = None) -> str:
        ts = time.strftime("%Y%m%d_%H%M%S")
        name = filepath or str(_re_dir / f"{target.replace('.','_')}_{ts}.txt")
        lines = ["ProjectZ Scan Report", f"Target : {target}", f"Date   : {ts}", "="*60]
        for mod, data in results.items():
            lines += [f"\n[ {mod.upper()} ]"]
            if isinstance(data, dict):
                for k, v in data.items():
                    if str(k).startswith("_"): continue
                    lines.append(f"  {k}: {str(v)[:200]}")
        Path(name).write_text("\n".join(lines))
        return name

    @staticmethod
    def save_csv(target: str, results: dict, filepath: str = None) -> str:
        """Export all findings to CSV — one row per key-value pair per module."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        name = filepath or str(_re_dir / f"{target.replace('.','_')}_{ts}.csv")

        def _flatten(obj: Any, module: str, prefix: str = "") -> list:
            rows = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(k).startswith("_"): continue
                    key = f"{prefix}.{k}" if prefix else str(k)
                    if isinstance(v, (dict, list)) and v:
                        rows.extend(_flatten(v, module, key))
                    else:
                        rows.append({"module": module, "key": key, "value": str(v)[:500]})
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:50]):
                    rows.extend(_flatten(item, module, f"{prefix}[{i}]"))
            else:
                rows.append({"module": module, "key": prefix, "value": str(obj)[:500]})
            return rows

        all_rows = []
        for mod, data in results.items():
            all_rows.extend(_flatten(data, mod))

        Path(name).parent.mkdir(parents=True, exist_ok=True)
        with open(name, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["module","key","value"])
            writer.writeheader()
            writer.writerows(all_rows)
        return name

    @staticmethod
    def save_html(target: str, results: dict, db_summary: dict = None,
                  filepath: str = None) -> str:
        ts   = time.strftime("%Y%m%d_%H%M%S")
        name = filepath or str(_re_dir / f"{target.replace('.','_')}_{ts}.html")

        total_mods  = len(results)
        total_found = sum(v.get("total",0) if isinstance(v,dict) else 0 for v in results.values())
        errors      = sum(1 for v in results.values() if isinstance(v,dict) and v.get("error"))

        cards = ""
        for mod, data in results.items():
            elapsed = data.get("_elapsed", 0) if isinstance(data, dict) else 0
            err     = data.get("error","")    if isinstance(data, dict) else ""
            sc      = "error" if err else "ok"
            icon    = "✘" if err else "✔"
            rows    = ""
            if isinstance(data, dict):
                for k, v in data.items():
                    if str(k).startswith("_") or k == "error": continue
                    val = (f"[{len(v)} items] " + ", ".join(str(i)[:60] for i in v[:5])
                           + ("..." if len(v)>5 else "")) if isinstance(v,list) else \
                          (json.dumps(v,default=str)[:200] if isinstance(v,dict) else str(v)[:300])
                    rows += f'<tr><td class="key">{k}</td><td class="val">{val}</td></tr>'
            if err:
                rows += f'<tr><td class="key err">error</td><td class="val err">{err}</td></tr>'
            cards += f"""
            <div class="card">
              <div class="card-header {sc}">
                <span class="icon">{icon}</span>
                <span class="mod-name">{mod.upper()}</span>
                <span class="elapsed">{elapsed}s</span>
              </div>
              <div class="card-body">
                <table class="data-table"><tbody>{rows}</tbody></table>
              </div>
            </div>"""

        db_html = ""
        if db_summary:
            db_html = "<h2>Stored Intelligence</h2>"
            for sec, rows in db_summary.items():
                if not rows: continue
                db_html += f"<h3>{sec.upper()} ({len(rows)})</h3><table class='db-table'><tbody>"
                for row in rows[:20]:
                    db_html += "<tr>" + "".join(f"<td><b>{k}</b>: {str(v)[:80]}</td>" for k,v in row.items()) + "</tr>"
                db_html += "</tbody></table>"

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ProjectZ — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:24px}}
.header{{background:linear-gradient(135deg,#1f2937,#111827);border:1px solid #30363d;border-radius:12px;padding:28px 32px;margin-bottom:24px}}
.header h1{{font-size:1.8rem;color:#58a6ff;margin-bottom:6px}}
.header .meta{{color:#8b949e;font-size:.9rem}}
.stats{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 20px;flex:1;min-width:120px;text-align:center}}
.stat .num{{font-size:1.8rem;font-weight:700;color:#58a6ff}}
.stat .lbl{{font-size:.75rem;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:.05em}}
.stat.danger .num{{color:#f85149}}.stat.ok .num{{color:#3fb950}}
h2{{color:#58a6ff;margin:20px 0 10px;font-size:1.1rem;border-bottom:1px solid #30363d;padding-bottom:6px}}
h3{{color:#79c0ff;margin:14px 0 6px;font-size:.95rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(520px,1fr));gap:14px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}}
.card-header{{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#1c2128;border-bottom:1px solid #30363d}}
.card-header.ok{{border-left:4px solid #3fb950}}.card-header.error{{border-left:4px solid #f85149}}
.icon{{font-size:.9rem}}.card-header.ok .icon{{color:#3fb950}}.card-header.error .icon{{color:#f85149}}
.mod-name{{font-weight:700;font-size:.9rem;color:#e6edf3;flex:1}}.elapsed{{font-size:.75rem;color:#8b949e}}
.card-body{{padding:10px 14px;overflow-x:auto}}
.data-table{{width:100%;border-collapse:collapse;font-size:.8rem}}
.data-table td{{padding:4px 6px;border-bottom:1px solid #21262d;vertical-align:top}}
.data-table td.key{{color:#79c0ff;width:33%;font-family:monospace;white-space:nowrap}}
.data-table td.val{{color:#adbac7;word-break:break-all}}.data-table td.err{{color:#f85149}}
.db-table{{width:100%;border-collapse:collapse;font-size:.78rem;margin-bottom:12px}}
.db-table td{{padding:5px 8px;border:1px solid #30363d}}
.footer{{text-align:center;color:#484f58;font-size:.75rem;margin-top:28px;padding-top:14px;border-top:1px solid #21262d}}
</style></head><body>
<div class="header">
  <h1>🔍 ProjectZ OSINT Report</h1>
  <div class="meta">Target: <strong style="color:#e6edf3">{target}</strong> &nbsp;|&nbsp; {ts}</div>
</div>
<div class="stats">
  <div class="stat"><div class="num">{total_mods}</div><div class="lbl">Modules</div></div>
  <div class="stat"><div class="num">{total_found}</div><div class="lbl">Findings</div></div>
  <div class="stat {'danger' if errors else 'ok'}"><div class="num">{errors}</div><div class="lbl">Errors</div></div>
</div>
<h2>Module Results</h2>
<div class="cards">{cards}</div>
{db_html}
<div class="footer">ProjectZ OSINT Framework v1.0 &nbsp;|&nbsp; {ts}</div>
</body></html>"""
        Path(name).write_text(html, encoding="utf-8")
        return name

    @staticmethod
    def list_results(target: str = None) -> list:
        files = sorted(_re_dir.glob("*"), key=lambda f: f.stat().st_mtime, reverse=True)
        if target: files = [f for f in files if target.replace(".","_") in f.name]
        return [str(f) for f in files[:20]]
