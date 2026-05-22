"""
ProjectZ - Professional Logger (Sliver-Style)
=============================================
Terminal output styled after the Sliver C2 framework:
  [*] info      — cyan    — operations in progress
  [+] found     — green   — positive findings
  [!] warning   — yellow  — anomalies / partial results
  [-] error     — red     — module failures
  [>] data      — white   — key:value findings
  [~] debug     — dim     — written to file only

Timestamp: absolute wall-clock  HH:MM:SS
Log file:  data/logs/projectz_YYYYMMDD.log  (rotating, 5MB × 7)
"""

from __future__ import annotations

import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ── Log directory ──────────────────────────────────────────────────────────
_root    = Path(__file__).resolve().parents[2]
_log_dir = _root / "data" / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)

_log_file = _log_dir / f"projectz_{time.strftime('%Y%m%d')}.log"
_file_handler = RotatingFileHandler(
    _log_file, maxBytes=5 * 1024 * 1024, backupCount=7, encoding="utf-8"
)
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)-22s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))

_root_logger = logging.getLogger("projectz")
_root_logger.setLevel(logging.DEBUG)
if not _root_logger.handlers:
    _root_logger.addHandler(_file_handler)
_root_logger.propagate = False


# ── Colour palette (Sliver-style) ──────────────────────────────────────────
_R  = Style.RESET_ALL
_B  = Style.BRIGHT
_DM = Style.DIM

# Prefix blocks
_PRE_INFO  = f"{Fore.CYAN}{_B}[*]{_R}"
_PRE_FOUND = f"{Fore.GREEN}{_B}[+]{_R}"
_PRE_WARN  = f"{Fore.YELLOW}{_B}[!]{_R}"
_PRE_ERR   = f"{Fore.RED}{_B}[-]{_R}"
_PRE_DATA  = f"{Fore.BLUE}{_B}[>]{_R}"
_PRE_CRIT  = f"{Fore.RED}{_B}[!]{_R}"
_PRE_SEC   = f"{Fore.CYAN}{_B}[~]{_R}"


def _ts() -> str:
    return f"{_DM}{time.strftime('%H:%M:%S')}{_R}"


class OSINTLogger:
    """
    Sliver-style dual-output logger.
    Terminal: coloured prefixed lines.
    File:     plain text with timestamps.
    """

    def __init__(self, name: str = "projectz"):
        self.name  = name
        self._flog = logging.getLogger(f"projectz.{name}")

    # ── Core log levels ────────────────────────────────────────────────────

    def info(self, msg: str):
        """[*] General operation status."""
        print(f"  {_ts()} {_PRE_INFO}  {msg}")
        self._flog.info(msg)

    def found(self, key: str, value: str = ""):
        """[+] Positive finding (key: value)."""
        if value:
            out = f"{Fore.WHITE}{_B}{key}{_R}: {Fore.GREEN}{value}{_R}"
        else:
            out = f"{Fore.GREEN}{_B}{key}{_R}"
        print(f"  {_ts()} {_PRE_FOUND}  {out}")
        self._flog.info("FOUND | %s: %s", key, value)

    def warning(self, msg: str):
        """[!] Non-critical anomaly or partial result."""
        print(f"  {_ts()} {_PRE_WARN}  {Fore.YELLOW}{msg}{_R}")
        self._flog.warning(msg)

    def error(self, msg: str):
        """[-] Module failure or critical error."""
        print(f"  {_ts()} {_PRE_ERR}  {Fore.RED}{msg}{_R}", file=sys.stderr)
        self._flog.error(msg)

    def data(self, key: str, value: str = ""):
        """[>] Key intelligence data point."""
        out = f"{Fore.CYAN}{_B}{key}{_R}: {Fore.WHITE}{value}{_R}" if value else \
              f"{Fore.CYAN}{key}{_R}"
        print(f"  {_ts()} {_PRE_DATA}  {out}")
        self._flog.info("DATA | %s: %s", key, value)

    def critical(self, msg: str):
        """[!] Critical security finding."""
        print(f"  {_ts()} {_PRE_CRIT}  {Fore.RED}{_B}{msg}{_R}")
        self._flog.critical(msg)

    def debug(self, msg: str):
        """Silent on terminal — written to log file only."""
        self._flog.debug(msg)

    def section(self, title: str):
        """Section separator with module name."""
        pad  = "─" * max(0, 55 - len(title))
        name = f" {self.name} " if self.name not in ("projectz", "cli", "engine") else ""
        print(f"\n  {Fore.CYAN}{_B}┌─ {title}{name}{pad}┐{_R}")
        self._flog.info("SECTION ── %s", title)

    def section_end(self):
        print(f"  {Fore.CYAN}{_DM}└{'─'*60}┘{_R}")

    def banner(self, msg: str):
        print(f"{Fore.CYAN}{_B}{msg}{_R}")
        self._flog.info("BANNER | %s", msg.strip())

    @staticmethod
    def log_file() -> str:
        return str(_log_file)


# ── Module progress indicator ─────────────────────────────────────────────
def print_module_start(name: str, target: str):
    print(f"  {_ts()} {_PRE_INFO}  Running {Fore.CYAN}{_B}{name}{_R} → {Fore.WHITE}{target}{_R}")

def print_module_done(name: str, count: int, elapsed: float):
    col = Fore.GREEN if count > 0 else Fore.YELLOW
    print(f"  {_ts()} {_PRE_FOUND}  {Fore.CYAN}{_B}{name}{_R} "
          f"→ {col}{count} results{_R}  "
          f"{_DM}({elapsed:.1f}s){_R}")

def print_module_error(name: str, err: str):
    short = err[:80] if len(err) > 80 else err
    print(f"  {_ts()} {_PRE_ERR}  {Fore.CYAN}{name}{_R} "
          f"→ {Fore.RED}{short}{_R}")


# ── Console compat shim ───────────────────────────────────────────────────
class _Console:
    """Rich-like shim used by engine.py."""
    def print(self, msg: str, style: str = "", **kw):
        import re as _re
        clean = _re.sub(r"\[/?[^\]]+\]", "", str(msg))
        print(clean)

console = _Console()
