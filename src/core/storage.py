"""
ProjectZ - Storage Layer
Handles: SQLite DB, JSON cache, wordlists, results manager.
All tables created automatically. No external deps.

DB Tables:
  scans        — every module run with full JSON result
  subdomains   — discovered subdomains
  emails       — discovered email addresses
  iocs         — threat IOCs (domains, IPs, hashes, URLs)
  ports        — open ports per host
  findings     — structured findings (vulns, leaks, misconfigs)
  domains      — domain-level metadata summary
  people       — people / personnel intel
"""

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

_root   = Path(__file__).resolve().parents[2]
_db_dir = _root / "data" / "db"
_ca_dir = _root / "data" / "cache"
_wl_dir = _root / "data" / "wordlists"
_re_dir = _root / "data" / "results"
_lo_dir = _root / "data" / "logs"

for d in (_db_dir, _ca_dir, _wl_dir, _re_dir, _lo_dir):
    d.mkdir(parents=True, exist_ok=True)


# ── JSON file cache ───────────────────────────────────────────────────────
class _Cache:
    TTL = 24 * 3600  # 24 hours

    def _path(self, module: str, key: str) -> Path:
        safe = key.replace("/", "_").replace(":", "_").replace(" ", "_")[:80]
        return _ca_dir / f"{module}_{safe}.json"

    def get(self, module: str, key: str) -> Optional[Any]:
        p = self._path(module, key)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text())
            if time.time() - data.get("_ts", 0) > self.TTL:
                p.unlink(missing_ok=True)
                return None
            return data.get("value")
        except Exception:
            return None

    def set(self, module: str, key: str, value: Any):
        p = self._path(module, key)
        try:
            p.write_text(json.dumps(
                {"_ts": time.time(), "value": value},
                default=str, indent=2,
            ))
        except Exception:
            pass

    def clear(self, module: str = None):
        for p in _ca_dir.glob("*.json"):
            if module is None or p.name.startswith(module):
                p.unlink(missing_ok=True)

    def stats(self) -> dict:
        files = list(_ca_dir.glob("*.json"))
        return {
            "entries": len(files),
            "size_kb": sum(f.stat().st_size for f in files) // 1024,
        }


cache = _Cache()


# ── SQLite database ───────────────────────────────────────────────────────
class _DatabaseManager:
    _db_path = str(_db_dir / "projectz.db")

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self._db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")   # better concurrency
        con.execute("PRAGMA foreign_keys=ON")
        return con

    def init_db(self):
        with self._conn() as con:
            con.executescript("""
                -- Every module run
                CREATE TABLE IF NOT EXISTS scans (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    target     TEXT    NOT NULL,
                    module     TEXT    NOT NULL,
                    result     TEXT,
                    elapsed    REAL    DEFAULT 0,
                    status     TEXT    DEFAULT 'ok',
                    created_at REAL    DEFAULT (unixepoch())
                );
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scans_module ON scans(module);

                -- Subdomains discovered
                CREATE TABLE IF NOT EXISTS subdomains (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain     TEXT    NOT NULL,
                    subdomain  TEXT    NOT NULL,
                    ip         TEXT    DEFAULT '',
                    source     TEXT    DEFAULT '',
                    created_at REAL    DEFAULT (unixepoch()),
                    UNIQUE(domain, subdomain)
                );
                CREATE INDEX IF NOT EXISTS idx_sub_domain ON subdomains(domain);

                -- Email addresses
                CREATE TABLE IF NOT EXISTS emails (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    email      TEXT    UNIQUE NOT NULL,
                    domain     TEXT    DEFAULT '',
                    source     TEXT    DEFAULT '',
                    verified   INTEGER DEFAULT 0,
                    created_at REAL    DEFAULT (unixepoch())
                );

                -- Threat IOCs
                CREATE TABLE IF NOT EXISTS iocs (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type   TEXT    NOT NULL,
                    value      TEXT    NOT NULL,
                    source     TEXT    DEFAULT '',
                    severity   TEXT    DEFAULT 'info',
                    metadata   TEXT    DEFAULT '{}',
                    created_at REAL    DEFAULT (unixepoch())
                );
                CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(ioc_type);
                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

                -- Open ports per host
                CREATE TABLE IF NOT EXISTS ports (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    target     TEXT    NOT NULL,
                    port       INTEGER NOT NULL,
                    protocol   TEXT    DEFAULT 'tcp',
                    service    TEXT    DEFAULT '',
                    version    TEXT    DEFAULT '',
                    state      TEXT    DEFAULT 'open',
                    banner     TEXT    DEFAULT '',
                    created_at REAL    DEFAULT (unixepoch()),
                    UNIQUE(target, port, protocol)
                );
                CREATE INDEX IF NOT EXISTS idx_ports_target ON ports(target);

                -- Structured findings (vulns, leaks, misconfigs)
                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT    NOT NULL,
                    module      TEXT    NOT NULL,
                    title       TEXT    NOT NULL,
                    description TEXT    DEFAULT '',
                    severity    TEXT    DEFAULT 'info',
                    evidence    TEXT    DEFAULT '',
                    url         TEXT    DEFAULT '',
                    created_at  REAL    DEFAULT (unixepoch())
                );
                CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

                -- Domain-level metadata summary
                CREATE TABLE IF NOT EXISTS domains (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain      TEXT    UNIQUE NOT NULL,
                    registrar   TEXT    DEFAULT '',
                    created     TEXT    DEFAULT '',
                    expires     TEXT    DEFAULT '',
                    nameservers TEXT    DEFAULT '[]',
                    ip          TEXT    DEFAULT '',
                    asn         TEXT    DEFAULT '',
                    org         TEXT    DEFAULT '',
                    country     TEXT    DEFAULT '',
                    last_scan   REAL    DEFAULT (unixepoch()),
                    updated_at  REAL    DEFAULT (unixepoch())
                );

                -- People / personnel
                CREATE TABLE IF NOT EXISTS people (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain     TEXT    NOT NULL,
                    full_name  TEXT    DEFAULT '',
                    email      TEXT    DEFAULT '',
                    role       TEXT    DEFAULT '',
                    linkedin   TEXT    DEFAULT '',
                    github     TEXT    DEFAULT '',
                    twitter    TEXT    DEFAULT '',
                    source     TEXT    DEFAULT '',
                    created_at REAL    DEFAULT (unixepoch()),
                    UNIQUE(domain, email)
                );

                -- Scan sessions (groups of modules run together)
                CREATE TABLE IF NOT EXISTS sessions (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    target     TEXT    NOT NULL,
                    modules    TEXT    DEFAULT '[]',
                    status     TEXT    DEFAULT 'running',
                    started_at REAL    DEFAULT (unixepoch()),
                    ended_at   REAL    DEFAULT 0,
                    report_path TEXT   DEFAULT ''
                );
            """)

    # ── Insert helpers ─────────────────────────────────────────────────────
    async def save_scan(self, target: str, module: str, result: dict):
        elapsed = result.get("_elapsed", 0)
        status  = "error" if result.get("error") else "ok"
        try:
            with self._conn() as con:
                con.execute(
                    "INSERT INTO scans(target, module, result, elapsed, status) VALUES(?,?,?,?,?)",
                    (target, module, json.dumps(result, default=str), elapsed, status),
                )
        except Exception:
            pass

    async def insert_subdomain(self, domain: str, subdomain: str,
                                ip: str = "", source: str = ""):
        try:
            with self._conn() as con:
                con.execute(
                    "INSERT OR IGNORE INTO subdomains(domain,subdomain,ip,source) VALUES(?,?,?,?)",
                    (domain, subdomain, ip, source),
                )
        except Exception:
            pass

    async def insert_email(self, email: str, domain: str = "", source: str = ""):
        try:
            with self._conn() as con:
                con.execute(
                    "INSERT OR IGNORE INTO emails(email,domain,source) VALUES(?,?,?)",
                    (email, domain, source),
                )
        except Exception:
            pass

    async def insert_ioc(self, ioc_type: str, value: str,
                          source: str = "", metadata: Any = None,
                          severity: str = "info"):
        try:
            with self._conn() as con:
                con.execute(
                    "INSERT INTO iocs(ioc_type,value,source,severity,metadata) VALUES(?,?,?,?,?)",
                    (ioc_type, value, source, severity,
                     json.dumps(metadata or {}, default=str)),
                )
        except Exception:
            pass

    async def insert_port(self, target: str, port: int, protocol: str = "tcp",
                           service: str = "", version: str = "",
                           state: str = "open", banner: str = ""):
        try:
            with self._conn() as con:
                con.execute(
                    """INSERT OR REPLACE INTO ports
                       (target,port,protocol,service,version,state,banner)
                       VALUES(?,?,?,?,?,?,?)""",
                    (target, port, protocol, service, version, state, banner),
                )
        except Exception:
            pass

    async def insert_finding(self, target: str, module: str, title: str,
                              description: str = "", severity: str = "info",
                              evidence: str = "", url: str = ""):
        try:
            with self._conn() as con:
                con.execute(
                    """INSERT INTO findings
                       (target,module,title,description,severity,evidence,url)
                       VALUES(?,?,?,?,?,?,?)""",
                    (target, module, title, description, severity, evidence, url),
                )
        except Exception:
            pass

    async def upsert_domain(self, domain: str, **fields):
        """Update or insert domain metadata."""
        try:
            with self._conn() as con:
                existing = con.execute(
                    "SELECT id FROM domains WHERE domain=?", (domain,)
                ).fetchone()
                if existing:
                    set_clause = ", ".join(f"{k}=?" for k in fields)
                    vals = list(fields.values()) + [domain]
                    con.execute(
                        f"UPDATE domains SET {set_clause}, updated_at=unixepoch() WHERE domain=?",
                        vals,
                    )
                else:
                    cols = "domain, " + ", ".join(fields.keys())
                    phs  = "?, " + ", ".join("?" for _ in fields)
                    vals = [domain] + list(fields.values())
                    con.execute(f"INSERT INTO domains({cols}) VALUES({phs})", vals)
        except Exception:
            pass

    async def insert_person(self, domain: str, full_name: str = "",
                             email: str = "", role: str = "",
                             linkedin: str = "", github: str = "",
                             twitter: str = "", source: str = ""):
        if not email and not full_name:
            return
        try:
            with self._conn() as con:
                con.execute(
                    """INSERT OR IGNORE INTO people
                       (domain,full_name,email,role,linkedin,github,twitter,source)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (domain, full_name, email, role, linkedin, github, twitter, source),
                )
        except Exception:
            pass

    def start_session(self, target: str, modules: list) -> int:
        try:
            with self._conn() as con:
                cur = con.execute(
                    "INSERT INTO sessions(target,modules) VALUES(?,?)",
                    (target, json.dumps(modules)),
                )
                return cur.lastrowid
        except Exception:
            return 0

    def end_session(self, session_id: int, report_path: str = ""):
        try:
            with self._conn() as con:
                con.execute(
                    "UPDATE sessions SET status='done', ended_at=unixepoch(), report_path=? WHERE id=?",
                    (report_path, session_id),
                )
        except Exception:
            pass

    # ── Query helpers ──────────────────────────────────────────────────────
    def query(self, sql: str, params: tuple = ()) -> list:
        try:
            with self._conn() as con:
                return [dict(r) for r in con.execute(sql, params).fetchall()]
        except Exception:
            return []

    def get_target_summary(self, target: str) -> dict:
        """All stored data for a target across all tables."""
        return {
            "scans":      self.query("SELECT module,status,elapsed,created_at FROM scans WHERE target=? ORDER BY created_at DESC", (target,)),
            "subdomains": self.query("SELECT subdomain,ip,source FROM subdomains WHERE domain=?", (target,)),
            "emails":     self.query("SELECT email,source,verified FROM emails WHERE domain=?", (target,)),
            "ports":      self.query("SELECT port,protocol,service,version,state FROM ports WHERE target=?", (target,)),
            "findings":   self.query("SELECT title,severity,module,url FROM findings WHERE target=? ORDER BY severity", (target,)),
            "iocs":       self.query("SELECT ioc_type,value,severity,source FROM iocs WHERE value LIKE ?", (f"%{target}%",)),
            "people":     self.query("SELECT full_name,email,role,source FROM people WHERE domain=?", (target,)),
        }

    def stats(self) -> dict:
        counts = {}
        for table in ("scans","subdomains","emails","ports","findings","iocs","people","domains","sessions"):
            try:
                with self._conn() as con:
                    counts[table] = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except Exception:
                counts[table] = 0
        return counts


DatabaseManager = _DatabaseManager()
DatabaseManager.init_db()


# ── Wordlists ─────────────────────────────────────────────────────────────
class _WordlistManager:
    def _load(self, name: str, limit: int) -> list:
        p = _wl_dir / f"{name}.txt"
        if p.exists():
            lines = [l.strip() for l in p.read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
            return lines[:limit]
        # Built-in fallbacks
        fallbacks = {
            "subdomains": [
                "www","mail","ftp","admin","api","dev","staging","test","qa",
                "blog","shop","cdn","static","img","images","assets","media",
                "app","portal","dashboard","login","auth","sso","vpn","remote",
                "intranet","internal","secure","beta","old","new","support",
                "help","docs","wiki","git","gitlab","jenkins","jira","confluence",
                "kibana","grafana","prometheus","monitor","status","health",
                "db","database","mysql","redis","elastic","mongo","smtp","imap",
                "pop","mx","ns1","ns2","ns3","cpanel","whm","webmail","mx1",
                "m","mobile","wap","api1","api2","v1","v2","cloud","aws",
                "azure","gcp","backup","archive","legacy","corp","hr",
                "finance","marketing","sales","dev2","qa2","uat",
            ],
            "directories": [
                "admin","login","dashboard","api","v1","v2","backup","test",
                ".git","wp-admin","phpmyadmin","config","install","setup",
                "upload","uploads","files","data","static","assets","images",
                ".env","robots.txt","sitemap.xml","swagger","graphql",
                "actuator","health","metrics","info","debug",
            ],
            "admin-panels": [
                "admin","administrator","admin/login","wp-admin","wp-login.php",
                "phpmyadmin","adminer","cpanel","webmail","portal",
                "manage","manager","management","control","controlpanel",
                "adminpanel","backend","cms","console",
            ],
        }
        return fallbacks.get(name, [])[:limit]

    def subdomains(self, limit: int = 300) -> list:
        return self._load("subdomains", limit)

    def directories(self, limit: int = 500) -> list:
        return self._load("directories", limit)

    def admin_panels(self, limit: int = 200) -> list:
        return self._load("admin-panels", limit)


wordlists = _WordlistManager()


# ── Results Manager ───────────────────────────────────────────────────────
class _ResultsManager:
    def save_json(self, target: str, data: dict, filepath: str = None) -> str:
        ts   = time.strftime("%Y%m%d_%H%M%S")
        name = filepath or str(_re_dir / f"{target.replace('.','_')}_{ts}.json")
        Path(name).parent.mkdir(parents=True, exist_ok=True)
        Path(name).write_text(json.dumps(data, indent=2, default=str))
        return name

    def save_txt(self, target: str, data: dict, filepath: str = None) -> str:
        ts   = time.strftime("%Y%m%d_%H%M%S")
        name = filepath or str(_re_dir / f"{target.replace('.','_')}_{ts}.txt")
        lines = [f"ProjectZ Scan Report", f"Target : {target}",
                 f"Date   : {ts}", "=" * 60, ""]
        for module, result in data.items():
            lines.append(f"\n[ {module.upper()} ]")
            if isinstance(result, dict):
                for k, v in result.items():
                    if k.startswith("_"): continue
                    lines.append(f"  {k}: {str(v)[:200]}")
        Path(name).write_text("\n".join(lines))
        return name

    @staticmethod
    def list_results(target: str = None) -> list:
        files = sorted(_re_dir.glob("*.json"), reverse=True)
        if target:
            files = [f for f in files if target.replace(".","_") in f.name]
        return [str(f) for f in files[:20]]


ResultsManager = _ResultsManager()
