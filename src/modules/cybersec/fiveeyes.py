"""
ProjectZ — Module: Five Eyes + India Government Threat Intelligence
===================================================================
Queries the PUBLIC advisory and threat feeds from 6 nations:

  🇺🇸 CISA (USA)        — Known Exploited Vulnerabilities (KEV) catalog
  🇬🇧 NCSC (UK)         — Cyber threat alerts + guidance RSS
  🇨🇦 CCCS (Canada)     — Cyber threat bulletin + alert RSS
  🇦🇺 ACSC (Australia)  — Cyber threat alert feed
  🇳🇿 NCSC-NZ (NZ)      — Cyber security advisory feed
  🇮🇳 CERT-In (India)   — Vulnerability Notes + Security Alerts + Advisories

WHY CERT-IN IS INCLUDED:
  CERT-In (Indian Computer Emergency Response Team) is India's national
  nodal agency for responding to cybersecurity incidents, operating under
  the Ministry of Electronics and Information Technology (MeitY).
  It publishes public advisories, vulnerability notes, and security alerts
  specifically for consumption by security researchers and organizations.
  Reading these feeds is legal, ethical, and encouraged by the Government
  of India. This is the same as reading cert-in.org.in in a browser.

  Reference: IT Act 2000, Section 70B — CERT-In mandate
  Feed URL:  https://cert-in.org.in (public, no auth required)

All feeds are 100% FREE, PUBLIC, and carry ZERO legal risk to access.

Usage:
  python3 projectz.py example.com fiveeyes
  python3 projectz.py apache      fiveeyes   # software vendor check
  python3 projectz.py 8.8.8.8     fiveeyes
"""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Optional

from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache, DatabaseManager
from src.core.config import config


# ── Feed URLs — all public, no auth ──────────────────────────────────────

# USA — CISA Known Exploited Vulnerabilities
CISA_KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/known-exploited-vulnerabilities/main/known_exploited_vulnerabilities.json"

# UK — NCSC advisory RSS
NCSC_UK_RSS  = "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"

# Canada — CCCS alert RSS
CCCS_CA_RSS  = "https://www.cyber.gc.ca/webservice/en/rss/alerts"

# Australia — ACSC alert RSS
ACSC_AU_RSS  = "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/alerts-and-advisories-rss-feed"

# New Zealand — NCSC-NZ advisory RSS
NCSC_NZ_RSS  = "https://www.ncsc.govt.nz/rss/alerts-advisories/"

# India — CERT-In feeds (all public, published by MeitY/Government of India)
CERTIN_VULN_NOTES = "https://cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01"
CERTIN_ALERTS     = "https://cert-in.org.in/s2cMainServlet?pageid=PUBALERTS01"
CERTIN_ADVISORIES = "https://cert-in.org.in/s2cMainServlet?pageid=PUBADVISORY01"
CERTIN_RSS        = "https://www.cert-in.org.in/RSS/Advisory.xml"


# ── Source registry ───────────────────────────────────────────────────────

SOURCES = {
    "CISA_US": {
        "country": "United States",
        "agency":  "CISA — Cybersecurity & Infrastructure Security Agency",
        "flag":    "🇺🇸",
        "type":    "json",
        "url":     CISA_KEV_URL,
        "law":     "FISMA / Executive Order 14028",
    },
    "NCSC_UK": {
        "country": "United Kingdom",
        "agency":  "NCSC — National Cyber Security Centre",
        "flag":    "🇬🇧",
        "type":    "rss",
        "url":     NCSC_UK_RSS,
        "law":     "Computer Misuse Act 1990",
    },
    "CCCS_CA": {
        "country": "Canada",
        "agency":  "CCCS — Canadian Centre for Cyber Security",
        "flag":    "🇨🇦",
        "type":    "rss",
        "url":     CCCS_CA_RSS,
        "law":     "Cybersecurity Act (Bill C-26)",
    },
    "ACSC_AU": {
        "country": "Australia",
        "agency":  "ACSC — Australian Cyber Security Centre",
        "flag":    "🇦🇺",
        "type":    "rss",
        "url":     ACSC_AU_RSS,
        "law":     "Security of Critical Infrastructure Act 2018",
    },
    "NCSC_NZ": {
        "country": "New Zealand",
        "agency":  "NCSC-NZ — National Cyber Security Centre",
        "flag":    "🇳🇿",
        "type":    "rss",
        "url":     NCSC_NZ_RSS,
        "law":     "Cybersecurity Strategy 2019",
    },
    "CERTIN_IN": {
        "country": "India",
        "agency":  "CERT-In — Indian Computer Emergency Response Team (MeitY)",
        "flag":    "🇮🇳",
        "type":    "certin",   # custom parser for CERT-In HTML pages
        "url":     CERTIN_VULN_NOTES,
        "law":     "IT Act 2000 Section 70B",
    },
}


class FiveEyesModule(BaseModule):
    """
    Six-nation government threat intelligence module.
    Five Eyes nations (USA, UK, Canada, Australia, NZ) + India (CERT-In).
    All feeds are public. Zero API keys required.
    """

    MODULE_NAME = "fiveeyes"
    DESCRIPTION = (
        "Six-nation govt threat intel: CISA KEV (USA) · NCSC (UK) · CCCS (CA) · "
        "ACSC (AU) · NCSC-NZ · CERT-In (India). 100%% public feeds, zero API keys."
    )

    # ── Entry point ───────────────────────────────────────────────────────
    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"Six-nation threat intelligence check: {target}")

        cached = cache.get("fiveeyes", target)
        if cached:
            return cached

        # Fetch all 6 feeds concurrently
        tasks = {
            key: self._fetch_source(key, meta, target)
            for key, meta in SOURCES.items()
        }
        raw = dict(zip(
            tasks.keys(),
            await asyncio.gather(*tasks.values(), return_exceptions=True),
        ))

        # Normalise exceptions
        source_results: dict[str, dict] = {}
        for key, val in raw.items():
            if isinstance(val, Exception):
                self.log.warning(f"{key} error: {val}")
                source_results[key] = {
                    "matches": [], "advisories": [], "cves": [],
                    "vendors": [], "error": str(val)[:100],
                }
            else:
                source_results[key] = val

        # Aggregate
        all_advisories   = []
        all_cves         = []
        all_vendors      = []
        kev_matches      = []
        certin_matches   = []
        matching_sources = []

        for key, data in source_results.items():
            meta    = SOURCES[key]
            matches = data.get("matches", [])
            advs    = data.get("advisories", [])

            if matches:
                matching_sources.append(f"{meta['flag']} {meta['country']}")

            for adv in advs:
                all_advisories.append({
                    **adv,
                    "source_key": key,
                    "country":    meta["country"],
                    "flag":       meta["flag"],
                    "agency":     meta["agency"],
                })

            all_cves.extend(data.get("cves", []))
            all_vendors.extend(data.get("vendors", []))

            if key == "CISA_US":
                kev_matches = data.get("kev_matches", [])
            if key == "CERTIN_IN":
                certin_matches = data.get("matches", [])

        # Deduplicate
        all_cves    = sorted(set(all_cves))
        all_vendors = sorted(set(all_vendors))

        # Score
        score, verdict, level = self._score(
            kev_matches, certin_matches, all_advisories,
            all_cves, matching_sources,
        )

        result = {
            "target":             target,
            "total":              len(all_advisories),

            # Verdict
            "threat_score":       score,
            "verdict":            verdict,
            "threat_level":       level,
            "matching_nations":   matching_sources,
            "nations_checked":    6,

            # CISA KEV
            "kev_matches":        kev_matches,
            "kev_count":          len(kev_matches),
            "in_cisa_kev":        len(kev_matches) > 0,

            # CERT-In specific
            "certin_matches":     certin_matches,
            "certin_count":       len(certin_matches),
            "in_certin":          len(certin_matches) > 0,

            # Combined CVEs and vendors
            "cves_referenced":    all_cves[:40],
            "cve_count":          len(all_cves),
            "vendors_affected":   all_vendors[:20],

            # All advisories — most recent 20
            "advisories": sorted(
                all_advisories,
                key=lambda x: x.get("published", ""),
                reverse=True,
            )[:20],

            # Per-source detail
            "sources": {
                key: {
                    "country":    SOURCES[key]["country"],
                    "agency":     SOURCES[key]["agency"],
                    "flag":       SOURCES[key]["flag"],
                    "law":        SOURCES[key]["law"],
                    "advisories": len(source_results[key].get("advisories", [])),
                    "matches":    len(source_results[key].get("matches", [])),
                    "error":      source_results[key].get("error", ""),
                    "feed_ok":    "error" not in source_results[key],
                }
                for key in SOURCES
            },
        }

        self._log_findings(result)

        # Persist to DB if notable threat level
        if score >= 30:
            await DatabaseManager.insert_ioc(
                "threat_govt", target, "fiveeyes",
                {
                    "score":   score,
                    "verdict": verdict,
                    "kev":     len(kev_matches),
                    "certin":  len(certin_matches),
                    "nations": matching_sources,
                },
            )

        cache.set("fiveeyes", target, result)
        return result

    # ── Fetch dispatcher ──────────────────────────────────────────────────
    async def _fetch_source(self, key: str, meta: dict, target: str) -> dict:
        if meta["type"] == "json":
            return await self._fetch_cisa_kev(meta["url"], target)
        elif meta["type"] == "certin":
            return await self._fetch_certin(target)
        else:
            return await self._fetch_rss(meta["url"], target)

    # ── CISA KEV (JSON) ───────────────────────────────────────────────────
    async def _fetch_cisa_kev(self, url: str, target: str) -> dict:
        r = await asyncio.wait_for(
            fetch(url, headers=self._hdrs(), timeout=15), timeout=18,
        )
        if not r["ok"] or not r["json"]:
            # Try GitHub mirror
            r = await asyncio.wait_for(
                fetch(CISA_KEV_MIRROR, headers=self._hdrs(), timeout=12), timeout=15,
            )
        if not r["ok"] or not r["json"]:
            return {"advisories": [], "matches": [], "kev_matches": [],
                    "cves": [], "vendors": []}

        vulns  = r["json"].get("vulnerabilities", [])
        tl     = target.lower()

        kev_matches  = []
        all_advs     = []
        all_cves     = []
        all_vendors  = []

        for v in vulns:
            vendor  = (v.get("vendorProject") or "").lower()
            product = (v.get("product") or "").lower()
            desc    = (v.get("shortDescription") or "").lower()
            cve     = v.get("cveID", "")

            if cve:
                all_cves.append(cve)
            vp = v.get("vendorProject", "")
            if vp:
                all_vendors.append(vp)

            if tl in vendor or tl in product or tl in desc:
                entry = {
                    "cve":         cve,
                    "vendor":      v.get("vendorProject", ""),
                    "product":     v.get("product", ""),
                    "description": (v.get("shortDescription") or "")[:200],
                    "date_added":  v.get("dateAdded", ""),
                    "due_date":    v.get("dueDate", ""),
                    "action":      (v.get("requiredAction") or "")[:150],
                    "source":      "CISA KEV",
                }
                kev_matches.append(entry)

        # Most recent 10 advisories
        for v in sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:10]:
            all_advs.append({
                "title":     f"{v.get('vendorProject','')} — {v.get('product','')}",
                "summary":   (v.get("shortDescription") or "")[:200],
                "cve":       v.get("cveID", ""),
                "published": v.get("dateAdded", ""),
                "url":       "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "type":      "KEV",
            })

        return {
            "advisories":  all_advs,
            "matches":     kev_matches,
            "kev_matches": kev_matches,
            "cves":        all_cves[:60],
            "vendors":     list(set(all_vendors))[:40],
            "total_kev":   len(vulns),
        }

    # ── CERT-In (India) ───────────────────────────────────────────────────
    async def _fetch_certin(self, target: str) -> dict:
        """
        CERT-In publishes advisories and vulnerability notes at cert-in.org.in.
        These are public pages under the Government of India (MeitY).
        We fetch the advisory listing page and parse the HTML table.

        CERT-In advisory ID format: CIVN-YYYY-NNNN (Vulnerability Notes)
                                     CIAD-YYYY-NNNN (Advisories)
                                     CIAS-YYYY-NNNN (Security Alerts)

        Legal basis: IT Act 2000 Section 70B designates CERT-In as the
        national agency and mandates public disclosure of threat information.
        Accessing their public website carries zero legal risk.
        """
        advisories = []
        cves       = []
        matches    = []
        tl         = target.lower()

        # Try all three CERT-In feed endpoints
        endpoints  = [
            ("Vulnerability Notes", CERTIN_VULN_NOTES,  "CIVN"),
            ("Security Alerts",     CERTIN_ALERTS,       "CIAS"),
            ("Advisories",          CERTIN_ADVISORIES,   "CIAD"),
            ("RSS Feed",            CERTIN_RSS,           "RSS"),
        ]

        for feed_name, url, prefix in endpoints:
            try:
                r = await asyncio.wait_for(
                    fetch(url, headers=self._certin_hdrs(), timeout=12),
                    timeout=15,
                )
                if not r["ok"] or not r["text"]:
                    continue

                text = r["text"]

                # If it's the RSS feed, parse as XML
                if prefix == "RSS":
                    rss_advs, rss_cves = self._parse_rss(text, "CERTIN_IN")
                    for adv in rss_advs:
                        adv["source"] = "CERT-In RSS"
                        adv["feed"]   = feed_name
                        advisories.append(adv)
                        cves.extend(adv.get("cves", []))
                        combined = (adv.get("title","") + " " + adv.get("summary","")).lower()
                        if tl in combined:
                            matches.append(adv)
                    continue

                # Parse HTML advisory listing table
                parsed = self._parse_certin_html(text, prefix, feed_name)
                for adv in parsed:
                    advisories.append(adv)
                    found_cves = re.findall(r'CVE-\d{4}-\d{4,7}',
                                           adv.get("title","") + " " + adv.get("summary",""),
                                           re.IGNORECASE)
                    cves.extend(c.upper() for c in found_cves)
                    combined = (adv.get("title","") + " " + adv.get("summary","") +
                                " " + adv.get("category","")).lower()
                    if tl in combined:
                        matches.append(adv)

            except asyncio.TimeoutError:
                self.log.warning(f"CERT-In timeout: {feed_name}")
            except Exception as e:
                self.log.warning(f"CERT-In {feed_name} error: {e}")

        return {
            "advisories": advisories[:20],
            "matches":    matches,
            "cves":       list(set(cves))[:30],
            "vendors":    [],
            "source":     "CERT-In (cert-in.org.in)",
            "legal_note": "Public feed — IT Act 2000 Section 70B",
        }

    def _parse_certin_html(self, html: str, prefix: str, feed_name: str) -> list:
        """
        Parse CERT-In HTML advisory listing table.
        CERT-In uses a standard HTML table with columns:
          Advisory ID | Date | Severity | Description
        """
        advisories = []

        # Find advisory ID patterns (CIVN-2024-0001, CIAD-2024-0001 etc.)
        id_pattern  = re.compile(
            rf'({re.escape(prefix)}-\d{{4}}-\d{{4}})', re.IGNORECASE
        )
        # Match table rows
        row_pattern = re.compile(
            r'<tr[^>]*>(.*?)</tr>', re.IGNORECASE | re.DOTALL
        )
        # Strip HTML tags
        tag_strip   = re.compile(r'<[^>]+>')
        # Date pattern
        date_pat    = re.compile(r'\d{2}[/-]\d{2}[/-]\d{4}|\d{4}-\d{2}-\d{2}')
        # Severity keywords
        sev_pat     = re.compile(
            r'(critical|high|medium|low|severe)', re.IGNORECASE
        )

        rows = row_pattern.findall(html)
        for row in rows[:30]:
            clean = tag_strip.sub(" ", row).strip()
            clean = re.sub(r'\s+', ' ', clean)

            adv_id = ""
            ids = id_pattern.findall(row)
            if ids:
                adv_id = ids[0].upper()

            date_m = date_pat.search(clean)
            date   = date_m.group(0) if date_m else ""

            sev_m    = sev_pat.search(clean)
            severity = sev_m.group(0).lower() if sev_m else "medium"

            # Extract description text (everything except ID and date)
            desc = clean
            if adv_id:
                desc = desc.replace(adv_id, "").strip()
            desc = desc[:250]

            if not adv_id and not desc.strip():
                continue
            if len(desc.strip()) < 10:
                continue

            advisories.append({
                "title":     adv_id or desc[:80],
                "summary":   desc,
                "published": date,
                "severity":  severity,
                "url":       f"https://cert-in.org.in/s2cMainServlet?pageid={self._page_for(prefix)}",
                "category":  feed_name,
                "source":    "CERT-In",
                "type":      "advisory",
            })

        return advisories

    def _page_for(self, prefix: str) -> str:
        mapping = {
            "CIVN": "PUBVLNOTES01",
            "CIAS": "PUBALERTS01",
            "CIAD": "PUBADVISORY01",
        }
        return mapping.get(prefix, "PUBVLNOTES01")

    # ── RSS parser (shared — used for UK/CA/AU/NZ and CERT-In RSS) ────────
    async def _fetch_rss(self, url: str, target: str) -> dict:
        r = await asyncio.wait_for(
            fetch(url, headers=self._hdrs(), timeout=12), timeout=15,
        )
        if not r["ok"] or not r["text"]:
            return {"advisories": [], "matches": [], "cves": [], "vendors": []}

        advisories, cves = self._parse_rss(r["text"], "rss")
        tl = target.lower()

        matches = []
        for adv in advisories:
            text = (adv.get("title","") + " " + adv.get("summary","") +
                    " " + adv.get("category","")).lower()
            if tl in text:
                matches.append(adv)

        return {
            "advisories": advisories[:15],
            "matches":    matches,
            "cves":       cves,
            "vendors":    [],
        }

    def _parse_rss(self, xml_text: str, source_key: str) -> tuple[list, list]:
        advisories = []
        cves       = []

        try:
            xml_text = xml_text.lstrip("\ufeff").strip()
            xml_text = re.sub(
                r'[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '', xml_text
            )
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return [], []

        is_atom = "}" in root.tag or root.tag.lower() == "feed"
        NS_ATOM = "http://www.w3.org/2005/Atom"

        items = (root.findall(f".//{{{NS_ATOM}}}entry") if is_atom
                 else root.findall(".//item"))

        for item in items[:20]:
            if is_atom:
                title   = self._xt(item, [f"{{{NS_ATOM}}}title"])
                summary = self._xt(item, [f"{{{NS_ATOM}}}summary",
                                          f"{{{NS_ATOM}}}content"])
                link    = self._xa(item, f"{{{NS_ATOM}}}link", "href")
                pub     = self._xt(item, [f"{{{NS_ATOM}}}published",
                                          f"{{{NS_ATOM}}}updated"])
                cat     = self._xa(item, f"{{{NS_ATOM}}}category", "term")
            else:
                title   = self._xt(item, ["title"])
                summary = self._xt(item, ["description"])
                link    = self._xt(item, ["link"])
                pub     = self._xt(item, ["pubDate",
                    "{http://purl.org/dc/elements/1.1/}date"])
                cat     = self._xt(item, ["category"])

            combined   = (title + " " + summary).upper()
            found_cves = re.findall(r'CVE-\d{4}-\d{4,7}', combined)
            cves.extend(found_cves)

            advisories.append({
                "title":     (title or "")[:120],
                "summary":   re.sub(r"<[^>]+>", "", summary or "")[:300],
                "url":       link or "",
                "published": pub or "",
                "category":  cat or "",
                "cves":      found_cves,
                "type":      "advisory",
            })

        return advisories, list(set(cves))

    # ── Threat scoring ────────────────────────────────────────────────────
    def _score(
        self,
        kev_matches:      list,
        certin_matches:   list,
        advisories:       list,
        cves:             list,
        matching_nations: list,
    ) -> tuple[int, str, str]:
        score = 0

        # CISA KEV — actively exploited in the wild (most severe)
        score += min(len(kev_matches) * 25, 60)

        # CERT-In matches — India-specific threat confirmation
        score += min(len(certin_matches) * 15, 30)

        # Multi-nation advisory matches
        score += min(len(matching_nations) * 8, 24)

        # CVE count
        score += min(len(cves) * 1, 15)

        score = min(score, 100)

        if score >= 75:
            return score, "ACTIVELY EXPLOITED",  "critical"
        if score >= 50:
            return score, "HIGH THREAT",          "high"
        if score >= 25:
            return score, "MODERATE THREAT",      "medium"
        if score > 0:
            return score, "LOW / MONITORING",     "low"
        return 0,  "NOT IN FEEDS",               "clean"

    # ── Console output ────────────────────────────────────────────────────
    def _log_findings(self, r: dict) -> None:
        self.log.found("Verdict",      r["verdict"])
        self.log.found("Threat Score", f"{r['threat_score']}/100")
        self.log.found("Nations",      "6 (USA · UK · Canada · Australia · NZ · India)")

        if r["in_cisa_kev"]:
            self.log.warning(
                f"⚠  CISA KEV — {r['kev_count']} Known Exploited Vulnerability match(es)"
            )
            for k in r["kev_matches"][:3]:
                self.log.warning(
                    f"   {k['cve']} · {k['vendor']} {k['product']} · Added {k['date_added']}"
                )

        if r["in_certin"]:
            self.log.warning(
                f"⚠  CERT-In — {r['certin_count']} Indian govt advisory match(es)"
            )
            for m in r["certin_matches"][:3]:
                self.log.warning(
                    f"   {m.get('title','')[:80]}"
                )

        for nation in r["matching_nations"]:
            self.log.found("Matched", nation)

        if r["cve_count"]:
            self.log.found("CVEs Referenced", str(r["cve_count"]))

        # Per-nation status table
        self.log.info("Nation feed status:")
        for src_key, src in r["sources"].items():
            status = "✓" if src["feed_ok"] else "✗ (timeout/blocked)"
            self.log.info(
                f"  {src['flag']}  {src['country']:<14}  "
                f"{src['advisories']:3d} advisories  "
                f"{src['matches']:2d} matches  {status}"
            )

    # ── HTTP header helpers ───────────────────────────────────────────────
    def _hdrs(self) -> dict:
        return {
            **config.DEFAULT_HEADERS,
            "Accept": "application/json, application/xml, text/xml, */*",
        }

    def _certin_hdrs(self) -> dict:
        """
        CERT-In pages occasionally require Accept-Language: en-IN
        and a standard browser User-Agent to return proper HTML.
        This is normal browser-like behaviour — no credential bypass.
        """
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-IN,en;q=0.9,hi;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT":             "1",
            "Connection":      "keep-alive",
        }

    # ── XML helpers ───────────────────────────────────────────────────────
    def _xt(self, el, tags: list) -> str:
        for tag in tags:
            child = el.find(tag)
            if child is not None and child.text:
                return child.text.strip()
        return ""

    def _xa(self, el, tag: str, attr: str) -> str:
        child = el.find(tag)
        return child.get(attr, "") if child is not None else ""

    # ── Target cleaner ────────────────────────────────────────────────────
    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://", "http://", "www."):
            if t.lower().startswith(p):
                t = t[len(p):]
        return t.split("/")[0].lower()
