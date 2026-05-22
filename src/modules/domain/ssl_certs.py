"""
ProjectZ - Module 04: SSL/TLS Certificate Analysis
Certificate details, CT log entries, SAN names, cipher suites.
Self-coded using ssl + cryptography + crt.sh API.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import socket
from datetime import datetime
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class SSLModule(BaseModule):
    MODULE_NAME = "ssl"
    DESCRIPTION = "SSL/TLS certificate analysis — validity, SANs, CT logs, cipher suites"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        port   = self.options.get("port", 443)
        self.log.info(f"SSL analysis: {domain}:{port}")

        cached = cache.get("ssl", f"{domain}:{port}")
        if cached:
            return cached

        # Run both checks concurrently
        cert_info, ct_certs = await asyncio.gather(
            self._grab_cert(domain, port),
            self._crtsh_certs(domain),
            return_exceptions=True,
        )

        if isinstance(cert_info, Exception):
            cert_info = {"error": str(cert_info)}
        if isinstance(ct_certs, Exception):
            ct_certs = []

        result = {
            "domain":           domain,
            "total":       1,
            "port":             port,
            "certificate":      cert_info,
            "ct_log_entries":   len(ct_certs),
            "ct_subjects":      ct_certs[:20],
            "san_domains":      cert_info.get("san", []) if isinstance(cert_info, dict) else [],
            "issuer":           cert_info.get("issuer", "") if isinstance(cert_info, dict) else "",
            "valid_from":       cert_info.get("not_before", "") if isinstance(cert_info, dict) else "",
            "valid_until":      cert_info.get("not_after", "") if isinstance(cert_info, dict) else "",
            "days_remaining":   cert_info.get("days_remaining") if isinstance(cert_info, dict) else None,
            "is_self_signed":   cert_info.get("is_self_signed", False) if isinstance(cert_info, dict) else False,
            "cipher_suite":     cert_info.get("cipher", "") if isinstance(cert_info, dict) else "",
            "tls_version":      cert_info.get("tls_version", "") if isinstance(cert_info, dict) else "",
        }

        self._log_findings(result)
        cache.set("ssl", f"{domain}:{port}", result)
        await self._persist_db(result)
        return result

    # ── Live certificate grab ──────────────────────────────────────────────
    async def _grab_cert(self, domain: str, port: int) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_grab, domain, port)

    def _sync_grab(self, domain: str, port: int) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_OPTIONAL

        try:
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert     = ssock.getpeercert()
                    cipher   = ssock.cipher()
                    tls_ver  = ssock.version()
                    der_cert = ssock.getpeercert(binary_form=True)
            return self._parse_cert(cert, cipher, tls_ver, der_cert, domain)
        except ssl.SSLCertVerificationError as e:
            # Still grab basic info
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            try:
                with socket.create_connection((domain, port), timeout=10) as sock:
                    with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert   = ssock.getpeercert()
                        cipher = ssock.cipher()
                        tls_ver = ssock.version()
                r = self._parse_cert(cert, cipher, tls_ver, None, domain)
                r["cert_warning"] = str(e)
                return r
            except Exception as e2:
                return {"error": str(e2)}
        except Exception as e:
            return {"error": str(e)}

    def _parse_cert(self, cert: dict, cipher, tls_ver: str, der_cert, domain: str) -> dict:
        def _fmt(t):
            try:
                return datetime.strptime(t, "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
            except Exception:
                return str(t)

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))

        not_before = _fmt(cert.get("notBefore", ""))
        not_after  = _fmt(cert.get("notAfter", ""))
        days_rem   = None
        try:
            exp        = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
            days_rem   = (exp - datetime.utcnow()).days
        except Exception:
            pass

        # Subject Alternative Names
        san = []
        for kind, value in cert.get("subjectAltName", []):
            if kind == "DNS":
                san.append(value.lower())

        issuer_str  = issuer.get("organizationName", issuer.get("commonName", ""))
        subject_str = subject.get("commonName", "")
        is_self_signed = (issuer.get("commonName") == subject.get("commonName"))

        return {
            "subject_cn":    subject_str,
            "issuer":        issuer_str,
            "not_before":    not_before,
            "not_after":     not_after,
            "days_remaining": days_rem,
            "san":           san,
            "is_self_signed": is_self_signed,
            "serial":        str(cert.get("serialNumber", "")),
            "cipher":        cipher[0] if cipher else "",
            "tls_version":   tls_ver or "",
            "san_count":     len(san),
        }

    # ── CT Log entries via crt.sh ──────────────────────────────────────────
    async def _crtsh_certs(self, domain: str) -> list[str]:
        url = f"https://crt.sh/?q={domain}&output=json"
        subjects = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                seen = set()
                for entry in data:
                    name = entry.get("common_name", "").strip().lower()
                    if name and name not in seen:
                        seen.add(name)
                        subjects.append(name)
        except Exception as e:
            self.log.warning(f"crt.sh CT log error: {e}")
        return subjects

    def _log_findings(self, r: dict) -> None:
        cert = r.get("certificate", {})
        if isinstance(cert, dict) and not cert.get("error"):
            self.log.found("Issuer",     r.get("issuer", ""))
            self.log.found("Valid Until", r.get("valid_until", ""))
            if r.get("days_remaining") is not None:
                days = r["days_remaining"]
                if days < 30:
                    self.log.warning(f"Certificate expires in {days} days!")
                else:
                    self.log.found("Days Remaining", str(days))
        if r.get("san_domains"):
            self.log.found("SAN Count", str(len(r["san_domains"])))
        if r.get("ct_log_entries"):
            self.log.found("CT Log Entries", str(r["ct_log_entries"]))
        if r.get("is_self_signed"):
            self.log.warning("Self-signed certificate detected!")


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
