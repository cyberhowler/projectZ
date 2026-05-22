"""
ProjectZ - Module 21: Masscan Wrapper
High-speed port scanning using masscan binary.
Falls back gracefully to async TCP scanner if masscan not installed.
Requires: sudo masscan (or capabilities set on binary).
"""

import asyncio
import json
import re
import shutil
import socket
import tempfile
from pathlib import Path

from src.core.engine import BaseModule
from src.core.storage import cache, DatabaseManager
from src.modules.network.nmap_wrapper import SERVICE_MAP, TOP_100_PORTS


class MasscanModule(BaseModule):
    MODULE_NAME = "masscan"
    DESCRIPTION = "High-speed port scan via masscan binary (TCP SYN) — falls back to async connect"


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
        target = self._clean(self.target)
        rate   = self.options.get("masscan_rate", 1000)
        ports  = self.options.get("ports", "0-65535")
        self.log.info(f"Masscan: {target} ports={ports} rate={rate}")

        cached = cache.get("masscan", f"{target}:{ports}")
        if cached:
            return cached

        ip = target if self._is_ip(target) else await self._to_ip(target)
        if not ip:
            return {"target": target, "error": "Could not resolve IP"}

        if shutil.which("masscan"):
            result = await self._masscan(target, ip, ports, rate)
        else:
            self.log.warning("masscan not installed — falling back to async TCP scanner")
            result = await self._async_fallback(target, ip)

        self._log_findings(result)
        cache.set("masscan", f"{target}:{ports}", result)
        await self._persist_db(result)
        return result

    # ── Masscan ────────────────────────────────────────────────────────────
    async def _masscan(self, target: str, ip: str, ports: str, rate: int) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            outfile = tf.name

        cmd = [
            "masscan", ip,
            "-p", ports,
            "--rate", str(rate),
            "--output-format", "json",
            "--output-filename", outfile,
            "--wait", "2",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            err_text  = stderr.decode("utf-8", errors="ignore")

            if "requires root" in err_text.lower() or "permission denied" in err_text.lower():
                self.log.warning("masscan needs root/sudo — falling back to TCP connect")
                Path(outfile).unlink(missing_ok=True)
                return await self._async_fallback(target, ip)

            result = self._parse_masscan_json(target, ip, outfile)
            Path(outfile).unlink(missing_ok=True)
            return result

        except asyncio.TimeoutError:
            Path(outfile).unlink(missing_ok=True)
            return {"target": target, "ip": ip, "error": "masscan timed out",
                    "open_ports": [], "scanner": "masscan"}
        except Exception as e:
            Path(outfile).unlink(missing_ok=True)
            self.log.warning(f"masscan error: {e} — falling back")
            return await self._async_fallback(target, ip)

    def _parse_masscan_json(self, target: str, ip: str, outfile: str) -> dict:
        open_ports = []
        try:
            content = Path(outfile).read_text(errors="ignore").strip()
            # masscan JSON is a list of objects, may have trailing comma
            content = content.rstrip(",").rstrip()
            if not content.startswith("["):
                content = f"[{content}]"
            data = json.loads(content)
            for entry in data:
                for port_info in entry.get("ports", []):
                    port_num = port_info.get("port", 0)
                    open_ports.append({
                        "port":     port_num,
                        "protocol": port_info.get("proto", "tcp"),
                        "service":  SERVICE_MAP.get(port_num, "unknown"),
                        "status":   port_info.get("status", "open"),
                        "banner":   "",
                    })
        except Exception as e:
            self.log.warning(f"masscan JSON parse error: {e}")

        return {
            "target":       target,
            "total":        len(open_ports),
            "ip":           ip,
            "open_ports":   open_ports,
            "port_count":   len(open_ports),
            "port_numbers": [p["port"] for p in open_ports],
            "scanner":      "masscan",
        }

    # ── Async TCP fallback ─────────────────────────────────────────────────
    async def _async_fallback(self, target: str, ip: str) -> dict:
        sem        = asyncio.Semaphore(50)
        open_ports = []

        async def _probe(port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=1.2
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    open_ports.append({
                        "port":     port,
                        "protocol": "tcp",
                        "service":  SERVICE_MAP.get(port, "unknown"),
                        "banner":   "",
                    })
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in TOP_100_PORTS], return_exceptions=True)
        open_ports.sort(key=lambda x: x["port"])
        return {
            "target":       target,
            "ip":           ip,
            "open_ports":   open_ports,
            "port_count":   len(open_ports),
            "port_numbers": [p["port"] for p in open_ports],
            "scanner":      "async-tcp-connect-fallback",
        }

    def _log_findings(self, r: dict) -> None:
        self.log.found("Scanner", r.get("scanner", ""))
        self.log.found("Open Ports", str(r.get("port_count", 0)))
        for p in r.get("open_ports", [])[:10]:
            self.log.found(f"Port {p['port']}/tcp", p.get("service", ""))

    async def _resolve(self, domain: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception:
            return ""

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]