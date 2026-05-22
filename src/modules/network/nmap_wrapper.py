"""
ProjectZ - Module 20: Port Scanner (nmap wrapper + pure-Python fallback)
TCP connect scan for top 1000 ports. Uses nmap if installed,
falls back to pure asyncio socket scanner — no root required.
"""

from __future__ import annotations

import asyncio
import re
import socket
import subprocess
import shutil
from typing import Optional

from src.core.engine import BaseModule
from src.core.storage import cache, DatabaseManager

# Top 100 common ports for the pure fallback scanner
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 443, 445,
    465, 513, 514, 515, 587, 631, 993, 995, 1080, 1194, 1433, 1521, 1723,
    2049, 2181, 2375, 2376, 3000, 3306, 3389, 3690, 4000, 4444, 4848, 5000,
    5432, 5900, 5984, 5985, 6379, 6443, 7001, 7180, 7443, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9042, 9090, 9200, 9300, 9418, 10000, 11211,
    27017, 27018, 28017, 50000, 50070, 61616,
]

# Service banner fingerprints
SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 119: "NNTP", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 194: "IRC", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev-Server", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4444: "Metasploit", 5000: "UPnP",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 5985: "WinRM",
    6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "PHP-FPM", 9042: "Cassandra",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    9418: "Git", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB-Shard", 50000: "DB2", 50070: "Hadoop-NameNode",
    61616: "ActiveMQ",
}


class NmapModule(BaseModule):
    MODULE_NAME = "portscan"
    DESCRIPTION = "Port scanner — nmap (if installed) or async TCP connect fallback"

    async def run(self) -> dict:
        target  = self._clean(self.target)
        ports   = self.options.get("ports", "top100")
        self.log.info(f"Port scan: {target} ({ports})")

        cached = cache.get("portscan", f"{target}:{ports}")
        if cached:
            return cached

        ip = target if self._is_ip(target) else await self._resolve(target)
        if not ip:
            return {"target": target, "error": "Could not resolve IP"}

        if shutil.which("nmap"):
            result = await self._nmap_scan(target, ip, ports)
        else:
            self.log.warning("nmap not found — using async TCP connect scanner")
            result = await self._async_tcp_scan(target, ip)

        self._log_findings(result)
        cache.set("portscan", f"{target}:{ports}", result)
        await self._persist_db(result)
        return result

    # ── nmap scan ─────────────────────────────────────────────────────────
    async def _nmap_scan(self, target: str, ip: str, ports: str) -> dict:
        port_arg = "--top-ports 1000" if ports == "top100" else f"-p {ports}"
        cmd = [
            "nmap", "-sV", "-T4", "--open",
            "-oX", "-",          # XML output to stdout
            port_arg,
            "--script", "banner,http-title,ssl-cert",
            target,
        ]
        # Flatten the port_arg list
        cmd_flat = []
        for c in cmd:
            cmd_flat.extend(c.split() if " " in c else [c])

        try:
            loop   = asyncio.get_event_loop()
            proc   = await asyncio.create_subprocess_exec(
                *cmd_flat,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            xml    = stdout.decode("utf-8", errors="ignore")
            return self._parse_nmap_xml(target, ip, xml)
        except asyncio.TimeoutError:
            return {"target": target, "ip": ip, "error": "nmap timed out (180s)",
                    "open_ports": [], "scanner": "nmap"}
        except Exception as e:
            self.log.warning(f"nmap error: {e}")
            return await self._async_tcp_scan(target, ip)

    def _parse_nmap_xml(self, target: str, ip: str, xml: str) -> dict:
        open_ports = []
        # Parse XML manually — no lxml dependency needed
        port_blocks = re.findall(
            r'<port protocol="([^"]+)" portid="(\d+)">(.*?)</port>',
            xml, re.DOTALL,
        )
        for proto, port_num, block in port_blocks:
            state_m  = re.search(r'state="([^"]+)"', block)
            svc_m    = re.search(r'<service name="([^"]+)"', block)
            prod_m   = re.search(r'product="([^"]+)"', block)
            ver_m    = re.search(r'version="([^"]+)"', block)
            banner_m = re.search(r'<script id="banner"[^>]*output="([^"]+)"', block)
            title_m  = re.search(r'<script id="http-title"[^>]*output="([^"]+)"', block)

            if state_m and state_m.group(1) == "open":
                port_info = {
                    "port":     int(port_num),
                    "protocol": proto,
                    "service":  svc_m.group(1) if svc_m else SERVICE_MAP.get(int(port_num), "unknown"),
                    "product":  prod_m.group(1) if prod_m else "",
                    "version":  ver_m.group(1) if ver_m else "",
                    "banner":   banner_m.group(1)[:200] if banner_m else "",
                    "http_title": title_m.group(1)[:200] if title_m else "",
                }
                open_ports.append(port_info)

        return {
            "target":      target,
            "total":       len(open_ports),
            "ip":          ip,
            "open_ports":  open_ports,
            "port_count":  len(open_ports),
            "port_numbers": [p["port"] for p in open_ports],
            "scanner":     "nmap",
        }

    # ── Pure async TCP connect fallback ───────────────────────────────────
    async def _async_tcp_scan(self, target: str, ip: str) -> dict:
        sem        = asyncio.Semaphore(50)
        open_ports = []

        async def _probe(port: int):
            async with sem:
                try:
                    conn = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                    # Try to grab a banner
                    banner = ""
                    try:
                        writer.write(b"\r\n")
                        await writer.drain()
                        data   = await asyncio.wait_for(reader.read(256), timeout=1)
                        banner = data.decode("utf-8", errors="ignore").strip()[:200]
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                    open_ports.append({
                        "port":     port,
                        "protocol": "tcp",
                        "service":  SERVICE_MAP.get(port, "unknown"),
                        "banner":   banner,
                        "product":  "",
                        "version":  "",
                    })
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in TOP_100_PORTS], return_exceptions=True)
        open_ports.sort(key=lambda x: x["port"])

        return {
            "target":       target,
            "ip":           ip,
            "total":        len(open_ports),
            "open_ports":   open_ports,
            "port_count":   len(open_ports),
            "port_numbers": [p["port"] for p in open_ports],
            "scanner":      "async-tcp-connect",
        }

    def _log_findings(self, r: dict) -> None:
        count = r.get("port_count", 0)
        self.log.found("Open Ports", str(count))
        for p in r.get("open_ports", [])[:15]:
            svc = p.get("service", "")
            ver = p.get("version", "")
            self.log.found(f"Port {p['port']}/tcp", f"{svc} {ver}".strip())
        # Flag interesting ports
        for dangerous in [21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017]:
            if dangerous in r.get("port_numbers", []):
                self.log.warning(f"⚠ Port {dangerous} ({SERVICE_MAP.get(dangerous, '')}) open!")

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
