"""
modules/port_scan.py
Phase 2a: Port scanning via naabu (preferred, Go-based, fast) with masscan fallback.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.config import ReconXConfig
from core.database import ReconDB
from core.logger import get_logger
from core.process import ProcessRunner

log = get_logger(__name__)

PORT_PRESETS = {"100": "-top-ports 100", "1000": "-top-ports 1000", "full": "-p -"}


async def scan_ports(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                      target: str, hosts: list[str]) -> dict[str, list[int]]:
    if not hosts:
        return {}

    top = cfg.ports.get("top", "1000")
    log.info(f"[cyan]Phase 2[/cyan] — port scanning {len(hosts)} host(s) (top={top})")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        input_path = f.name

    host_ports: dict[str, list[int]] = {}
    try:
        if ProcessRunner.is_available(cfg.tool("naabu")):
            cmd = [cfg.tool("naabu"), "-list", input_path, "-json", "-silent"]
            if top == "full":
                cmd += ["-p", "-"]
            else:
                cmd += ["-top-ports", top]
            res = await runner.run(cmd, timeout=1800)
            for line in res.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    host = obj.get("host") or obj.get("ip")
                    port = obj.get("port")
                    if host and port:
                        host_ports.setdefault(host, []).append(int(port))
                except json.JSONDecodeError:
                    continue

        elif ProcessRunner.is_available(cfg.tool("masscan")):
            port_range = "1-65535" if top == "full" else ("1-1000" if top == "1000" else "1-100")
            cmd = [cfg.tool("masscan"), "-iL", input_path, "-p", port_range,
                   "--rate", "1000", "-oJ", "-"]
            res = await runner.run(cmd, timeout=1800)
            try:
                data = json.loads(res.stdout) if res.stdout.strip() else []
                for entry in data:
                    ip = entry.get("ip")
                    for p in entry.get("ports", []):
                        host_ports.setdefault(ip, []).append(int(p["port"]))
            except json.JSONDecodeError:
                pass
        else:
            log.warning("Neither naabu nor masscan found on PATH — skipping port scan.")
    finally:
        Path(input_path).unlink(missing_ok=True)

    for host, ports in host_ports.items():
        for port in set(ports):
            await db.add_open_port(target, host, port)

    total_ports = sum(len(v) for v in host_ports.values())
    log.info(f"[green]{total_ports} open ports[/green] found across {len(host_ports)} hosts.")
    return host_ports
