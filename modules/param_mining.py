"""
modules/param_mining.py
Phase 3 (cont.): Hidden parameter discovery via arjun (preferred) / x8.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.config import ReconXConfig
from core.logger import get_logger
from core.process import ProcessRunner

log = get_logger(__name__)


async def mine_parameters(runner: ProcessRunner, cfg: ReconXConfig, urls: list[str]) -> dict[str, list[str]]:
    if not urls:
        return {}

    log.info(f"[cyan]Phase 3[/cyan] — mining hidden parameters on {len(urls)} URL(s)")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        input_path = f.name

    out_json = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False).name
    results: dict[str, list[str]] = {}

    try:
        if ProcessRunner.is_available(cfg.tool("arjun")):
            cmd = [cfg.tool("arjun"), "-i", input_path, "-oJ", out_json, "-t", "10", "-w", "medium"]
            await runner.run(cmd, timeout=1800)
            if Path(out_json).exists():
                try:
                    data = json.loads(Path(out_json).read_text())
                    for url, params in data.items():
                        results[url] = params if isinstance(params, list) else params.get("params", [])
                except (json.JSONDecodeError, OSError):
                    pass
        elif ProcessRunner.is_available(cfg.tool("x8")):
            for url in urls:
                res = await runner.run([cfg.tool("x8"), "-u", url, "-o", "json"], timeout=300)
                try:
                    data = json.loads(res.stdout)
                    results[url] = data.get("params", [])
                except json.JSONDecodeError:
                    continue
        else:
            log.warning("Neither arjun nor x8 found on PATH — skipping parameter mining.")
    finally:
        Path(input_path).unlink(missing_ok=True)
        Path(out_json).unlink(missing_ok=True)

    total = sum(len(v) for v in results.values())
    log.info(f"[green]{total} hidden parameter(s)[/green] found across {len(results)} URL(s).")
    return results
