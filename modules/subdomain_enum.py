"""
modules/subdomain_enum.py
Phase 1: Passive subdomain discovery via subfinder, assetfinder, amass (passive),
findomain, and crt.sh. Runs all sources concurrently, merges + dedups results.
"""
from __future__ import annotations

import json

import aiohttp

from core.config import ReconXConfig
from core.database import ReconDB
from core.logger import get_logger
from core.process import ProcessRunner
from core.scope import ScopeFilter

log = get_logger(__name__)


async def _run_subfinder(runner: ProcessRunner, cfg: ReconXConfig, domain: str) -> set[str]:
    cmd = [cfg.tool("subfinder"), "-d", domain, "-silent", "-all"]
    if cfg.api_keys.get("chaos"):
        cmd += ["-provider-config", "-"]  # placeholder; users typically configure ~/.config/subfinder/provider-config.yaml
    res = await runner.run(cmd)
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


async def _run_assetfinder(runner: ProcessRunner, cfg: ReconXConfig, domain: str) -> set[str]:
    res = await runner.run([cfg.tool("assetfinder"), "--subs-only", domain])
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


async def _run_amass(runner: ProcessRunner, cfg: ReconXConfig, domain: str) -> set[str]:
    res = await runner.run([cfg.tool("amass"), "enum", "-passive", "-d", domain, "-silent"])
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


async def _run_findomain(runner: ProcessRunner, cfg: ReconXConfig, domain: str) -> set[str]:
    res = await runner.run([cfg.tool("findomain"), "-t", domain, "-q"])
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


async def _run_crtsh(domain: str) -> set[str]:
    """crt.sh certificate transparency query — no binary needed, pure HTTP."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found: set[str] = set()
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return found
                text = await resp.text()
                data = json.loads(text)
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            found.add(name)
    except Exception as e:
        log.debug(f"crt.sh query failed for {domain}: {e}")
    return found


async def enumerate_subdomains(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                                scope: ScopeFilter, domain: str) -> list[str]:
    """Runs all passive sources concurrently, merges, scope-filters, persists."""
    import asyncio

    log.info(f"[cyan]Phase 1[/cyan] — enumerating subdomains for [bold]{domain}[/bold]")

    tasks = {
        "subfinder": _run_subfinder(runner, cfg, domain),
        "assetfinder": _run_assetfinder(runner, cfg, domain),
        "amass": _run_amass(runner, cfg, domain),
        "findomain": _run_findomain(runner, cfg, domain),
        "crtsh": _run_crtsh(domain),
    }
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    merged: dict[str, set[str]] = {}  # subdomain -> sources
    for source, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            log.warning(f"{source} failed: {result}")
            continue
        for sub in result:
            sub = sub.strip().lower().rstrip(".")
            if not sub:
                continue
            merged.setdefault(sub, set()).add(source)

    in_scope = {s: srcs for s, srcs in merged.items() if scope.is_in_scope(s)}
    dropped = len(merged) - len(in_scope)
    if dropped:
        log.info(f"Scope filter dropped {dropped} out-of-scope subdomain(s).")

    new_count = 0
    for sub, srcs in in_scope.items():
        is_new = await db.add_subdomain(domain, sub, source=",".join(sorted(srcs)))
        new_count += int(is_new)

    log.info(f"[green]Found {len(in_scope)} in-scope subdomains[/green] "
              f"({new_count} new) for {domain}")
    return sorted(in_scope.keys())
