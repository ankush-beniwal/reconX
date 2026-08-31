"""
modules/permute_resolve.py
Phase 1 (cont.): Permutation generation (alterx/dnsgen) and mass DNS resolution
(puredns/massdns) against trusted resolvers, to surface active subdomains that
passive sources missed.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from core.config import ReconXConfig
from core.logger import get_logger
from core.process import ProcessRunner
from core.scope import ScopeFilter

log = get_logger(__name__)


async def generate_permutations(runner: ProcessRunner, cfg: ReconXConfig,
                                 subdomains: list[str]) -> list[str]:
    """Prefer alterx (fast, pattern-based); fall back to dnsgen if unavailable."""
    if not subdomains:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        input_path = f.name

    if ProcessRunner.is_available(cfg.tool("alterx")):
        res = await runner.run([cfg.tool("alterx"), "-l", input_path, "-silent"])
    elif ProcessRunner.is_available(cfg.tool("dnsgen")):
        res = await runner.run([cfg.tool("dnsgen"), input_path])
    else:
        log.warning("Neither alterx nor dnsgen found on PATH — skipping permutation phase.")
        Path(input_path).unlink(missing_ok=True)
        return []

    Path(input_path).unlink(missing_ok=True)
    perms = {line.strip().lower() for line in res.stdout.splitlines() if line.strip()}
    log.info(f"Generated {len(perms)} candidate permutations.")
    return sorted(perms)


async def resolve_candidates(runner: ProcessRunner, cfg: ReconXConfig,
                              candidates: list[str]) -> list[str]:
    """Resolve candidate hostnames with puredns (preferred) against trusted resolvers."""
    if not candidates:
        return []

    resolvers_file = cfg.resolvers.get("trusted_resolvers_file")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(candidates))
        input_path = f.name

    resolved: set[str] = set()
    try:
        if ProcessRunner.is_available(cfg.tool("puredns")) and resolvers_file and Path(resolvers_file).exists():
            cmd = [cfg.tool("puredns"), "resolve", input_path, "-r", resolvers_file, "-q"]
            res = await runner.run(cmd, timeout=900)
            resolved = {line.strip().lower() for line in res.stdout.splitlines() if line.strip()}
        elif ProcessRunner.is_available(cfg.tool("massdns")) and resolvers_file:
            cmd = [cfg.tool("massdns"), "-r", resolvers_file, "-t", "A", "-o", "S", input_path]
            res = await runner.run(cmd, timeout=900)
            for line in res.stdout.splitlines():
                if line and " A " in line:
                    resolved.add(line.split(" ")[0].rstrip(".").lower())
        else:
            log.warning("No resolver tool (puredns/massdns) + resolvers file configured — "
                        "skipping active resolution; passive results only.")
    finally:
        Path(input_path).unlink(missing_ok=True)

    log.info(f"[green]{len(resolved)}[/green] candidates resolved to live DNS records.")
    return sorted(resolved)


async def check_takeovers(runner: ProcessRunner, cfg: ReconXConfig, subdomains: list[str]) -> list[dict]:
    """Subdomain takeover checks via nuclei (takeover tag) + subzy as cross-validation."""
    if not subdomains:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        input_path = f.name

    findings: list[dict] = []
    try:
        if ProcessRunner.is_available(cfg.tool("nuclei")):
            res = await runner.run(
                [cfg.tool("nuclei"), "-l", input_path, "-tags", "takeover",
                 "-jsonl", "-silent"],
                timeout=900,
            )
            import json
            for line in res.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    findings.append({
                        "subdomain": obj.get("host") or obj.get("matched-at"),
                        "template": obj.get("template-id"),
                        "tool": "nuclei",
                    })
                except json.JSONDecodeError:
                    continue

        if ProcessRunner.is_available(cfg.tool("subzy")):
            res = await runner.run(
                [cfg.tool("subzy"), "run", "--targets", input_path, "--hide_fails", "--verify_ssl"],
                timeout=900,
            )
            for line in res.stdout.splitlines():
                if "[VULNERABLE]" in line or "vulnerable" in line.lower():
                    findings.append({"subdomain": line.strip(), "template": None, "tool": "subzy"})
    finally:
        Path(input_path).unlink(missing_ok=True)

    if findings:
        log.warning(f"[bold red]{len(findings)} possible subdomain takeover(s) found![/bold red]")
    return findings
