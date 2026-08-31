#!/usr/bin/env python3
"""
ReconX — Automated Recon & Asset Discovery Framework
main.py: CLI entrypoint. Parses args, loads config, drives the orchestrator.

Usage examples:
    python main.py -d example.com
    python main.py -d example.com -c config.yaml --force
    python main.py -l targets.txt --diff
    python main.py -d example.com --only subdomain_enum,http_probe
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from core.config import load_config_or_exit
from core.logger import get_logger, setup_logging
from core.orchestrator import Orchestrator

log = get_logger("reconx.main")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — modular, high-performance recon framework for bug bounty / pentest asset discovery.",
    )
    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-d", "--domain", help="Single root domain to scan (e.g. example.com)")
    target_group.add_argument("-l", "--list", help="Path to a file with one root domain per line")

    p.add_argument("-c", "--config", default="config.yaml", help="Path to config.yaml (default: ./config.yaml)")
    p.add_argument("--force", action="store_true", help="Ignore resume state; re-run all phases from scratch")
    p.add_argument("--diff", action="store_true", help="Enable diff mode: alert only on newly discovered assets")
    p.add_argument("--only", help="Comma-separated list of phases to run (e.g. subdomain_enum,http_probe)")
    p.add_argument("--no-report", action="store_true", help="Skip writing JSON/Markdown/HTML reports")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


def load_targets(args: argparse.Namespace) -> list[str]:
    if args.domain:
        return [args.domain.strip().lower()]
    path = Path(args.list)
    if not path.exists():
        log.error(f"[red]Target list file not found:[/red] {path}")
        sys.exit(1)
    lines = [ln.strip().lower() for ln in path.read_text().splitlines()]
    return [ln for ln in lines if ln and not ln.startswith("#")]


async def run(args: argparse.Namespace):
    cfg = load_config_or_exit(args.config)

    setup_logging(level="DEBUG" if args.verbose else cfg.general.get("log_level", "INFO"))

    if args.diff:
        cfg.raw["general"]["diff_mode"] = True

    targets = load_targets(args)
    log.info(f"[bold cyan]ReconX[/bold cyan] starting — {len(targets)} target(s), "
              f"concurrency={cfg.general.get('concurrency')}, "
              f"rate_limit={cfg.general.get('rate_limit_rps')} rps")

    orchestrator = Orchestrator(cfg, force=args.force)
    await orchestrator.setup()

    try:
        for target in targets:
            log.info(f"\n[bold magenta]==== Target: {target} ====[/bold magenta]")
            result = await orchestrator.run_target(target)
            if result.get("error"):
                log.error(f"Skipped {target}: {result['error']}")
                continue
            if not args.no_report:
                orchestrator.build_report(result)
            _print_summary(target, result)
    finally:
        await orchestrator.teardown()


def _print_summary(target: str, result: dict):
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title=f"ReconX Summary — {target}")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="bold green")

    total_ports = sum(len(v) for v in result.get("open_ports", {}).values())
    table.add_row("Subdomains", str(len(result.get("subdomains", []))))
    table.add_row("Live HTTP hosts", str(len(result.get("live_hosts", []))))
    table.add_row("Open ports", str(total_ports))
    table.add_row("Endpoints", str(len(result.get("endpoints", []))))
    table.add_row("JS secrets flagged", str(len(result.get("secrets", []))))
    table.add_row("Takeover candidates", str(len(result.get("takeovers", []))))
    table.add_row("Vulnerabilities (nuclei)", str(len(result.get("vulnerabilities", []))))
    table.add_row("Misconfig heuristics", str(len(result.get("misconfig_findings", []))))
    console.print(table)


def main():
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        log.warning("\n[yellow]Interrupted by user — state saved, safe to resume later.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
