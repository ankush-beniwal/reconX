"""
reporting/report_generator.py
Generates JSON, Markdown, and HTML summary reports from the full scan_result
dict produced by the orchestrator.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import markdown2

from core.logger import get_logger

log = get_logger(__name__)

MD_TEMPLATE = """# ReconX Report — {target}
Generated: {timestamp}

## Summary
| Metric | Count |
|---|---|
| Subdomains | {n_subdomains} |
| Live HTTP hosts | {n_live} |
| Open ports | {n_ports} |
| Endpoints | {n_endpoints} |
| JS secrets flagged | {n_secrets} |
| Takeover candidates | {n_takeovers} |
| Vulnerabilities (nuclei) | {n_vulns} |
| Misconfig heuristics | {n_misconfig} |

## Subdomain Takeover Candidates
{takeover_section}

## Vulnerabilities
{vuln_section}

## Exposed Secrets (JS Analysis)
{secrets_section}

## Misconfiguration Heuristics (CORS / Open Redirect / SSRF)
{misconfig_section}

## Live Hosts
{live_hosts_section}
"""


def _bullet_list(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items) if items else "_None found._"


def generate_markdown(scan_result: dict) -> str:
    target = scan_result["target"]
    subs = scan_result.get("subdomains", [])
    live = scan_result.get("live_hosts", [])
    ports = scan_result.get("open_ports", {})
    endpoints = scan_result.get("endpoints", [])
    secrets = scan_result.get("secrets", [])
    takeovers = scan_result.get("takeovers", [])
    vulns = scan_result.get("vulnerabilities", [])
    misconfig = scan_result.get("misconfig_findings", [])

    takeover_lines = [f"`{t.get('subdomain')}` — template: {t.get('template') or t.get('tool')}" for t in takeovers]
    vuln_lines = [f"**[{v.get('severity','?').upper()}]** `{v.get('url')}` — {v.get('description')} "
                  f"({v.get('template_id')})" for v in vulns]
    secret_lines = [f"`{s.get('js_url')}` — {s.get('type')}: `{s.get('snippet')}`" for s in secrets]
    misconfig_lines = [f"`{m.get('url')}` — {m.get('issue')}: {m.get('detail')}" for m in misconfig]
    live_lines = [f"`{h.get('url')}` [{h.get('status_code')}] {h.get('title','')} "
                  f"— tech: {h.get('tech','-')}, cdn: {h.get('cdn','-')}" for h in live]

    total_ports = sum(len(v) for v in ports.values())

    return MD_TEMPLATE.format(
        target=target,
        timestamp=datetime.utcnow().isoformat() + "Z",
        n_subdomains=len(subs), n_live=len(live), n_ports=total_ports,
        n_endpoints=len(endpoints), n_secrets=len(secrets), n_takeovers=len(takeovers),
        n_vulns=len(vulns), n_misconfig=len(misconfig),
        takeover_section=_bullet_list(takeover_lines),
        vuln_section=_bullet_list(vuln_lines),
        secrets_section=_bullet_list(secret_lines),
        misconfig_section=_bullet_list(misconfig_lines),
        live_hosts_section=_bullet_list(live_lines),
    )


def generate_html(markdown_text: str) -> str:
    body = markdown2.markdown(markdown_text, extras=["tables", "fenced-code-blocks"])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ReconX Report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #f4f4f4; }}
code {{ background: #f0f0f0; padding: 1px 5px; border-radius: 3px; }}
h1, h2 {{ border-bottom: 2px solid #eee; padding-bottom: 6px; }}
</style></head><body>
{body}
</body></html>"""


def write_reports(scan_result: dict, output_dir: Path, formats: list[str]) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    target_safe = scan_result["target"].replace("*", "wildcard").replace("/", "_")
    written = {}

    if "json" in formats:
        json_path = output_dir / f"{target_safe}_report.json"
        json_path.write_text(json.dumps(scan_result, indent=2, default=str))
        written["json"] = json_path

    md_text = generate_markdown(scan_result)
    if "markdown" in formats:
        md_path = output_dir / f"{target_safe}_report.md"
        md_path.write_text(md_text)
        written["markdown"] = md_path

    if "html" in formats:
        html_path = output_dir / f"{target_safe}_report.html"
        html_path.write_text(generate_html(md_text))
        written["html"] = html_path

    log.info(f"[green]Reports written:[/green] {', '.join(str(p) for p in written.values())}")
    return written
