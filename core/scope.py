"""
core/scope.py
Strict in-scope/out-of-scope filtering. Every asset discovered anywhere in the
pipeline MUST pass through ScopeFilter.is_in_scope() before being persisted,
scanned further, or reported. Exclusions (lines prefixed with "!") always win.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path


class ScopeFilter:
    def __init__(self, scope_file: str | Path):
        self.includes: list[re.Pattern] = []
        self.excludes: list[re.Pattern] = []
        self.include_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.exclude_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._load(scope_file)

    def _load(self, scope_file: str | Path):
        p = Path(scope_file)
        if not p.exists():
            raise FileNotFoundError(f"Scope file not found: {p}")

        for raw_line in p.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            is_exclude = line.startswith("!")
            if is_exclude:
                line = line[1:].strip()

            if self._looks_like_cidr(line):
                net = ipaddress.ip_network(line, strict=False)
                (self.exclude_cidrs if is_exclude else self.include_cidrs).append(net)
                continue

            pattern = self._domain_to_regex(line)
            (self.excludes if is_exclude else self.includes).append(pattern)

    @staticmethod
    def _looks_like_cidr(s: str) -> bool:
        return "/" in s and re.match(r"^[\d.:a-fA-F]+/\d+$", s) is not None

    @staticmethod
    def _domain_to_regex(pattern: str) -> re.Pattern:
        # *.example.com  -> ^([a-z0-9-]+\.)*example\.com$
        # example.com    -> ^example\.com$
        escaped = re.escape(pattern).replace(r"\*", "[a-z0-9-]+")
        if pattern.startswith("*."):
            base = re.escape(pattern[2:])
            regex = rf"^([a-z0-9-]+\.)*{base}$"
        else:
            regex = rf"^{escaped}$"
        return re.compile(regex, re.IGNORECASE)

    def is_in_scope(self, asset: str) -> bool:
        """asset can be a hostname or an IP address."""
        asset = asset.strip().lower().rstrip(".")

        # 1. Exclusions always win.
        for rx in self.excludes:
            if rx.match(asset):
                return False
        if self._is_ip(asset):
            ip = ipaddress.ip_address(asset)
            if any(ip in net for net in self.exclude_cidrs):
                return False

        # 2. Must match at least one inclusion rule.
        for rx in self.includes:
            if rx.match(asset):
                return True
        if self._is_ip(asset):
            ip = ipaddress.ip_address(asset)
            if any(ip in net for net in self.include_cidrs):
                return True

        return False

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def filter_list(self, assets: list[str]) -> list[str]:
        return [a for a in assets if self.is_in_scope(a)]
