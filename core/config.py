"""
core/config.py
Loads and validates config.yaml. Fails fast with clear errors so
misconfiguration never causes silent partial scans.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


@dataclass
class ReconXConfig:
    raw: dict[str, Any]
    path: Path

    # --- convenience accessors -------------------------------------------------
    @property
    def general(self) -> dict:
        return self.raw.get("general", {})

    @property
    def tool_paths(self) -> dict:
        return self.raw.get("tool_paths", {})

    @property
    def resolvers(self) -> dict:
        return self.raw.get("resolvers", {})

    @property
    def wordlists(self) -> dict:
        return self.raw.get("wordlists", {})

    @property
    def api_keys(self) -> dict:
        return self.raw.get("api_keys", {})

    @property
    def ports(self) -> dict:
        return self.raw.get("ports", {})

    @property
    def nuclei(self) -> dict:
        return self.raw.get("nuclei", {})

    @property
    def notifications(self) -> dict:
        return self.raw.get("notifications", {})

    @property
    def reporting(self) -> dict:
        return self.raw.get("reporting", {})

    def tool(self, name: str) -> str:
        """Resolve a tool binary path/name, allowing env-var overrides:
        RECONX_TOOL_<NAME> takes precedence over config.yaml."""
        env_key = f"RECONX_TOOL_{name.upper()}"
        return os.environ.get(env_key, self.tool_paths.get(name, name))

    def output_dir(self) -> Path:
        p = Path(self.general.get("output_dir", "./data/results"))
        p.mkdir(parents=True, exist_ok=True)
        return p

    def db_path(self) -> Path:
        p = Path(self.general.get("db_path", "./data/reconx.db"))
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


def load_config(path: str | Path = "config.yaml") -> ReconXConfig:
    p = Path(path)
    if not p.exists():
        raise ConfigError(
            f"Config file not found at '{p}'. Copy config.yaml.example -> config.yaml"
        )
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Malformed YAML in {p}: {e}") from e

    required_sections = ["general", "tool_paths"]
    missing = [s for s in required_sections if s not in data]
    if missing:
        raise ConfigError(f"config.yaml missing required sections: {missing}")

    return ReconXConfig(raw=data, path=p)


def load_config_or_exit(path: str | Path = "config.yaml") -> ReconXConfig:
    try:
        return load_config(path)
    except ConfigError as e:
        print(f"[FATAL] Config error: {e}", file=sys.stderr)
        sys.exit(1)
