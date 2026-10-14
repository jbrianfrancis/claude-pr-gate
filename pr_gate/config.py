"""Load and validate .pr-gate.yml."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ["info", "low", "medium", "high", "critical"]

DEFAULTS: dict[str, Any] = {
    "model": "claude-sonnet-5-5",
    "max_tokens": 4096,
    "fail_on": "high",            # lowest severity that fails the gate
    "max_findings": {},           # e.g. {"medium": 5}: fail if more than 5 medium findings
    "on_error": "closed",         # "closed" = fail if the gate itself errors; "open" = pass
    "categories": ["security", "quality"],
    "ignore_paths": ["**/*.lock", "**/package-lock.json", "**/dist/**", "**/vendor/**", "**/*.min.js"],
    "secret_paths": ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/id_rsa*",
                     "**/*.p12", "**/*.pfx", "**/credentials*", "**/secrets*.y*ml"],
    "max_diff_chars": 120_000,    # total diff budget sent to the model
    "chunk_chars": 40_000,        # per-request chunk size
    "on_truncate": "fail",        # "fail" = fail if any file is truncated or over budget; "pass" = pass, flagged
    "inline_comments": True,
    "max_inline_comments": 15,
    "custom_rules": [],           # list of {id, description, severity}
}


@dataclass
class Config:
    model: str
    max_tokens: int
    fail_on: str
    max_findings: dict[str, int]
    on_error: str
    categories: list[str]
    ignore_paths: list[str]
    secret_paths: list[str]
    max_diff_chars: int
    chunk_chars: int
    on_truncate: str
    inline_comments: bool
    max_inline_comments: int
    custom_rules: list[dict[str, Any]] = field(default_factory=list)


class ConfigError(ValueError):
    pass


def load_config(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Config:
    text = Path(path).read_text() if path and Path(path).exists() else None
    return parse_config(text, overrides)


def parse_config(text: str | None, overrides: dict[str, Any] | None = None) -> Config:
    """Build a Config from .pr-gate.yml text. None means the file is absent: use defaults."""
    data = copy.deepcopy(DEFAULTS)
    if text is not None:
        loaded = yaml.safe_load(text) or {}
        if not isinstance(loaded, dict):
            raise ConfigError(".pr-gate.yml must be a mapping")
        # ignore_paths extends the defaults rather than replacing them
        extra_ignores = loaded.pop("ignore_paths", None)
        extra_secrets = loaded.pop("secret_paths", None)
        unknown = set(loaded) - set(DEFAULTS)
        if unknown:
            raise ConfigError(f"Unknown config keys: {sorted(unknown)}")
        data.update(loaded)
        if extra_ignores:
            data["ignore_paths"] = data["ignore_paths"] + list(extra_ignores)
        if extra_secrets:
            data["secret_paths"] = data["secret_paths"] + list(extra_secrets)
    for k, v in (overrides or {}).items():
        if v not in (None, ""):
            data[k] = v
    _validate(data)
    return Config(**data)


def _validate(d: dict[str, Any]) -> None:
    if d["fail_on"] not in SEVERITIES + ["none"]:
        raise ConfigError(f"fail_on must be one of {SEVERITIES + ['none']}")
    if d["on_error"] not in ("open", "closed"):
        raise ConfigError("on_error must be 'open' or 'closed'")
    if d["on_truncate"] not in ("fail", "pass"):
        raise ConfigError("on_truncate must be 'fail' or 'pass'")
    for sev in d["max_findings"]:
        if sev not in SEVERITIES:
            raise ConfigError(f"max_findings key {sev!r} is not a severity")
    for r in d["custom_rules"]:
        if not isinstance(r, dict) or "id" not in r or "description" not in r:
            raise ConfigError("each custom rule needs 'id' and 'description'")
        if r.get("severity", "medium") not in SEVERITIES:
            raise ConfigError(f"custom rule {r['id']}: bad severity")
    d["max_tokens"] = int(d["max_tokens"])
    d["max_diff_chars"] = int(d["max_diff_chars"])
    d["chunk_chars"] = int(d["chunk_chars"])
