"""Decide PASS/FAIL and render the summary comment."""
from __future__ import annotations

from collections import Counter

from .config import SEVERITIES, Config
from .review import Finding, Usage

MARKER = "<!-- claude-pr-gate -->"
ICON = {"critical": "🛑", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}
# USD per million tokens (input, output). Update when pricing changes.
# Most specific prefix wins. Source: Anthropic pricing page, Oct 2026.
PRICES = {"sonnet-5": (2.0, 10.0), "opus-5": (4.0, 20.0),
          "sonnet": (3.0, 15.0), "haiku": (1.0, 5.0), "opus": (15.0, 75.0)}


def rank(sev: str) -> int:
    return SEVERITIES.index(sev)


def decide(cfg: Config, findings: list[Finding]) -> tuple[bool, list[str]]:
    reasons = []
    if cfg.fail_on != "none":
        bad = [f for f in findings if rank(f.severity) >= rank(cfg.fail_on)]
        if bad:
            reasons.append(f"{len(bad)} finding(s) at or above '{cfg.fail_on}'")
    counts = Counter(f.severity for f in findings)
    for sev, limit in cfg.max_findings.items():
        if counts[sev] > int(limit):
            reasons.append(f"{counts[sev]} '{sev}' findings (limit {limit})")
    return (not reasons), reasons


def estimate_cost(model: str, usage: Usage) -> float:
    family = next((k for k in PRICES if k in model), "sonnet-5")
    pin, pout = PRICES[family]
    return usage.input_tokens / 1e6 * pin + usage.output_tokens / 1e6 * pout


def render_summary(cfg: Config, passed: bool, reasons: list[str], findings: list[Finding],
                   skipped: dict[str, str], truncated: list[str], usage: Usage,
                   redactions: int = 0, error: str | None = None) -> str:
    lines = [MARKER]
    status = "✅ PASS" if passed else "❌ FAIL"
    lines.append(f"## AI PR Gate: {status}")
    if error:
        lines.append(f"\n> ⚠️ The gate could not complete: `{error}` → "
                     f"{'passing (fail-open, `on_error: open`)' if passed else 'failing (fail-closed)'}.")
    for r in reasons:
        lines.append(f"- {r}")
    if findings:
        lines.append("\n| Severity | Category | Location | Finding |\n|---|---|---|---|")
        for f in sorted(findings, key=lambda f: -rank(f.severity)):
            loc = f"`{f.path}:{f.line}`" if f.path and f.line else (f"`{f.path}`" if f.path else "")
            lines.append(f"| {ICON[f.severity]} {f.severity} | {f.category} | {loc} | **{_esc(f.title)}**: {_esc(f.detail)} |")
    elif not error:
        lines.append("\nNo issues found in the reviewed changes.")
    notes = []
    if skipped:
        notes.append("Not sent to the model: " + ", ".join(f"`{p}` ({r})" for p, r in sorted(skipped.items())))
    if truncated:
        notes.append("Truncated or over budget (partially/not reviewed): " + ", ".join(f"`{p}`" for p in truncated))
    if redactions:
        notes.append(f"{redactions} secret-looking string(s) were redacted before review.")
    if notes:
        lines.append("\n<details><summary>Review scope</summary>\n\n" + "\n".join(f"- {n}" for n in notes) + "\n</details>")
    lines.append(f"\n<sub>model `{cfg.model}` · {usage.input_tokens:,} in / {usage.output_tokens:,} out tokens · "
                 f"≈${estimate_cost(cfg.model, usage):.3f}</sub>")
    return "\n".join(lines)


def _esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")
