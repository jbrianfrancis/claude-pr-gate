"""Entry point: python -m pr_gate [--platform github|bitbucket|local]."""
from __future__ import annotations

import argparse
import os
import sys

from .config import parse_config
from .diff import chunk, filter_files, parse_diff
from .gate import decide, render_summary
from .platforms import Bitbucket, GitHub, Local
from .review import ModelOutputError, Usage, review_chunks


def make_platform(name: str, args):
    if name == "github":
        return GitHub.from_env()
    if name == "bitbucket":
        return Bitbucket.from_env()
    return Local(args.diff_file, args.base)


def run(platform, cfg, api_key: str, caller=None) -> int:
    findings, usage, skipped, truncated, redactions, error = [], Usage(), {}, [], 0, None
    try:
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        files = parse_diff(platform.get_diff())
        res = filter_files(files, cfg.ignore_paths, cfg.secret_paths)
        skipped, redactions = res.skipped, res.redactions
        chunks, truncated = chunk(res.files, cfg.chunk_chars, cfg.max_diff_chars)
        truncated = list(dict.fromkeys(truncated))  # a file can be both truncated and over budget
        if chunks:
            kw = {"caller": caller} if caller else {}
            findings, usage = review_chunks(cfg, chunks, api_key, **kw)
        # keep inline comments only on lines actually added in this PR
        added = {f.path: f.added_lines for f in res.files}
        passed, reasons = decide(cfg, findings, truncated)
    except Exception as e:  # noqa: BLE001 - gate policy decides what an error means
        error = f"{type(e).__name__}: {e}"
        # A diff can steer the model into a non-JSON reply, so that always fails, whatever on_error says.
        passed = cfg.on_error == "open" and not isinstance(e, ModelOutputError)
        reasons, added = [], {}

    body = render_summary(cfg, passed, reasons, findings, skipped, truncated, usage, redactions, error)
    platform.post_summary(body)
    if cfg.inline_comments and findings:
        inline = [f for f in findings if f.path in added and f.line in added[f.path]][: cfg.max_inline_comments]
        try:
            platform.post_inline(inline)
        except Exception as e:  # inline comments are best-effort
            print(f"warning: inline comments failed: {e}", file=sys.stderr)
    desc = "PASS" if passed else ("FAIL: " + "; ".join(reasons) if reasons else "FAIL: gate error")
    if passed and truncated and error is None:
        desc = f"PASS, but {len(truncated)} file(s) truncated and not fully reviewed (on_truncate: pass)"
    platform.set_status(passed, desc)
    return 0 if passed else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pr-gate")
    p.add_argument("--platform", choices=["github", "bitbucket", "local"], default="local")
    p.add_argument("--config", default=".pr-gate.yml")
    p.add_argument("--model")
    p.add_argument("--diff-file", help="local mode: review this diff file")
    p.add_argument("--base", help="local mode: git base ref (default origin/main)")
    args = p.parse_args(argv)
    platform = make_platform(args.platform, args)
    # Rules come from the PR's base commit, never its head, so a PR cannot loosen its own gate.
    cfg = parse_config(platform.read_base_file(args.config),
                       {"model": args.model or os.environ.get("PR_GATE_MODEL")})
    return run(platform, cfg, os.environ.get("ANTHROPIC_API_KEY", ""))


if __name__ == "__main__":
    sys.exit(main())
