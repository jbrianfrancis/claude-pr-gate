"""End-to-end runs of the example PR scenarios with the model mocked."""
from pathlib import Path

import pytest

from pr_gate.cli import run
from pr_gate.config import load_config
from helpers import FakePlatform, RecordingCaller, fake_response

ROOT = Path(__file__).resolve().parent.parent
SC = ROOT / "examples" / "scenarios"
CFG = load_config(ROOT / ".pr-gate.yml")


def test_sql_injection_fails_with_inline_comments():
    plat = FakePlatform((SC / "01-sql-injection.diff").read_text())
    caller = RecordingCaller(fake_response([
        {"severity": "critical", "category": "security", "title": "SQL injection", "detail": "bind params",
         "path": "demo-app/app.py", "line": 26},
        {"severity": "low", "rule": "no-print-debug", "category": "no-print-debug", "title": "print",
         "detail": "rm", "path": "demo-app/app.py", "line": 25},
        {"severity": "medium", "category": "quality", "title": "context line", "detail": "d",
         "path": "demo-app/app.py", "line": 18},   # not an added line -> no inline comment
    ]))
    assert run(plat, CFG, "k", caller=caller) == 1
    assert plat.status[0] is False and "FAIL" in plat.status[1]
    assert "❌ FAIL" in plat.summary and "SQL injection" in plat.summary
    assert [f.line for f in plat.inline] == [26, 25]


def test_secrets_never_sent():
    plat = FakePlatform((SC / "02-secrets-and-shell.diff").read_text())
    caller = RecordingCaller(fake_response([{"severity": "high", "category": "security",
                                             "title": "Command injection", "detail": "shell=True",
                                             "path": "demo-app/export.py", "line": 9}]))
    assert run(plat, CFG, "k", caller=caller) == 1
    sent = "".join(caller.prompts)
    assert "sk_live" not in sent and "AKIAABCDEFGHIJKLMNOP" not in sent and ".env" not in sent
    assert "logo.png" not in sent
    assert "`.env` (secret-looking file (never sent))" in plat.summary
    assert "1 secret-looking string(s) were redacted" in plat.summary


def test_clean_pr_passes():
    plat = FakePlatform((SC / "03-clean-refactor.diff").read_text())
    assert run(plat, CFG, "k", caller=RecordingCaller(fake_response([]))) == 0
    assert plat.status == (True, "PASS") and "No issues found" in plat.summary
    assert plat.inline is None


def test_fail_open_on_api_error_when_opted_in():
    cfg = load_config(ROOT / ".pr-gate.yml", {"on_error": "open"})
    plat = FakePlatform((SC / "03-clean-refactor.diff").read_text())
    assert run(plat, cfg, "k", caller=RecordingCaller(RuntimeError("API down"))) == 0
    assert plat.status[0] is True and "fail-open" in plat.summary


def test_fail_closed_on_api_error_by_default():
    plat = FakePlatform((SC / "03-clean-refactor.diff").read_text())
    assert CFG.on_error == "closed" and load_config(None).on_error == "closed"
    assert run(plat, CFG, "k", caller=RecordingCaller(RuntimeError("API down"))) == 1
    assert plat.status == (False, "FAIL: gate error") and "fail-closed" in plat.summary


def test_missing_key_respects_policy():
    plat = FakePlatform("")
    assert run(plat, load_config(None, {"on_error": "closed"}), "") == 1
    assert "ANTHROPIC_API_KEY is not set" in plat.summary


def test_only_ignored_files_means_no_api_call():
    diff = "diff --git a/yarn.lock b/yarn.lock\n+++ b/yarn.lock\n@@ -0,0 +1 @@\n+x\n"
    caller = RecordingCaller(RuntimeError("should not be called"))
    plat = FakePlatform(diff)
    assert run(plat, CFG, "k", caller=caller) == 0 and caller.prompts == []


EVIL = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,0 +1,1 @@\n+os.system(request.args['c'])\n"


def _text_reply(text):
    return {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": 10, "output_tokens": 5}}


@pytest.mark.parametrize("on_error", ["closed", "open"])
@pytest.mark.parametrize("reply", ["Sure! Looks fine.", "{not json}", '{"verdict": "ok"}', '{"findings": "none"}'])
def test_unparseable_model_reply_fails(on_error, reply):
    """Audit PoC 1: a prompt-injected diff makes the model answer in prose. That must never PASS."""
    plat = FakePlatform(EVIL)
    cfg = load_config(ROOT / ".pr-gate.yml", {"on_error": on_error})
    assert run(plat, cfg, "k", caller=RecordingCaller(_text_reply(reply))) == 1
    assert plat.status == (False, "FAIL: gate error") and "fail-closed" in plat.summary


def _file_diff(path, body):
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,1 @@\n+{body}\n"


def _top_line(summary):
    return summary.splitlines()[1]


def test_payload_past_chunk_truncation_does_not_pass():
    """Audit PoC 2b: malicious code after the 40 KB per-file cut is never sent to the model."""
    big = _file_diff("app.py", "x" * 40_000).rstrip("\n") + "\n+os.system(request.args['c'])\n"
    caller = RecordingCaller(fake_response([]))
    plat = FakePlatform(big)
    assert run(plat, CFG, "k", caller=caller) == 1
    assert "os.system" not in "".join(caller.prompts)
    assert plat.status[0] is False and plat.status[1].startswith("FAIL: 1 file(s) truncated")
    assert "❌ FAIL" in _top_line(plat.summary) and "not fully reviewed" in _top_line(plat.summary)


def test_padded_diff_over_budget_does_not_pass():
    """Audit PoC 2: big benign files push the diff past max_diff_chars."""
    pad = _file_diff("big.txt", "x" * 39_000) * 4
    caller = RecordingCaller(fake_response([]))
    plat = FakePlatform(pad + EVIL)
    assert run(plat, CFG, "k", caller=caller) == 1
    assert plat.status[0] is False and "truncated" in plat.status[1]
    assert "not fully reviewed" in _top_line(plat.summary)


def test_on_truncate_pass_still_flags_truncation():
    cfg = load_config(ROOT / ".pr-gate.yml", {"on_truncate": "pass"})
    plat = FakePlatform(_file_diff("app.py", "x" * 40_001))
    assert run(plat, cfg, "k", caller=RecordingCaller(fake_response([]))) == 0
    assert plat.status[0] is True and "not fully reviewed" in plat.status[1]
    assert "✅ PASS" in _top_line(plat.summary) and "not fully reviewed" in _top_line(plat.summary)
