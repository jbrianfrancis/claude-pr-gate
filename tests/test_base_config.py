"""A PR must not be able to change its own gate by editing .pr-gate.yml (audit PoC 3)."""
import subprocess

import pytest

from pr_gate import cli
from pr_gate.review import Finding, Usage

CRITICAL = [Finding("critical", "security", "RCE", "os.system on request input", "app.py", 1)]


def _git(repo, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=repo,
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    (tmp_path / "README.md").write_text("x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(cli, "review_chunks", lambda cfg, chunks, key: (CRITICAL, Usage()))
    return tmp_path


def _pr_head(repo, head_config):
    """Commit a malicious change plus a PR-supplied .pr-gate.yml on top of the base."""
    (repo / "app.py").write_text("os.system(request.args['c'])\n")
    (repo / ".pr-gate.yml").write_text(head_config)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "pr")


@pytest.mark.parametrize("head_config", ["fail_on: none\n", "ignore_paths: ['**']\n"])
def test_pr_cannot_weaken_gate_when_base_has_no_config(repo, head_config, capsys):
    base = _git(repo, "rev-parse", "HEAD")
    _pr_head(repo, head_config)
    assert cli.main(["--platform", "local", "--base", base]) == 1
    assert "STATUS: failure" in capsys.readouterr().out


def test_config_comes_from_base_commit(repo, capsys):
    (repo / ".pr-gate.yml").write_text("fail_on: critical\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base rules")
    base = _git(repo, "rev-parse", "HEAD")
    _pr_head(repo, "fail_on: none\n")
    assert cli.main(["--platform", "local", "--base", base]) == 1
    out = capsys.readouterr().out
    assert "STATUS: failure" in out and "at or above 'critical'" in out


def test_pr_cannot_set_on_truncate_pass(repo, monkeypatch, capsys):
    monkeypatch.setattr(cli, "review_chunks", lambda cfg, chunks, key: ([], Usage()))
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "big.txt").write_text("x" * 50_000 + "\n")
    _pr_head(repo, "on_truncate: pass\n")
    assert cli.main(["--platform", "local", "--base", base]) == 1
    assert "STATUS: failure - FAIL: 1 file(s) truncated" in capsys.readouterr().out
