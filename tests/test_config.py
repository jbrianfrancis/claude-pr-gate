import pytest

from pr_gate.config import ConfigError, load_config


def test_defaults_when_missing(tmp_path):
    cfg = load_config(tmp_path / "nope.yml")
    assert cfg.fail_on == "high" and cfg.on_error == "closed" and cfg.on_truncate == "fail"
    assert cfg.model.startswith("claude-sonnet")


def test_ignore_paths_extend_defaults(tmp_path):
    p = tmp_path / ".pr-gate.yml"
    p.write_text("ignore_paths: ['docs/**']\nfail_on: medium\n")
    cfg = load_config(p)
    assert "docs/**" in cfg.ignore_paths and "**/*.lock" in cfg.ignore_paths
    assert cfg.fail_on == "medium"


def test_override_model(tmp_path):
    assert load_config(None, {"model": "claude-haiku-4-5"}).model == "claude-haiku-4-5"
    assert load_config(None, {"model": ""}).model.startswith("claude-sonnet")


@pytest.mark.parametrize("yml", ["fail_on: severe", "on_error: maybe", "bogus: 1",
                                 "custom_rules: [{id: x}]", "max_findings: {huge: 1}",
                                 "on_truncate: maybe"])
def test_invalid(tmp_path, yml):
    p = tmp_path / "c.yml"
    p.write_text(yml)
    with pytest.raises(ConfigError):
        load_config(p)


def test_repo_example_config_is_valid():
    from conftest import ROOT
    cfg = load_config(ROOT / ".pr-gate.yml")
    assert {r["id"] for r in cfg.custom_rules} == {"no-print-debug", "sql-params"}
