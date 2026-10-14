"""Demo app must work on a fresh install (audit E2E finding E1: HTTP 500, 'no such table: notes')."""
import importlib.util
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "demo-app" / "app.py"


def test_fresh_db_returns_404_not_500(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)   # notes.db is created relative to the working directory
    spec = importlib.util.spec_from_file_location("demo_app", APP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (tmp_path / "notes.db").exists()
    resp = mod.app.test_client().get("/notes/1")
    assert resp.status_code == 404 and resp.get_json() == {"error": "not found"}
