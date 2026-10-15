"""Secret redaction: on the diff before the model call, and on model text before it is posted."""
import pytest

from pr_gate.cli import run
from pr_gate.config import ConfigError, load_config
from pr_gate.diff import redact
from helpers import FakePlatform, RecordingCaller, fake_response

# Fake secrets are assembled at runtime so this file never contains a scannable credential.
R = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY"          # 32 random-looking chars
STRIPE_LIVE = "sk_" + "live_" + R[:24]
STRIPE_RESTRICTED = "rk_" + "live_" + R[:24]
STRIPE_TEST = "sk_" + "test_" + R[:24]
AWS_ID = "AKIA" + "Q2W3E4R5T6Y7U8I9"
AWS_STS_ID = "ASIA" + "Q2W3E4R5T6Y7U8I9"
AWS_SECRET = (R + "/+Zz9Yy8X")[:40]
GH = {p: p + "_" + R + "abcd" for p in ("ghp", "gho", "ghu", "ghs", "ghr")}
GH_PAT = "github_" + "pat_" + "11ABCDEFG0" + R
SLACK = "xox" + "b-" + "123456789012-" + R[:24]
GOOGLE = "AI" + "za" + (R + "_-abc")[:35]
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
PEM_BODY = ["MIIEowIBAAKCAQEA7bq3" + R, "Zx8y7W6v5U4t3S2r1Q0p" + R, "kL2mN4pQ6rS8tU0vW1xY"]
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "\n".join(PEM_BODY) + "\n-----END RSA PRIVATE KEY-----"

CASES = {
    "stripe-live": (f'STRIPE = "{STRIPE_LIVE}"', STRIPE_LIVE),
    "stripe-restricted": (f"key: {STRIPE_RESTRICTED}", STRIPE_RESTRICTED),
    "stripe-test": (f"stripe.api_key = '{STRIPE_TEST}'", STRIPE_TEST),
    "aws-id": (f"aws_id = {AWS_ID}", AWS_ID),
    "aws-sts-id": (f"creds({AWS_STS_ID!r})", AWS_STS_ID),
    "aws-secret": (f"aws_secret_access_key = {AWS_SECRET}", AWS_SECRET),
    **{f"github-{p}": (f'gh_auth("{t}")', t) for p, t in GH.items()},
    "github-pat": (f"auth={GH_PAT}", GH_PAT),
    "slack": (f'post("{SLACK}")', SLACK),
    "google": (f"const MAPS = '{GOOGLE}';", GOOGLE),
    "jwt": (f"headers['Authorization'] = 'Bearer {JWT}'", JWT),
    "generic-api-key": ('API_KEY="Zt8q2Lr5Vx9Nc4Kp7Hw3"', "Zt8q2Lr5Vx9Nc4Kp7Hw3"),
    "generic-secret-colon": ("client_secret: Zt8q2Lr5Vx9Nc4Kp7Hw3", "Zt8q2Lr5Vx9Nc4Kp7Hw3"),
    "generic-token-json": ('"token": "Zt8q2Lr5Vx9Nc4Kp7Hw3"', "Zt8q2Lr5Vx9Nc4Kp7Hw3"),
    "generic-password": ("DB_PASSWORD=Zt8q2Lr5Vx9Nc4Kp7Hw3", "Zt8q2Lr5Vx9Nc4Kp7Hw3"),
    "generic-key": ("KEY = 'Zt8q2Lr5Vx9Nc4Kp7Hw3'", "Zt8q2Lr5Vx9Nc4Kp7Hw3"),
}


def _diff(*lines, path="app/settings.py"):
    body = "".join(f"+{l}\n" for l in lines)
    return (f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{body}")


def _run(diff, findings=(), cfg=None):
    plat = FakePlatform(diff)
    caller = RecordingCaller(fake_response(list(findings)))
    run(plat, cfg or load_config(None), "k", caller=caller)
    return plat, caller


@pytest.mark.parametrize("line,secret", CASES.values(), ids=CASES.keys())
def test_secret_never_reaches_model(line, secret):
    plat, caller = _run(_diff("import os", line, "print('ok')"))
    sent = "".join(caller.prompts)
    assert caller.prompts and secret not in sent
    assert "[REDACTED-SECRET]" in sent and "import os" in sent and "print('ok')" in sent
    assert "1 secret-looking string(s) were redacted" in plat.summary


def test_pem_block_fully_redacted():
    lines = ["KEY_PEM = '''", *PEM.splitlines(), "'''", "after = 1"]
    plat, caller = _run(_diff(*lines))
    sent = "".join(caller.prompts)
    assert all(b not in sent for b in PEM_BODY) and "END RSA PRIVATE KEY" not in sent
    assert "after = 1" in sent


def test_pem_header_without_end_still_redacts_body():
    text, n = redact("-----BEGIN " + "PRIVATE KEY-----\n+" + PEM_BODY[0] + "\n+x = 1")
    assert n == 1 and PEM_BODY[0] not in text and "x = 1" in text


def test_extra_patterns_from_config(tmp_path):
    p = tmp_path / ".pr-gate.yml"
    p.write_text("redact_patterns: ['acme_[0-9a-f]{12}', 'INTERNAL-[A-Z]{6}']\n")
    cfg = load_config(p)
    assert cfg.redact_patterns == ["acme_[0-9a-f]{12}", "INTERNAL-[A-Z]{6}"]
    plat, caller = _run(_diff("t = 'acme_0123456789ab'", "host = INTERNAL-ABCDEF"), cfg=cfg)
    sent = "".join(caller.prompts)
    assert "acme_0123456789ab" not in sent and "INTERNAL-ABCDEF" not in sent


@pytest.mark.parametrize("yml", ["redact_patterns: ['([a-z']", "redact_patterns: 'abc'", "redact_patterns: [1]"])
def test_bad_redact_patterns_are_config_errors(tmp_path, yml):
    p = tmp_path / ".pr-gate.yml"
    p.write_text(yml)
    with pytest.raises(ConfigError, match="redact_patterns"):
        load_config(p)


def test_model_echoed_secret_is_redacted_before_posting(tmp_path):
    p = tmp_path / ".pr-gate.yml"
    p.write_text("redact_patterns: ['acme_[0-9a-f]{12}']\n")
    cfg = load_config(p)
    echoed = [{"severity": "high", "category": f"leak {GOOGLE}", "title": f"Hardcoded {STRIPE_LIVE}",
               "detail": f"Rotate {AWS_ID} and acme_0123456789ab now", "path": "app/settings.py", "line": 1}]
    plat, _ = _run(_diff("x = 1"), echoed, cfg=cfg)
    posted = [plat.summary] + [f"{f.category} {f.title} {f.detail}" for f in plat.inline]
    for body in posted:
        for s in (GOOGLE, STRIPE_LIVE, AWS_ID, "acme_0123456789ab"):
            assert s not in body
        assert "[REDACTED-SECRET]" in body
    assert "Rotate" in plat.inline[0].detail


def test_error_text_in_summary_is_redacted():
    plat = FakePlatform(_diff("x = 1"))
    run(plat, load_config(None), "k", caller=RecordingCaller(RuntimeError(f"bad key {STRIPE_LIVE}")))
    assert STRIPE_LIVE not in plat.summary and "[REDACTED-SECRET]" in plat.summary


ORDINARY = """\
+token = None
+password = get_password()
+password = os.environ["DB_PASSWORD"]
+self.token = request.headers.get("X-Token")
+api_key = settings.ANTHROPIC_API_KEY
+secret_key_name = "default"
+cache_key = f"user:{user_id}:profile"
+primary_key = "id"
+MAX_TOKENS = 4096
+token_count = len(tokens)
+password_hash = bcrypt.hashpw(password, salt)
+def refresh_token(token: str) -> str:
+request_id = "550e8400-e29b-41d4-a716-446655440000"
+idempotency_key = "550e8400-e29b-41d4-a716-446655440000"
+"integrity": "sha512-3xyQ0Wk1RPKvE8cFyPj2X1yR8hJ4kN3Vb6sFzq0pL5mW9oTaB2cD4eF6gH8iJ0kL",
+checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
+commit = "7c3f20d9a1b2c3d4e5f60718293a4b5c6d7e8f90"
+FIXTURE = "SGVsbG8sIHdvcmxkISBUaGlzIGlzIHRlc3QgZGF0YS4="
+resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c"
+password = "hunter2"
+token = "abc"
+password = "aaaaaaaaaaaaaaaaaaaa"
+# Set GITHUB_TOKEN and ANTHROPIC_API_KEY in repo secrets.
+if not key: raise KeyError(key)
"""


def test_no_over_redaction_on_ordinary_code():
    text, n = redact(ORDINARY)
    assert (text, n) == (ORDINARY, 0)
