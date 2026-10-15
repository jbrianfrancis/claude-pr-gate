"""Parse unified diffs, filter what is safe/useful to send, and chunk."""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatch

REDACTED = "[REDACTED-SECRET]"

# A pattern with a named group "secret" redacts only that group (keeps the key name visible).
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.{0,20000}?-----END [A-Z ]*PRIVATE KEY-----"
               r"|(?:\n[+\- ]?[A-Za-z0-9+/=]{16,})*)", re.S),       # PEM private key block
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                      # AWS access key id
    re.compile(r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),      # Stripe secret / restricted keys
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),                     # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),                   # GitHub fine-grained PAT
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),                     # Anthropic keys
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),                   # Slack tokens
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"),                           # Google API keys
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),  # JWT
]

# Generic `password = "..."` style assignments. The value is redacted only if it looks like a
# real secret (see _looks_secret), so `token = None` or `password = get_password()` survive.
ASSIGNMENT = re.compile(
    r"(?i)\b[A-Za-z0-9_.\-]*(?:key|secret|token|passw(?:or)?d)[A-Za-z0-9_]*[\"']?"
    r"\s*[:=]\s*(?:(?P<q>[\"'])(?P<qv>[^\"'\s]+)(?P=q)|(?P<v>[A-Za-z0-9+/=_\-.~]+)(?![A-Za-z0-9+/=_\-.~(\[]))")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
MIN_SECRET_LEN = 16
MIN_ENTROPY = 3.0   # bits per char


def _entropy(s: str) -> float:
    return -sum(c / len(s) * math.log2(c / len(s)) for c in Counter(s).values())


def _looks_secret(v: str) -> bool:
    return (len(v) >= MIN_SECRET_LEN and _entropy(v) >= MIN_ENTROPY and not UUID.fullmatch(v)
            and any(c.isdigit() for c in v) and any(c.isalpha() for c in v))


@dataclass
class FileDiff:
    path: str
    text: str
    binary: bool = False
    added_lines: set[int] = field(default_factory=set)   # new-file line numbers that were added


@dataclass
class FilterResult:
    files: list[FileDiff]
    skipped: dict[str, str]   # path -> reason
    redactions: int = 0


def _match(path: str, patterns: list[str]) -> bool:
    name = path.rsplit("/", 1)[-1]
    for p in patterns:
        if fnmatch(path, p) or fnmatch(name, p) or (p.startswith("**/") and fnmatch(path, p[3:])):
            return True
    return False


def parse_diff(diff: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    new_line = 0
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line.rstrip("\n"))
            cur = FileDiff(path=m.group(2) if m else line.split()[-1], text="")
            files.append(cur)
        if cur is None:
            continue
        cur.text += line
        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            cur.binary = True
        elif line.startswith("+++ "):
            p = line[4:].strip()
            if p != "/dev/null":
                cur.path = p[2:] if p.startswith("b/") else p
        elif line.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            new_line = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            cur.added_lines.add(new_line)
            new_line += 1
        elif line.startswith(" "):
            new_line += 1
    return files


def _replace_secret(m: re.Match) -> str:
    if "secret" not in m.re.groupindex:
        return REDACTED
    a, b = m.span("secret")
    return m.string[m.start():a] + REDACTED + m.string[b:m.end()]


def redact(text: str, extra_patterns: Sequence[str] = ()) -> tuple[str, int]:
    """Replace secret-looking strings with [REDACTED-SECRET]. `extra_patterns` are regexes from config."""
    n = 0
    for pat in SECRET_PATTERNS + [re.compile(p) for p in extra_patterns]:
        text, k = pat.subn(_replace_secret, text)
        n += k

    def assignment(m: re.Match) -> str:
        nonlocal n
        g = "qv" if m.group("qv") is not None else "v"
        if not _looks_secret(m.group(g)):
            return m.group(0)
        n += 1
        a, b = m.span(g)
        return m.string[m.start():a] + REDACTED + m.string[b:m.end()]
    return ASSIGNMENT.sub(assignment, text), n


def filter_files(files: list[FileDiff], ignore_paths: list[str], secret_paths: list[str],
                 extra_patterns: Sequence[str] = ()) -> FilterResult:
    kept, skipped, redactions = [], {}, 0
    for f in files:
        if f.binary:
            skipped[f.path] = "binary"
        elif _match(f.path, secret_paths):
            skipped[f.path] = "secret-looking file (never sent)"
        elif _match(f.path, ignore_paths):
            skipped[f.path] = "ignored by config"
        else:
            f.text, n = redact(f.text, extra_patterns)
            redactions += n
            kept.append(f)
    return FilterResult(kept, skipped, redactions)


def chunk(files: list[FileDiff], chunk_chars: int, max_total: int) -> tuple[list[str], list[str]]:
    """Group file diffs into chunks. Returns (chunks, truncated_paths).

    Files are never split mid-hunk unless a single file exceeds chunk_chars, in which
    case it is truncated. Once max_total is reached, remaining files are dropped and listed.
    """
    chunks: list[str] = []
    truncated: list[str] = []
    cur, total = "", 0
    for f in files:
        text = f.text
        if len(text) > chunk_chars:
            text = text[:chunk_chars] + "\n[... file diff truncated ...]\n"
            truncated.append(f.path)
        if total + len(text) > max_total:
            truncated.append(f.path)
            continue
        if cur and len(cur) + len(text) > chunk_chars:
            chunks.append(cur)
            cur = ""
        cur += text
        total += len(text)
    if cur:
        chunks.append(cur)
    return chunks, truncated
