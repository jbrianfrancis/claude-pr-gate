"""Thin GitHub / Bitbucket / local adapters. All HTTP goes through `http()` so tests can mock it."""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .gate import MARKER
from .review import Finding


def http(method: str, url: str, headers: dict, body: dict | None = None, raw: bool = False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    if data is not None:
        req.add_header("content-type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        payload = r.read()
    if raw:
        return payload.decode("utf-8", "replace")
    return json.loads(payload) if payload else {}


def git_diff(base: str, head: str = "HEAD") -> str:
    return subprocess.run(["git", "diff", "--no-color", f"{base}...{head}"],
                          check=True, capture_output=True, text=True).stdout


def git_show(ref: str, path: str) -> str | None:
    """Contents of `path` at commit `ref`, or None if the file does not exist there."""
    subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                   check=True, capture_output=True)
    spec = f"{ref}:{path.removeprefix('./')}"
    if subprocess.run(["git", "cat-file", "-e", spec], capture_output=True).returncode != 0:
        return None
    return subprocess.run(["git", "show", spec], check=True, capture_output=True, text=True).stdout


class Local:
    """Prints results; used for dry runs and demos."""
    def __init__(self, diff_file: str | None = None, base: str | None = None):
        self.diff_file, self.base = diff_file, base

    def get_diff(self) -> str:
        if self.diff_file:
            with open(self.diff_file) as fh:
                return fh.read()
        return git_diff(self.base or "origin/main")

    def read_base_file(self, path: str) -> str | None:
        if self.diff_file:  # a bare diff file has no base commit; use the working tree
            return Path(path).read_text() if Path(path).exists() else None
        return git_show(self.base or "origin/main", path)

    def post_summary(self, body: str) -> None:
        print(body)

    def post_inline(self, findings: list[Finding]) -> None:
        for f in findings:
            print(f"::{f.severity}:: {f.path}:{f.line} {f.title}")

    def set_status(self, passed: bool, description: str) -> None:
        print(f"STATUS: {'success' if passed else 'failure'} - {description}")


class GitHub:
    def __init__(self, token: str, repo: str, pr: int, sha: str, api: str = "https://api.github.com",
                 base_sha: str | None = None):
        self.repo, self.pr, self.sha, self.api = repo, pr, sha, api.rstrip("/")
        self.base_sha = base_sha
        self.h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                  "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "claude-pr-gate"}

    @classmethod
    def from_env(cls) -> "GitHub":
        with open(os.environ["GITHUB_EVENT_PATH"]) as fh:
            ev = json.load(fh)
        pr = ev["pull_request"]
        return cls(os.environ["GITHUB_TOKEN"], os.environ["GITHUB_REPOSITORY"], pr["number"],
                   pr["head"]["sha"], os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                   base_sha=pr["base"]["sha"])

    def get_diff(self) -> str:
        h = dict(self.h, Accept="application/vnd.github.v3.diff")
        return http("GET", f"{self.api}/repos/{self.repo}/pulls/{self.pr}", h, raw=True)

    def read_base_file(self, path: str) -> str | None:
        if not self.base_sha:
            raise RuntimeError("PR base sha is unknown; refusing to read config from the PR head")
        h = dict(self.h, Accept="application/vnd.github.raw")
        url = (f"{self.api}/repos/{self.repo}/contents/{urllib.parse.quote(path.removeprefix('./'))}"
               f"?ref={self.base_sha}")
        try:
            return http("GET", url, h, raw=True)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def post_summary(self, body: str) -> None:
        # Update our previous comment instead of piling up new ones.
        comments = http("GET", f"{self.api}/repos/{self.repo}/issues/{self.pr}/comments?per_page=100", self.h)
        mine = [c for c in comments if MARKER in (c.get("body") or "")]
        if mine:
            http("PATCH", f"{self.api}/repos/{self.repo}/issues/comments/{mine[-1]['id']}", self.h, {"body": body})
        else:
            http("POST", f"{self.api}/repos/{self.repo}/issues/{self.pr}/comments", self.h, {"body": body})

    def post_inline(self, findings: list[Finding]) -> None:
        if not findings:
            return
        comments = [{"path": f.path, "line": f.line, "side": "RIGHT",
                     "body": f"**{f.severity.upper()}** · {f.category}: **{f.title}**\n\n{f.detail}"}
                    for f in findings]
        http("POST", f"{self.api}/repos/{self.repo}/pulls/{self.pr}/reviews", self.h,
             {"commit_id": self.sha, "event": "COMMENT", "body": "AI PR Gate inline findings", "comments": comments})

    def set_status(self, passed: bool, description: str) -> None:
        http("POST", f"{self.api}/repos/{self.repo}/statuses/{self.sha}", self.h,
             {"state": "success" if passed else "failure", "context": "claude-pr-gate",
              "description": description[:140]})


class Bitbucket:
    def __init__(self, token: str, workspace: str, repo: str, pr: str, sha: str, dest: str,
                 api: str = "https://api.bitbucket.org/2.0"):
        self.base = f"{api}/repositories/{workspace}/{repo}"
        self.pr, self.sha, self.dest = pr, sha, dest
        self.h = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    @classmethod
    def from_env(cls) -> "Bitbucket":
        e = os.environ
        return cls(e["BITBUCKET_ACCESS_TOKEN"], e["BITBUCKET_WORKSPACE"], e["BITBUCKET_REPO_SLUG"],
                   e["BITBUCKET_PR_ID"], e["BITBUCKET_COMMIT"], e.get("BITBUCKET_PR_DESTINATION_BRANCH", "main"))

    def get_diff(self) -> str:
        subprocess.run(["git", "fetch", "origin", self.dest], check=True, capture_output=True)
        return git_diff(f"origin/{self.dest}", self.sha)

    def read_base_file(self, path: str) -> str | None:
        subprocess.run(["git", "fetch", "origin", self.dest], check=True, capture_output=True)
        return git_show(f"origin/{self.dest}", path)

    def post_summary(self, body: str) -> None:
        http("POST", f"{self.base}/pullrequests/{self.pr}/comments", self.h, {"content": {"raw": body}})

    def post_inline(self, findings: list[Finding]) -> None:
        for f in findings:
            http("POST", f"{self.base}/pullrequests/{self.pr}/comments", self.h,
                 {"content": {"raw": f"**{f.severity.upper()}** · {f.category}: **{f.title}**\n\n{f.detail}"},
                  "inline": {"path": f.path, "to": f.line}})

    def set_status(self, passed: bool, description: str) -> None:
        http("POST", f"{self.base}/commit/{self.sha}/statuses/build", self.h,
             {"state": "SUCCESSFUL" if passed else "FAILED", "key": "claude-pr-gate",
              "name": "AI PR Gate", "description": description[:140],
              "url": os.environ.get("BITBUCKET_GIT_HTTP_ORIGIN", "https://bitbucket.org")})
