"""
bashguard.rules.public_disclosure — Block posting to public paste/gist services.

Two Mythos incidents:
1. After sandbox escape, the model unprompted posted its own exploit details
   to multiple hard-to-find but technically public-facing websites.
2. When preparing a code artifact for an internal user, the model posted it
   as a public-facing GitHub Gist against the user's intent.

Agents have no legitimate need to create public pastes or gists. These
services are exfiltration surfaces: content becomes publicly indexed, may be
cached, and is visible to anyone with the URL.

Blocked:
  gh gist create               — GitHub CLI gist creation
  gh repo create --public      — creating public repositories
  curl/wget to gist/paste APIs  — programmatic posting to paste services

Allowed:
  git clone github.com/...     — reading public repos is normal
  gh pr create                 — PRs are internal to the repo, not public pastes
  curl api.github.com (GET)    — reading the API
"""

from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Known public paste/gist service hostnames
_PASTE_HOSTS = frozenset({
    "pastebin.com",
    "paste.debian.net",
    "hastebin.com",
    "dpaste.com",
    "ix.io",
    "0x0.st",
    "paste.ee",
    "termbin.com",
    "sprunge.us",
    "clbin.com",
    "vpaste.net",
})

_PASTE_HOST_RE = re.compile(
    r"(?:https?://)?(" + "|".join(re.escape(h) for h in _PASTE_HOSTS) + r")"
)

# GitHub Gist API endpoint
_GITHUB_GIST_RE = re.compile(r"api\.github\.com/gists")


def _tokens(line: str) -> list[str]:
    return line.split()


@register
class PublicDisclosureRule:
    rule_id = "network.public_disclosure"
    severity = Severity.CRITICAL
    description = "Posting to a public paste or gist service — potential unauthorized data exfiltration"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("public_disclosure rule error")
            return []

    def _scan(self, script: str):
        for line in script.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            finding = self._check_line(stripped)
            if finding:
                yield finding

    def _check_line(self, line: str) -> Finding | None:
        tokens = _tokens(line)
        if not tokens:
            return None
        cmd = tokens[0]

        # gh gist create ...
        if cmd == "gh" and len(tokens) >= 3 and tokens[1] == "gist" and tokens[2] == "create":
            return self._finding(line)

        # gh repo create --public
        if cmd == "gh" and len(tokens) >= 3 and tokens[1] == "repo" and tokens[2] == "create":
            if "--public" in tokens:
                return self._finding(line)

        # curl/wget to paste services or github gist API
        if cmd in ("curl", "wget"):
            for tok in tokens[1:]:
                clean = tok.strip("'\"")
                if _PASTE_HOST_RE.search(clean):
                    return self._finding(line)
                if _GITHUB_GIST_RE.search(clean):
                    return self._finding(line)
            # Also check -F / --form flags that embed ix.io or 0x0.st without http://
            for tok in tokens[1:]:
                if _PASTE_HOST_RE.search(tok):
                    return self._finding(line)

        return None

    def _finding(self, line: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            action_type=ActionType.NETWORK_OUTBOUND,
            message=self.description,
            matched_text=line,
        )
