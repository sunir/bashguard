"""
bashguard.rules.ci_workflow_inject — Detect writes to CI/CD configuration files.

CI/CD workflows execute with access to repository secrets (deploy keys, API
tokens, registry credentials) that the in-session agent cannot directly read.
Writing a malicious workflow and triggering it via a push or PR gives the
attacker indirect access to those secrets.

Attack chain:
  agent writes .github/workflows/evil.yml
  → push or PR triggers GitHub Actions runner
  → runner mounts GITHUB_TOKEN + all repo secrets as env vars
  → workflow exfiltrates them to an attacker endpoint
  → agent never needed to read secrets directly

Real-world incidents:
  - Codecov bash uploader breach (2021) — CI script modification to exfil env
  - CircleCI breach (2023) — malicious CI config change exfiltrated secrets
  - Multiple supply chain attacks via `.github/workflows/*.yml` injection

Rule:
  ci.workflow_inject  (CRITICAL) — write to any CI/CD config path
"""
from __future__ import annotations

import logging

import tree_sitter_bash as tsb
from tree_sitter import Language, Parser as TSParser

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_LANG = Language(tsb.language())
_PARSER = TSParser(_LANG)

_WRITE_OPERATORS = {">", ">>"}
_COPY_MOVE_CMDS = {"cp", "mv"}
_TEE_CMDS = {"tee"}

# CI/CD file paths — any write here is suspicious
# Exact filenames (at repo root or anywhere in path)
_CI_FILENAMES = frozenset({
    "Jenkinsfile",
    ".travis.yml",
    "azure-pipelines.yml",
    ".drone.yml",
    ".drone.star",
})

# Directory prefixes — any file inside these dirs
_CI_DIR_PREFIXES = (
    ".github/workflows/",
    ".circleci/",
    ".buildkite/",
    ".teamcity/",
)


def _is_ci_target(path: str) -> bool:
    """True if path is a CI/CD configuration write target."""
    clean = path.strip("'\"")
    # Exact filename match (basename)
    basename = clean.rsplit("/", 1)[-1] if "/" in clean else clean
    if basename in _CI_FILENAMES:
        return True
    # Directory prefix match
    if any(clean.startswith(p) or ("/" + p) in clean for p in _CI_DIR_PREFIXES):
        return True
    # GitLab CI can be anywhere: .gitlab-ci.yml
    if basename == ".gitlab-ci.yml":
        return True
    return False


def _walk_write_redirects(node, source: bytes, targets: list[str]) -> None:
    if node.type == "file_redirect":
        operator = None
        target = None
        for child in node.children:
            if child.type in _WRITE_OPERATORS:
                operator = child.type
            elif child.type in ("word", "string", "raw_string", "concatenation"):
                target = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        if operator and target:
            targets.append(target)
    for child in node.children:
        _walk_write_redirects(child, source, targets)


def _redirect_targets(script: str) -> list[str]:
    try:
        source = script.encode("utf-8", errors="replace")
        tree = _PARSER.parse(source)
        targets: list[str] = []
        _walk_write_redirects(tree.root_node, source, targets)
        return targets
    except Exception:
        return []


@register
class CiWorkflowInjectRule:
    """
    Flag any write to CI/CD pipeline configuration files.

    CI pipelines run with access to repository secrets that the in-session
    agent cannot read directly.  Creating or modifying a workflow file is an
    indirect path to those secrets.  The attack requires only a push or PR —
    no additional agent activity needed after the write.

    Covers: GitHub Actions (.github/workflows/), CircleCI (.circleci/),
    Jenkins (Jenkinsfile), GitLab CI (.gitlab-ci.yml), Travis (.travis.yml),
    Azure Pipelines (azure-pipelines.yml), Drone (.drone.yml),
    Buildkite (.buildkite/).

    Incidents: Codecov 2021, CircleCI 2023, multiple supply-chain attacks.
    """

    rule_id = "ci.workflow_inject"
    severity = Severity.CRITICAL
    description = "Write to CI/CD config file — indirect access to pipeline secrets"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []

            # 1. Shell redirect targets (>, >>)
            for target in _redirect_targets(script):
                if _is_ci_target(target):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        message="Write to CI/CD config: indirect access to pipeline secrets via workflow trigger",
                        matched_text=target.strip("'\""),
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))

            # 2. cp/mv/tee destinations
            try:
                cmds = parse(script)
                for cmd in cmds:
                    if cmd.name in _TEE_CMDS:
                        for arg in cmd.args:
                            if _is_ci_target(arg):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.CRITICAL,
                                    message="tee to CI/CD config: indirect access to pipeline secrets",
                                    matched_text=arg.strip("'\""),
                                    action_type=ActionType.SYSTEM_CONFIG,
                                ))
                    elif cmd.name in _COPY_MOVE_CMDS:
                        if cmd.args and _is_ci_target(cmd.args[-1]):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=Severity.CRITICAL,
                                message=f"{cmd.name} to CI/CD config: indirect access to pipeline secrets",
                                matched_text=cmd.args[-1].strip("'\""),
                                action_type=ActionType.SYSTEM_CONFIG,
                            ))
            except Exception:
                pass

            return findings
        except Exception as e:
            _log.error("CiWorkflowInjectRule raised: %s", e, exc_info=True)
            return []
