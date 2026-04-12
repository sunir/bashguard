"""
bashguard.rules.test_harness — Test infrastructure tampering detection.

Grounded in Berkeley RDI "Trustworthy Benchmarks" (2025):
- SWE-bench attack: create conftest.py injecting pytest hooks that force ALL tests
  to report "passed" — 100% success rate on 500 + 731 instances.
- SWE-bench Pro: overwrite installed library files (django/__init__.py) so the
  import graph itself produces the desired output.

Both attacks defeat the test verification layer entirely.  If an agent can write
to conftest.py or any site-packages file, every subsequent pytest run is
untrustworthy.

Rules:
  test_harness.conftest_inject   — Write to conftest.py → SYSTEM_CONFIG / CRITICAL
  test_harness.site_packages_inject — Write to site-packages dir → SYSTEM_CONFIG / CRITICAL
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

# tree-sitter node types that represent write operators
_WRITE_OPERATORS = {">", ">>"}

# Commands that copy or move files (destination is last positional arg)
_COPY_MOVE_CMDS = {"cp", "mv"}
# Commands that write to tee targets
_TEE_CMDS = {"tee"}


def _is_conftest_target(path: str) -> bool:
    """True if path is a conftest.py write target (any nesting depth)."""
    clean = path.strip("'\"")
    return clean == "conftest.py" or clean.endswith("/conftest.py")


def _is_site_packages_target(path: str) -> bool:
    """True if path is inside a site-packages directory."""
    clean = path.strip("'\"")
    return "site-packages/" in clean or clean.endswith("site-packages")


def _walk_write_redirects(node, source: bytes, targets: list[str]) -> None:
    """Walk the CST collecting file_redirect write-target paths."""
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
    """Return all write-redirect target paths from the CST."""
    try:
        source = script.encode("utf-8", errors="replace")
        tree = _PARSER.parse(source)
        targets: list[str] = []
        _walk_write_redirects(tree.root_node, source, targets)
        return targets
    except Exception:
        return []


def _cmd_write_targets(script: str, match_fn) -> list[str]:
    """
    Return args from cp/mv/tee commands that are write destinations and match match_fn.

    - cp/mv: destination is the final positional arg
    - tee: all positional args are output destinations
    """
    hits: list[str] = []
    try:
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name in _TEE_CMDS:
                for arg in cmd.args:
                    if match_fn(arg):
                        hits.append(arg)
            elif cmd.name in _COPY_MOVE_CMDS:
                # destination = last positional arg (skip flags)
                if cmd.args:
                    dest = cmd.args[-1]
                    if match_fn(dest):
                        hits.append(dest)
    except Exception:
        pass
    return hits


@register
class ConftestInjectRule:
    """
    Flag any write to conftest.py.

    conftest.py files are loaded by pytest before any test runs.  A
    @pytest.hookimpl(hookwrapper=True) on pytest_runtest_makereport can set
    rep.outcome = "passed" for every test — no code fix required.

    Incident: SWE-bench 2025 (Berkeley RDI).  Success rate: 100 %.
    """

    rule_id = "test_harness.conftest_inject"
    severity = Severity.CRITICAL
    description = "Write to conftest.py — injects pytest hooks that force tests to pass"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []

            # 1. Shell redirect targets (>, >>)
            for target in _redirect_targets(script):
                if _is_conftest_target(target):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        message=f"Write to conftest.py: pytest hook injection vector (Berkeley RDI 2025)",
                        matched_text=target.strip("'\""),
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))

            # 2. cp/mv/tee destinations
            for target in _cmd_write_targets(script, _is_conftest_target):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    message=f"Write to conftest.py via {target}: pytest hook injection vector",
                    matched_text=target.strip("'\""),
                    action_type=ActionType.SYSTEM_CONFIG,
                ))

            return findings
        except Exception as e:
            _log.error("ConftestInjectRule raised: %s", e, exc_info=True)
            return []


@register
class SitePackagesInjectRule:
    """
    Flag any write into a Python site-packages directory.

    Overwriting an installed package file (e.g. django/__init__.py) changes
    the behaviour of every import of that package — including the test runner
    itself.  The monkey-patch can make any test return the expected result
    without actually fixing the underlying code.

    Also catches .venv/lib/.../site-packages/ (local virtualenv), which is NOT
    covered by paths.protected_write (which only blocks /usr/, /lib/, etc.).

    Incident: SWE-bench Pro 2025 (Berkeley RDI).
    """

    rule_id = "test_harness.site_packages_inject"
    severity = Severity.CRITICAL
    description = "Write to site-packages — monkey-patches installed library behaviour"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []

            # 1. Shell redirect targets
            for target in _redirect_targets(script):
                if _is_site_packages_target(target):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        message=f"Write to site-packages path: library monkey-patch vector",
                        matched_text=target.strip("'\""),
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))

            # 2. cp/mv/tee destinations
            for target in _cmd_write_targets(script, _is_site_packages_target):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    message=f"Write to site-packages via {target}: library monkey-patch vector",
                    matched_text=target.strip("'\""),
                    action_type=ActionType.SYSTEM_CONFIG,
                ))

            return findings
        except Exception as e:
            _log.error("SitePackagesInjectRule raised: %s", e, exc_info=True)
            return []
