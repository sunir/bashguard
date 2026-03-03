"""
Story: As a security operator, I need a regression suite of known-dangerous
commands so that each new rule addition and any future change can be validated
against a documented threat model.

This corpus is the ground truth. If a test here fails, either:
  a) A rule regressed (fix the rule), or
  b) The threat model changed (update the corpus with intent).

Never silently accept a failure here.
"""

import os
import pytest
import yaml

from bash_audit.auditor import audit
from bash_audit.context import make_context
from bash_audit.models import VerdictType, ExecutionContext
from bash_audit.policy import PolicyConfig, decide

_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "corpus.yaml")


def _load_corpus():
    with open(_CORPUS_PATH) as f:
        return yaml.safe_load(f)


def _make_id(entry: dict) -> str:
    cmd = entry["command"][:50].replace(" ", "_").replace("/", "_")
    return f"{entry['expected_verdict']}__{cmd}"


_CORPUS = _load_corpus()


@pytest.fixture(scope="module")
def ctx():
    return ExecutionContext(cwd="/tmp", allowed_hosts=frozenset())


@pytest.fixture(scope="module")
def config():
    return PolicyConfig.default()


@pytest.mark.parametrize("entry", _CORPUS, ids=[_make_id(e) for e in _CORPUS])
def test_corpus_entry(entry, ctx, config):
    command = entry["command"]
    expected_verdict = entry["expected_verdict"]
    expected_rules = set(entry.get("expected_rules", []))

    findings = audit(command, ctx)
    verdict = decide(findings, ctx, config)

    actual_rule_ids = {f.rule_id for f in findings}
    actual_verdict = verdict.verdict.value

    # Check expected rules all fired
    missing_rules = expected_rules - actual_rule_ids
    assert not missing_rules, (
        f"Command: {command!r}\n"
        f"Expected rules: {expected_rules}\n"
        f"Missing rules: {missing_rules}\n"
        f"Got rules: {actual_rule_ids}"
    )

    # Check verdict matches
    assert actual_verdict == expected_verdict, (
        f"Command: {command!r}\n"
        f"Expected verdict: {expected_verdict}\n"
        f"Got verdict: {actual_verdict}\n"
        f"Findings: {[(f.rule_id, f.severity.value, f.message) for f in findings]}"
    )
