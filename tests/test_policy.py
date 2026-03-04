"""
Story: As an operator, I need the policy layer to deterministically map
findings to verdicts using configurable TOML rules, so I can independently
tune response behavior without touching detection code.

Success:
- No findings → ALLOW (when default_allow=True)
- No findings → BLOCK (when default_allow=False, strict mode)
- CRITICAL finding → BLOCK with default config
- HIGH finding → BLOCK with default config
- MEDIUM finding → CONFIRM with default config
- LOW finding → ALLOW with default config
- Per-rule override trumps severity: MEDIUM finding + rule override BLOCK → BLOCK
- Multiple findings: highest escalation wins (BLOCK > CONFIRM > REDIRECT > ALLOW)
- REDIRECT verdict includes redirect_command
- CONFIRM verdict includes confirmation_prompt
"""

import pytest
from bashguard.models import (
    Finding, Severity, VerdictType, ExecutionContext
)
from bashguard.policy import PolicyConfig, RulePolicy, decide


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=f"test finding {rule_id}",
        matched_text="test",
    )


@pytest.fixture
def default_config():
    return PolicyConfig.default()


@pytest.fixture
def ctx():
    return ExecutionContext(cwd="/tmp", allowed_hosts=frozenset())


class TestDefaultConfig:
    def test_no_findings_allow(self, ctx, default_config):
        verdict = decide([], ctx, default_config)
        assert verdict.verdict == VerdictType.ALLOW

    def test_critical_blocks(self, ctx, default_config):
        findings = [_finding("some.rule", Severity.CRITICAL)]
        verdict = decide(findings, ctx, default_config)
        assert verdict.verdict == VerdictType.BLOCK

    def test_high_blocks(self, ctx, default_config):
        findings = [_finding("some.rule", Severity.HIGH)]
        verdict = decide(findings, ctx, default_config)
        assert verdict.verdict == VerdictType.BLOCK

    def test_medium_confirms(self, ctx, default_config):
        findings = [_finding("some.rule", Severity.MEDIUM)]
        verdict = decide(findings, ctx, default_config)
        assert verdict.verdict == VerdictType.CONFIRM

    def test_low_allows(self, ctx, default_config):
        findings = [_finding("some.rule", Severity.LOW)]
        verdict = decide(findings, ctx, default_config)
        assert verdict.verdict == VerdictType.ALLOW

    def test_info_allows(self, ctx, default_config):
        findings = [_finding("some.rule", Severity.INFO)]
        verdict = decide(findings, ctx, default_config)
        assert verdict.verdict == VerdictType.ALLOW


class TestStrictMode:
    def test_no_findings_block_in_strict_mode(self, ctx):
        config = PolicyConfig(default_allow=False)
        verdict = decide([], ctx, config)
        assert verdict.verdict == VerdictType.BLOCK


class TestRuleOverrides:
    def test_rule_override_trumps_severity(self, ctx):
        config = PolicyConfig(
            rule_overrides=[
                RulePolicy(rule_id="net.unknown_host", verdict=VerdictType.BLOCK)
            ]
        )
        # MEDIUM finding, but rule says BLOCK
        findings = [_finding("net.unknown_host", Severity.MEDIUM)]
        verdict = decide(findings, ctx, config)
        assert verdict.verdict == VerdictType.BLOCK

    def test_redirect_includes_command(self, ctx):
        config = PolicyConfig(
            rule_overrides=[
                RulePolicy(
                    rule_id="git.force_push",
                    verdict=VerdictType.REDIRECT,
                    redirect_template="echo BLOCKED: force push",
                )
            ]
        )
        findings = [_finding("git.force_push", Severity.HIGH)]
        verdict = decide(findings, ctx, config)
        assert verdict.verdict == VerdictType.REDIRECT
        assert verdict.redirect_command is not None

    def test_confirm_includes_prompt(self, ctx):
        config = PolicyConfig(
            rule_overrides=[
                RulePolicy(
                    rule_id="pkg.global_install",
                    verdict=VerdictType.CONFIRM,
                    confirmation_prompt="Allow global package install?",
                )
            ]
        )
        findings = [_finding("pkg.global_install", Severity.MEDIUM)]
        verdict = decide(findings, ctx, config)
        assert verdict.verdict == VerdictType.CONFIRM
        assert verdict.confirmation_prompt is not None


class TestEscalation:
    def test_block_beats_confirm(self, ctx):
        config = PolicyConfig(
            severity_verdicts={
                Severity.HIGH: VerdictType.BLOCK,
                Severity.MEDIUM: VerdictType.CONFIRM,
            }
        )
        findings = [
            _finding("rule.a", Severity.HIGH),
            _finding("rule.b", Severity.MEDIUM),
        ]
        verdict = decide(findings, ctx, config)
        assert verdict.verdict == VerdictType.BLOCK

    def test_all_findings_present_in_verdict(self, ctx, default_config):
        findings = [
            _finding("rule.a", Severity.CRITICAL),
            _finding("rule.b", Severity.HIGH),
        ]
        verdict = decide(findings, ctx, default_config)
        assert len(verdict.findings) == 2

    def test_verdict_message_not_empty(self, ctx, default_config):
        findings = [_finding("some.rule", Severity.CRITICAL)]
        verdict = decide(findings, ctx, default_config)
        assert verdict.message


class TestRedirectPayload:
    """Story: prompt executor needs redirect_tool/args/resolved to call safe tools directly."""

    def _finding_with_meta(self, rule_id: str, metadata: dict) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=Severity.LOW,
            message="redirect test",
            matched_text="test cmd",
            metadata=metadata,
        )

    def test_fully_resolved_when_all_template_vars_in_metadata(self, ctx):
        config = PolicyConfig(rule_overrides=[
            RulePolicy(
                rule_id="cat.file",
                verdict=VerdictType.REDIRECT,
                redirect_tool="read_file",
                redirect_args_template={"path": "{path}"},
            )
        ])
        finding = self._finding_with_meta("cat.file", {"path": "README.md"})
        verdict = decide([finding], ctx, config)
        assert verdict.verdict == VerdictType.REDIRECT
        assert verdict.redirect_tool == "read_file"
        assert verdict.redirect_args == {"path": "README.md"}
        assert verdict.redirect_resolved is True

    def test_unresolved_when_template_var_missing_from_metadata(self, ctx):
        config = PolicyConfig(rule_overrides=[
            RulePolicy(
                rule_id="cat.file",
                verdict=VerdictType.REDIRECT,
                redirect_tool="read_file",
                redirect_args_template={"path": "{path}"},
            )
        ])
        finding = self._finding_with_meta("cat.file", {})  # no path in metadata
        verdict = decide([finding], ctx, config)
        assert verdict.redirect_tool == "read_file"
        assert verdict.redirect_args == {"path": None}
        assert verdict.redirect_resolved is False

    def test_no_args_template_is_always_resolved(self, ctx):
        config = PolicyConfig(rule_overrides=[
            RulePolicy(
                rule_id="git.status",
                verdict=VerdictType.REDIRECT,
                redirect_tool="git_status",
                redirect_args_template={},
            )
        ])
        finding = self._finding_with_meta("git.status", {})
        verdict = decide([finding], ctx, config)
        assert verdict.redirect_tool == "git_status"
        assert verdict.redirect_args == {}
        assert verdict.redirect_resolved is True

    def test_literal_arg_values_are_always_resolved(self, ctx):
        config = PolicyConfig(rule_overrides=[
            RulePolicy(
                rule_id="git.log",
                verdict=VerdictType.REDIRECT,
                redirect_tool="git_log",
                redirect_args_template={"n": 10},  # literal int default
            )
        ])
        finding = self._finding_with_meta("git.log", {})
        verdict = decide([finding], ctx, config)
        assert verdict.redirect_args == {"n": 10}
        assert verdict.redirect_resolved is True

    def test_redirect_tool_none_when_verdict_not_redirect(self, ctx, default_config):
        findings = [_finding("some.rule", Severity.CRITICAL)]
        verdict = decide(findings, ctx, default_config)
        assert verdict.verdict == VerdictType.BLOCK
        assert verdict.redirect_tool is None
        assert verdict.redirect_args is None
        assert verdict.redirect_resolved is False


class TestPolicyConfigLoad:
    def test_default_config_is_valid(self):
        config = PolicyConfig.default()
        assert config.default_allow is True
        assert Severity.CRITICAL in config.severity_verdicts
        assert config.severity_verdicts[Severity.CRITICAL] == VerdictType.BLOCK
