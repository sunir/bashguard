"""Tests for .bashguard.yaml project-local config (ratcheting only — can tighten, never relax)."""
import pytest
import yaml

from bashguard.project_config import ProjectConfig, load_project_config, merge_configs


class TestProjectConfig:
    def test_load_from_yaml(self, tmp_path):
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "policy": {
                "severity": {
                    "medium": "block",  # tightening: allow→block
                }
            }
        }))
        cfg = load_project_config(cfg_path)
        assert cfg is not None
        assert cfg.severity_overrides.get("medium") == "block"

    def test_missing_file_returns_none(self, tmp_path):
        cfg = load_project_config(tmp_path / ".bashguard.yaml")
        assert cfg is None

    def test_empty_yaml_returns_empty_config(self, tmp_path):
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text("")
        cfg = load_project_config(cfg_path)
        assert cfg is not None
        assert cfg.severity_overrides == {}
        assert cfg.rule_overrides == {}

    def test_rule_overrides_loaded(self, tmp_path):
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "rules": [
                {"rule_id": "network.unknown_host", "verdict": "block"},
                {"rule_id": "git.destructive", "verdict": "block"},
            ]
        }))
        cfg = load_project_config(cfg_path)
        assert cfg.rule_overrides["network.unknown_host"] == "block"
        assert cfg.rule_overrides["git.destructive"] == "block"

    def test_additional_allowed_hosts(self, tmp_path):
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "context": {
                "allowed_hosts": ["internal.corp.com", "private-registry.io"]
            }
        }))
        cfg = load_project_config(cfg_path)
        assert "internal.corp.com" in cfg.additional_allowed_hosts
        assert "private-registry.io" in cfg.additional_allowed_hosts


class TestRatcheting:
    """Ratcheting: project config can only tighten policy, never relax.

    Tightening order: allow < confirm < block
    A project can move allow→block but NOT block→allow.
    """

    def _base_policy_config(self):
        from bashguard.policy import PolicyConfig
        return PolicyConfig.default()

    def test_tightening_severity_is_applied(self, tmp_path):
        """medium=confirm → medium=block is a tightening — allowed."""
        from bashguard.models import Severity
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "policy": {"severity": {"medium": "block"}}
        }))
        project = load_project_config(cfg_path)
        base = self._base_policy_config()
        merged = merge_configs(base, project)
        assert merged.severity_verdicts[Severity.MEDIUM].value == "block"

    def test_relaxing_severity_is_ignored(self, tmp_path):
        """critical=block → critical=allow is a relaxation — silently ignored."""
        from bashguard.models import Severity
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "policy": {"severity": {"critical": "allow"}}
        }))
        project = load_project_config(cfg_path)
        base = self._base_policy_config()
        merged = merge_configs(base, project)
        assert merged.severity_verdicts[Severity.CRITICAL].value == "block"

    def test_tightening_rule_is_applied(self, tmp_path):
        """Rule confirm→block is a tightening — allowed."""
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "rules": [{"rule_id": "git.destructive", "verdict": "block"}]
        }))
        project = load_project_config(cfg_path)
        base = self._base_policy_config()
        merged = merge_configs(base, project)
        rule = next((r for r in merged.rule_overrides if r.rule_id == "git.destructive"), None)
        assert rule is not None
        assert rule.verdict.value == "block"

    def test_relaxing_rule_is_ignored(self, tmp_path):
        """Rule block→allow is a relaxation — silently ignored."""
        from bashguard.models import VerdictType
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "rules": [{"rule_id": "network.unknown_host", "verdict": "allow"}]
        }))
        project = load_project_config(cfg_path)
        base = self._base_policy_config()
        merged = merge_configs(base, project)
        rule = next((r for r in merged.rule_overrides if r.rule_id == "network.unknown_host"), None)
        # Either rule not added, or remains at block
        if rule is not None:
            assert rule.verdict != VerdictType.ALLOW

    def test_new_rule_block_is_tightening(self, tmp_path):
        """A new rule (not in base) with verdict=block is always a tightening."""
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "rules": [{"rule_id": "custom.no_curl", "verdict": "block"}]
        }))
        project = load_project_config(cfg_path)
        base = self._base_policy_config()
        merged = merge_configs(base, project)
        rule = next((r for r in merged.rule_overrides if r.rule_id == "custom.no_curl"), None)
        assert rule is not None
        assert rule.verdict.value == "block"

    def test_project_config_cannot_remove_rules(self, tmp_path):
        """A project config cannot disable built-in rules."""
        cfg_path = tmp_path / ".bashguard.yaml"
        cfg_path.write_text(yaml.dump({
            "rules": [{"rule_id": "destructive.irreversible", "verdict": "allow"}]
        }))
        project = load_project_config(cfg_path)
        base = self._base_policy_config()
        merged = merge_configs(base, project)
        rule = next((r for r in merged.rule_overrides if r.rule_id == "destructive.irreversible"), None)
        if rule is not None:
            from bashguard.models import VerdictType
            assert rule.verdict != VerdictType.ALLOW
