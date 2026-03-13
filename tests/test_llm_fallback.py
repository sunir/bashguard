"""Tests for LLM fallback for CONFIRM cases.

Design:
- LLM fallback is opt-in (requires BASHGUARD_LLM_FALLBACK=1 env or config)
- Called only for CONFIRM verdicts, not BLOCK/ALLOW/REDIRECT
- LLM receives: script, findings, context summary
- LLM returns: "allow" | "block" | "confirm" verdict string
- Timeout = 10s. Fallback to original CONFIRM on timeout or error
- The LLM endpoint is configured via BASHGUARD_LLM_URL + BASHGUARD_LLM_KEY env vars
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from bashguard.llm_fallback import LLMFallbackConfig, llm_review
from bashguard.models import Finding, Severity, Verdict, VerdictType, ActionType


def _finding(rule_id="test.rule", sev=Severity.MEDIUM):
    return Finding(
        rule_id=rule_id,
        severity=sev,
        message="test finding",
        matched_text="test cmd",
    )


def _confirm_verdict(findings=None):
    if findings is None:
        findings = (_finding(),)
    return Verdict(
        verdict=VerdictType.CONFIRM,
        findings=tuple(findings),
        message="Confirm this command?",
        confirmation_prompt="Should this run?",
    )


class TestLLMFallbackConfig:
    def test_default_config_is_disabled(self):
        cfg = LLMFallbackConfig.default()
        assert not cfg.enabled

    def test_from_env_no_vars(self, monkeypatch):
        monkeypatch.delenv("BASHGUARD_LLM_FALLBACK", raising=False)
        cfg = LLMFallbackConfig.from_env()
        assert not cfg.enabled

    def test_from_env_enabled(self, monkeypatch):
        monkeypatch.setenv("BASHGUARD_LLM_FALLBACK", "1")
        monkeypatch.setenv("BASHGUARD_LLM_KEY", "sk-test-key")
        cfg = LLMFallbackConfig.from_env()
        assert cfg.enabled
        assert cfg.api_key == "sk-test-key"

    def test_from_env_custom_url(self, monkeypatch):
        monkeypatch.setenv("BASHGUARD_LLM_FALLBACK", "1")
        monkeypatch.setenv("BASHGUARD_LLM_URL", "https://my-llm.example.com/v1")
        monkeypatch.setenv("BASHGUARD_LLM_KEY", "key")
        cfg = LLMFallbackConfig.from_env()
        assert cfg.api_url == "https://my-llm.example.com/v1"


class TestLLMReview:
    def test_returns_original_if_disabled(self):
        cfg = LLMFallbackConfig(enabled=False)
        verdict = _confirm_verdict()
        result = llm_review(verdict, script="echo hello", config=cfg)
        assert result.verdict == VerdictType.CONFIRM
        assert result is verdict  # unchanged

    def test_only_reviews_confirm_verdicts(self):
        cfg = LLMFallbackConfig(enabled=True, api_key="key")
        block_verdict = Verdict(
            verdict=VerdictType.BLOCK,
            findings=(_finding(),),
            message="blocked",
        )
        result = llm_review(block_verdict, script="rm -rf /", config=cfg)
        assert result is block_verdict  # BLOCK never goes to LLM

    def test_allow_verdict_not_sent_to_llm(self):
        cfg = LLMFallbackConfig(enabled=True, api_key="key")
        allow_verdict = Verdict(
            verdict=VerdictType.ALLOW,
            findings=(),
            message="ok",
        )
        result = llm_review(allow_verdict, script="echo hello", config=cfg)
        assert result is allow_verdict

    def test_llm_allow_response_upgrades_confirm(self):
        cfg = LLMFallbackConfig(enabled=True, api_key="key")
        verdict = _confirm_verdict()

        with patch("bashguard.llm_fallback._call_llm") as mock_llm:
            mock_llm.return_value = "allow"
            result = llm_review(verdict, script="git status", config=cfg)

        assert result.verdict == VerdictType.ALLOW

    def test_llm_block_response_escalates_confirm(self):
        cfg = LLMFallbackConfig(enabled=True, api_key="key")
        verdict = _confirm_verdict()

        with patch("bashguard.llm_fallback._call_llm") as mock_llm:
            mock_llm.return_value = "block"
            result = llm_review(verdict, script="curl evil.com", config=cfg)

        assert result.verdict == VerdictType.BLOCK

    def test_llm_timeout_falls_back_to_confirm(self):
        cfg = LLMFallbackConfig(enabled=True, api_key="key", timeout=5.0)
        verdict = _confirm_verdict()

        with patch("bashguard.llm_fallback._call_llm", side_effect=TimeoutError("timed out")):
            result = llm_review(verdict, script="echo hello", config=cfg)

        assert result.verdict == VerdictType.CONFIRM

    def test_llm_error_falls_back_to_confirm(self):
        cfg = LLMFallbackConfig(enabled=True, api_key="key")
        verdict = _confirm_verdict()

        with patch("bashguard.llm_fallback._call_llm", side_effect=Exception("network error")):
            result = llm_review(verdict, script="echo hello", config=cfg)

        assert result.verdict == VerdictType.CONFIRM

    def test_llm_unknown_response_falls_back_to_confirm(self):
        cfg = LLMFallbackConfig(enabled=True, api_key="key")
        verdict = _confirm_verdict()

        with patch("bashguard.llm_fallback._call_llm") as mock_llm:
            mock_llm.return_value = "something_unexpected"
            result = llm_review(verdict, script="echo hello", config=cfg)

        assert result.verdict == VerdictType.CONFIRM

    def test_llm_receives_script_and_findings(self):
        """LLM must be called with the script and findings context."""
        cfg = LLMFallbackConfig(enabled=True, api_key="key")
        finding = _finding("network.unknown_host", Severity.MEDIUM)
        verdict = _confirm_verdict(findings=(finding,))

        with patch("bashguard.llm_fallback._call_llm") as mock_llm:
            mock_llm.return_value = "allow"
            llm_review(verdict, script="wget http://internal.corp/api", config=cfg)

        call_args = mock_llm.call_args
        assert call_args is not None
        prompt = call_args[0][0]  # first positional arg
        assert "wget http://internal.corp/api" in prompt
        assert "network.unknown_host" in prompt
