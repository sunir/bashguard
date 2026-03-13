"""
bashguard.llm_fallback — Optional LLM second opinion for CONFIRM verdicts.

Fast path: deterministic rules run first.
Slow path: LLM reviews CONFIRM cases when enabled.

Configuration via environment:
    BASHGUARD_LLM_FALLBACK=1          — enable LLM fallback
    BASHGUARD_LLM_KEY=sk-...          — API key
    BASHGUARD_LLM_URL=https://...     — custom endpoint (default: Anthropic)
    BASHGUARD_LLM_MODEL=claude-...    — model ID

Fail-safe: any error (timeout, network, bad response) → return original CONFIRM.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

from bashguard.models import Verdict, VerdictType

_log = logging.getLogger(__name__)

_DEFAULT_LLM_URL = "https://api.anthropic.com/v1/messages"
_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_DEFAULT_TIMEOUT = 10.0

_ALLOWED_RESPONSES = {"allow", "block", "confirm"}

_SYSTEM_PROMPT = """You are a security reviewer for bash commands executed by an AI coding assistant.
You will receive a bash command and security findings. Decide if it should be allowed.

Reply with EXACTLY ONE WORD: allow, block, or confirm
- allow: safe to run, no security concern
- block: definitely dangerous, should not run
- confirm: ambiguous, needs human review

Be conservative. When in doubt, say "confirm"."""

_USER_TEMPLATE = """Command: {script}

Security findings:
{findings}

Decision (allow/block/confirm):"""


@dataclass
class LLMFallbackConfig:
    """Configuration for the LLM fallback reviewer."""
    enabled: bool = False
    api_key: str = ""
    api_url: str = _DEFAULT_LLM_URL
    model: str = _DEFAULT_MODEL
    timeout: float = _DEFAULT_TIMEOUT

    @classmethod
    def default(cls) -> LLMFallbackConfig:
        return cls(enabled=False)

    @classmethod
    def from_env(cls) -> LLMFallbackConfig:
        enabled = os.environ.get("BASHGUARD_LLM_FALLBACK", "0").strip() == "1"
        return cls(
            enabled=enabled,
            api_key=os.environ.get("BASHGUARD_LLM_KEY", ""),
            api_url=os.environ.get("BASHGUARD_LLM_URL", _DEFAULT_LLM_URL),
            model=os.environ.get("BASHGUARD_LLM_MODEL", _DEFAULT_MODEL),
            timeout=float(os.environ.get("BASHGUARD_LLM_TIMEOUT", str(_DEFAULT_TIMEOUT))),
        )


def _build_prompt(script: str, verdict: Verdict) -> str:
    finding_lines = "\n".join(
        f"- [{f.severity.value}] {f.rule_id}: {f.message}"
        for f in verdict.findings
    )
    if not finding_lines:
        finding_lines = "(none)"
    return _USER_TEMPLATE.format(script=script, findings=finding_lines)


def _call_llm(prompt: str, config: LLMFallbackConfig) -> str:
    """Call the LLM API and return the verdict word. May raise on error."""
    import urllib.request
    import urllib.error

    payload = {
        "model": config.model,
        "max_tokens": 10,
        "system": _SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }

    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
    }

    req = urllib.request.Request(config.api_url, data=data, headers=headers, method="POST")

    import socket
    with urllib.request.urlopen(req, timeout=config.timeout) as resp:
        body = json.loads(resp.read())

    # Extract text from Anthropic response format
    text = body["content"][0]["text"].strip().lower()
    # Extract just the first word
    return text.split()[0] if text else ""


def llm_review(verdict: Verdict, script: str, config: LLMFallbackConfig) -> Verdict:
    """Review a CONFIRM verdict with an LLM. Returns original verdict on any error.

    Only CONFIRM verdicts are reviewed. BLOCK and ALLOW pass through unchanged.
    """
    if not config.enabled:
        return verdict

    if verdict.verdict != VerdictType.CONFIRM:
        return verdict

    try:
        prompt = _build_prompt(script, verdict)
        response = _call_llm(prompt, config)

        if response not in _ALLOWED_RESPONSES:
            _log.warning("LLM returned unexpected response %r, keeping CONFIRM", response)
            return verdict

        new_type = {
            "allow": VerdictType.ALLOW,
            "block": VerdictType.BLOCK,
            "confirm": VerdictType.CONFIRM,
        }[response]

        if new_type == verdict.verdict:
            return verdict

        return Verdict(
            verdict=new_type,
            findings=verdict.findings,
            message=f"[LLM] {verdict.message}",
            redirect_command=verdict.redirect_command,
            confirmation_prompt=verdict.confirmation_prompt,
            redirect_tool=verdict.redirect_tool,
            redirect_args=verdict.redirect_args,
            redirect_resolved=verdict.redirect_resolved,
        )

    except (TimeoutError, OSError, KeyError, IndexError, ValueError, Exception) as e:
        _log.warning("LLM fallback failed (%s), keeping CONFIRM", e)
        return verdict
