"""
bashguard.types — Data-grammar type implementations for the bash-ast CLI.

Forth-style pipeline (each method consumes a token and produces Output):
  hook:    "hook" → Entry.hook_mode()              → Output
  analyze: "analyze" "--command" CMD → AnalyzeScript.analyze_command(cmd) → Output
           "analyze" "--file" PATH   → AnalyzeScript.analyze_file(path)   → Output

Key design: full audit pipeline runs inside each token-consuming method because
data-grammar's main loop only iterates while tokens remain on the input stream.
Tokenless method chains would never fire.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from data_grammar import Document, Output as BaseOutput

from bashguard.approval_cache import ApprovalCache
from bashguard.audit_log import log_verdict, read_log
from bashguard.audit_stats import compute_stats
from bashguard.auditor import audit as _audit
from bashguard.context import make_context
from bashguard.llm_fallback import LLMFallbackConfig, llm_review
from bashguard.models import Verdict, VerdictType
from bashguard.policy import PolicyConfig, decide
from bashguard.project_config import load_project_config, merge_configs


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _run_audit(script: str):
    """Run security audit and return (findings, verdict).

    Loads .bashguard.yaml from CWD for project-local policy ratcheting.
    """
    import os
    ctx = make_context()
    base_policy = PolicyConfig.default()
    project_cfg = load_project_config(
        Path(os.getcwd()) / ".bashguard.yaml"
    )
    policy = merge_configs(base_policy, project_cfg)
    findings = _audit(script, ctx)
    verdict = decide(findings, ctx, policy)
    # Optional LLM second opinion for CONFIRM cases
    verdict = llm_review(verdict, script=script, config=LLMFallbackConfig.from_env())
    return findings, verdict


def _seatbelt_wrap(script: str) -> str | None:
    """Rewrite script to run under seatbelt. Returns None if unavailable or disabled."""
    import os
    import shlex
    if os.environ.get("BASHGUARD_SEATBELT") == "0":
        return None
    from bashguard.seatbelt import build_profile, sandbox_exec_available
    if not sandbox_exec_available():
        return None

    project_path = Path(os.getcwd())
    profile = build_profile(project_path=project_path)

    # Write profile to a session-keyed file so it persists across the session
    session_id = os.environ.get("SESSION_ID", "default")
    profile_dir = Path.home() / ".bashguard" / "seatbelt"
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_path = profile_dir / f"{session_id}.sb"
    profile_path.write_text(str(profile))

    return f"sandbox-exec -f {profile_path} /bin/bash -c {shlex.quote(script)}"


def _gates_output(script: str) -> "Output":
    """Audit script and return gates-compatible Output (deny/ask/silent)."""
    _, verdict = _run_audit(script)

    # Approval cache: if CONFIRM and all triggering rules are already approved, upgrade to ALLOW
    if verdict.verdict == VerdictType.CONFIRM and verdict.findings:
        cache = ApprovalCache()
        if all(cache.is_approved(f.rule_id) for f in verdict.findings):
            verdict = Verdict(
                verdict=VerdictType.ALLOW,
                findings=verdict.findings,
                message=f"[approved] {verdict.message}",
            )

    log_verdict(verdict, command=script)
    if verdict.verdict == VerdictType.ALLOW:
        from bashguard.credentials import load_and_substitute
        rewritten = load_and_substitute(script)
        wrapped = _seatbelt_wrap(rewritten)
        final = wrapped or rewritten
        if final != script:
            payload = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {"command": final},
                }
            }
            return Output(text=json.dumps(payload))
        return Output(text="")
    if verdict.verdict == VerdictType.BLOCK:
        payload = {"permissionDecision": "deny", "reason": verdict.message}
        return Output(text=json.dumps(payload), exit_code=2)
    if verdict.verdict == VerdictType.CONFIRM:
        reason = verdict.confirmation_prompt or verdict.message
        payload = {"permissionDecision": "ask", "reason": reason}
        return Output(text=json.dumps(payload))
    return Output(text="")


def _report_output(script: str) -> "Output":
    """Audit script and return full JSON debug report as Output."""
    findings, verdict = _run_audit(script)
    log_verdict(verdict, command=script)
    data = {
        "commands": [script],
        "violations": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "matched_text": f.matched_text,
            }
            for f in findings
        ],
        "response": {
            "action": verdict.verdict.value,
            "reason": verdict.message,
        },
    }
    return Output(text=json.dumps(data, indent=2))


# ─── Grammar types ────────────────────────────────────────────────────────────

class Entry(Document):
    """Entry point — dispatches to hook or analyze mode."""

    def hook_mode(self) -> "Output":
        """Read Claude PreToolUse JSON from stdin, audit, emit gates-compatible response."""
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON on stdin: {e}") from e
        cmd = data.get("tool_input", {}).get("command", "")
        return _gates_output(cmd)

    def new(self) -> "AnalyzeScript":
        """Create empty AnalyzeScript for analyze mode."""
        return AnalyzeScript()

    def approve_rule(self, rule_id: str) -> "Output":
        """Grant session approval for a rule."""
        ApprovalCache().approve(rule_id)
        return Output(text=f"Approved: {rule_id}")

    def revoke_rule(self, rule_id: str) -> "Output":
        """Revoke session approval for a rule."""
        ApprovalCache().revoke(rule_id)
        return Output(text=f"Revoked: {rule_id}")

    def show_stats(self) -> "StatsQuery":
        """Create a StatsQuery for audit statistics."""
        return StatsQuery()

    def show_log(self) -> "LogQuery":
        """Create a LogQuery for querying the audit log."""
        return LogQuery()

    def claude_subcommand(self) -> "ClaudeSetup":
        """Dispatch to Claude Code integration subcommands."""
        return ClaudeSetup()

    def __str__(self) -> str:
        return ""


class AnalyzeScript(Document):
    """Analyze mode — receives source via --command or --file token."""

    def analyze_command(self, cmd: str) -> "Output":
        """Audit the given command string, return full JSON report."""
        return _report_output(cmd)

    def analyze_file(self, path: str) -> "Output":
        """Load script from file, audit it, return full JSON report."""
        with open(path, "r", encoding="utf-8") as f:
            script = f.read()
        return _report_output(script)

    def __str__(self) -> str:
        return ""


class StatsQuery(Document):
    """Stats query mode — aggregate audit log statistics."""

    def __init__(self, **kwargs):
        self._days: int | None = None
        self._as_json: bool = False

    def set_days(self, days: str) -> "StatsQuery":
        self._days = int(days)
        return self

    def use_json(self) -> "StatsQuery":
        self._as_json = True
        return self

    def __str__(self) -> str:
        stats = compute_stats(days=self._days)
        if self._as_json:
            return json.dumps(stats, indent=2)
        lines = [
            f"Total audited:  {stats['total']}",
            f"Block rate:     {stats['block_rate']:.1%}",
            "",
            "By verdict:",
        ]
        for verdict, count in sorted(stats["by_verdict"].items()):
            lines.append(f"  {verdict:10} {count}")
        if stats["by_rule"]:
            lines.append("")
            lines.append("Top rules triggered:")
            for rule_id, count in sorted(stats["by_rule"].items(),
                                          key=lambda x: -x[1])[:10]:
                lines.append(f"  {rule_id:40} {count}")
        return "\n".join(lines)


class LogQuery(Document):
    """Log query mode — filters and displays audit log entries."""

    def __init__(self, **kwargs):
        self._verdict_filter: str | None = None
        self._rule_filter: str | None = None
        self._limit: int | None = None
        self._as_json: bool = False

    def filter_verdict(self, verdict: str) -> "LogQuery":
        self._verdict_filter = verdict.lower()
        return self

    def filter_rule(self, rule_id: str) -> "LogQuery":
        self._rule_filter = rule_id
        return self

    def set_limit(self, n: str) -> "LogQuery":
        self._limit = int(n)
        return self

    def use_json(self) -> "LogQuery":
        self._as_json = True
        return self

    def __str__(self) -> str:
        entries = list(read_log(
            decision=self._verdict_filter,
            rule_id=self._rule_filter,
            limit=self._limit,
        ))
        if self._as_json:
            return json.dumps(entries, indent=2)
        # Human-readable table
        lines = []
        for e in entries:
            ts = e.get("timestamp", "")[:19].replace("T", " ")
            verdict = e.get("verdict", "?").upper()
            cmd = e.get("command", "")[:60]
            rules = ", ".join(f["rule_id"] for f in e.get("findings", []))
            lines.append(f"{ts}  {verdict:8}  {cmd:<60}  {rules}")
        return "\n".join(lines)


class ClaudeSetup(Document):
    """Claude Code integration — installs all bashguard hook plugins."""

    def do_setup(self) -> "Output":
        """Symlink all bundled hooks into ~/.claude/hooks/<HookType>.d/system/."""
        from bashguard.setup import install_all_hooks
        links = install_all_hooks()
        lines = "\n".join(f"Installed: {p}" for p in links)
        return Output(text=lines)

    def __str__(self) -> str:
        return ""


class Output(BaseOutput):
    """Terminal output — str() is written to stdout by @output."""

    def __init__(self, text: str = "", exit_code: int = 0, **kwargs):
        self.text = text
        self.exit_code = exit_code

    def __str__(self) -> str:
        return self.text
