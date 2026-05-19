# Deep Review: bashguard

## Executive Summary

- Files reviewed: 139 source files (135 Python plus 4 hook/bin scripts), excluding generated `__pycache__`
- Classes reviewed: 327
- Methods/functions reviewed: 1610
- Concerns raised: 9 total / 2 critical / 4 high / 3 medium
- Cross-file observations: 3
- Overall verdict: REJECT

The code contains useful rule work and a sensible value-object/policy core, but the release integration is not fit for payment acceptance. The installed FUSE hooks call CLI commands that do not exist, credential detection misses ordinary `$HOME` paths, and multiple enforcement boundaries fail open while the README claims every Bash command is audited and sandboxed.

## System Design Assessment

- The core audit pipeline mostly follows data-flow-centred design: `CommandNode`/`Finding`/`Verdict` values move through parse, audit, and policy functions (`bashguard/parser.py:23-64`, `bashguard/auditor.py:27-49`, `bashguard/policy.py:90-151`).
- Where it does well: `Finding` is immutable evidence, not mutable decision state (`bashguard/models.py:48-65`); `decide` keeps response policy separate from detection (`bashguard/policy.py:90-151`); `ACLShadowFS._check_access` uses normalized exact-or-subtree path matching (`spike/acl_shadow_fs.py:50-58`).
- Where it does not: release enforcement is scattered across shell hooks, grammar, CLI use cases, seatbelt, and spike modules, and those pieces do not compose into a working session sandbox (`hooks/75-bashguard-mount:24`, `bashguard/grammar.bnf:25-80`, `spike/session.py:119-137`).

## Entry point path assessment

- `hooks/70-bashguard` -> `bashguard hook` -> `Entry.hook_mode` -> `_gates_output` -> `_run_audit` -> `auditor.audit` -> `policy.decide` -> permission JSON.
- Happy path: handled for allow/block/confirm JSON (`bashguard/types.py:78-115`).
- Non-fatal failures: rule exceptions are logged and skipped (`bashguard/auditor.py:39-48`).
- Logic/validation errors: invalid hook JSON raises `ValueError` (`bashguard/types.py:148-151`) and CLI returns non-deny exit 1 (`bashguard/cli.py:72-88`).
- Fatals: shell hook explicitly exits 0 if `bashguard` is absent (`hooks/70-bashguard:8-14`), so release behavior is fail-open.

## Contracts and boundaries

- Clear contracts: `audit` returns sorted findings (`bashguard/auditor.py:27-49`); `decide` maps findings to a `Verdict` (`bashguard/policy.py:90-151`); `ProjectConfig` is intended to ratchet only (`bashguard/project_config.py:1-10`).
- Boundary leaks: `$HOME` credential paths bypass detectors (`bashguard/rules/credentials.py:70-82`, `bashguard/rules/content_inspection.py:178-183`); path containment uses raw `startswith` (`bashguard/rules/content_inspection.py:187-196`).
- Persistence/network/filesystem/config/security risks: `allowed_hosts` config is parsed but never reaches `ExecutionContext` (`bashguard/project_config.py:90-104`, `bashguard/types.py:41-49`); seatbelt runs unsandboxed when unavailable (`bashguard/seatbelt.py:118-125`).

## CRITICAL concerns (block merge)

### CRITICAL-1: Installed FUSE hooks call CLI commands that do not exist

**Location**: `hooks/75-bashguard-mount:24`, `hooks/75-bashguard-unmount:19`, `bashguard/grammar.bnf:25`

**Evidence**:
```bash
exec bashguard fuse-mount --session-id "$SESSION_ID" --project "$PWD"
exec bashguard fuse-unmount --session-id "$SESSION_ID"
```

```bnf
Entry = "hook" @required :hook_mode > Output
      | "analyze" @required :new > AnalyzeScript
      | "approve" @required &rule_id<TEXT> :approve_rule > Output
```

**Why it concerns you**: `bashguard claude setup` installs a session sandbox that cannot be invoked by the shipped CLI, so the advertised FUSE protection is dead on arrival.
**What you would do**: Either implement `fuse-mount`/`fuse-unmount` in `grammar.bnf` and `types.py` using the session manager, or remove those hooks and product claims until they work end to end.
**Cross-file impact**: affects `bashguard/setup.py`, `hooks/75-bashguard-*`, `bashguard/grammar.bnf`, `bashguard/types.py`, `spike/session.py`.

### CRITICAL-2: `$HOME` credential paths are allowed

**Location**: `bashguard/rules/credentials.py:70`, `bashguard/rules/content_inspection.py:178`

**Evidence**:
```python
expanded = path.replace("~", home)
raw = path
```

```python
if clean.startswith("~/"):
    clean = home + clean[1:]
elif clean == "~":
```

Observed during review:
```text
CMD cat $HOME/.ssh/id_rsa
allow []
```

**Why it concerns you**: `$HOME/.ssh/id_rsa` and `$HOME/.aws/credentials` are normal shell forms for secret reads, and this bypasses the primary credential boundary.
**What you would do**: Normalize shell home variables before matching, at minimum `$HOME` and `${HOME}`, and add tests for reads, uploads, redirects, and `@file` network arguments using those forms.
**Cross-file impact**: affects `credentials.privileged_path`, `content.outside_boundary`, and exfiltration rules.

## HIGH concerns

### HIGH-1: The blocking hook explicitly fails open

**Location**: `hooks/70-bashguard:8`

**Evidence**:
```bash
# PROTOCOL: Blocking. Exits 2 to deny, 0 to allow.
# FAIL-OPEN: If bashguard is not installed or errors, exits 0 (allow).
command -v bashguard >/dev/null 2>&1 || exit 0
```

**Why it concerns you**: a missing or broken security binary becomes permission to execute Bash, which is the opposite of a trustworthy enforcement point.
**What you would do**: Fail closed for Bash tool calls when the hook is installed but cannot run, with an explicit deny reason and a documented recovery path.
**Cross-file impact**: affects hook installation, CLI error handling, and operator expectations.

### HIGH-2: Seatbelt sandboxing silently degrades to normal execution

**Location**: `bashguard/seatbelt.py:118`, `README.md:33`

**Evidence**:
```python
if not sandbox_exec_available():
    result = subprocess.run(
        cmd,
        capture_output=True,
```

```markdown
Your home directory is safe even if the audit misses something.
```

**Why it concerns you**: the README promises sandbox protection, but the implementation runs the command unsandboxed when `sandbox-exec` is unavailable.
**What you would do**: Make sandbox absence a block or confirm condition for protected execution modes, and make any fail-open mode explicit and opt-in.
**Cross-file impact**: affects `RunScript.execute_command`, `_seatbelt_wrap`, README claims, and tests.

### HIGH-3: `.bashguard.yaml` `allowed_hosts` is parsed but ignored

**Location**: `bashguard/project_config.py:92`, `bashguard/types.py:45`

**Evidence**:
```python
for host in context_section.get("allowed_hosts", []) or []:
    additional_allowed_hosts.add(str(host))
```

```python
trusted = project_cfg.trusted_paths if project_cfg else frozenset()
ctx = make_context(allowed_paths=trusted)
```

**Why it concerns you**: README-documented network configuration never reaches `NetworkRule`, so legitimate configured hosts are still treated as unknown.
**What you would do**: Pass `project_cfg.additional_allowed_hosts` into `make_context(allowed_hosts=...)` and test `_run_audit` against a real `.bashguard.yaml`.
**Cross-file impact**: affects `project_config`, `types`, `context`, `network`, and README examples.

### HIGH-4: Path boundary enforcement uses unsafe string prefixes

**Location**: `bashguard/rules/content_inspection.py:187`

**Evidence**:
```python
if any(clean.startswith(p) for p in _BOUNDARY_EXEMPT_PREFIXES):
    continue
...
if real.startswith(worktree):
```

Observed during review:
```text
CMD rm -rf /tmpx
allow []
```

**Why it concerns you**: prefix checks treat sibling paths as inside trusted boundaries, so `/tmpx` matches `/tmp` and similar bugs can occur with worktree or allowed path prefixes.
**What you would do**: Use `Path.resolve()` plus `Path.is_relative_to()` or exact-or-separator-aware containment for all filesystem boundaries.
**Cross-file impact**: affects `content_inspection`, `protected_paths`, and any project trusted path behavior.

## MEDIUM concerns

### MEDIUM-1: Detector crashes become empty findings

**Location**: `bashguard/auditor.py:39`, `bashguard/rules/__init__.py:25`

**Evidence**:
```python
for rule in active_rules:
    try:
        rule_findings = rule.check(script, context)
```

```python
Must NEVER raise. Return [] on any internal error.
```

**Why it concerns you**: an internal detector failure removes security evidence instead of producing an audit-integrity finding.
**What you would do**: Emit a high-severity `audit.rule_error` finding for unexpected rule failures, with a policy default that blocks or confirms.
**Cross-file impact**: affects every rule module and `auditor.audit`.

### MEDIUM-2: Session startup returns before FUSE mount readiness is proven

**Location**: `spike/session.py:119`

**Evidence**:
```python
proc = subprocess.Popen(
    [sys.executable, str(_TOKEN_AUTH_FS),
     real_root, str(mount_point), str(project_path)],
```

```python
state.save(self.sessions_dir / f"{session_id}.json")
return state
```

**Why it concerns you**: callers can receive a session and work directory even if the daemon immediately exits or never mounts.
**What you would do**: wait for mount readiness, verify process liveness, surface stderr on failure, and only persist active state after the mount is usable.
**Cross-file impact**: affects session CLI, hooks, and FUSE integration tests.

### MEDIUM-3: LLM fallback can downgrade human confirmation to allow

**Location**: `bashguard/llm_fallback.py:124`

**Evidence**:
```python
if verdict.verdict != VerdictType.CONFIRM:
    return verdict
...
"allow": VerdictType.ALLOW,
```

**Why it concerns you**: a remote probabilistic reviewer can bypass a deterministic human-review decision.
**What you would do**: Allow the LLM only to keep `CONFIRM` or escalate to `BLOCK`, never to downgrade to `ALLOW`.
**Cross-file impact**: affects `_run_audit`, hook mode, and operator trust model.

## CROSS-FILE observations

- Location: spans `bashguard/setup.py`, `hooks/75-bashguard-mount`, `bashguard/grammar.bnf`, `spike/session.py`. The FUSE sandbox is split across installed hooks, absent CLI commands, and spike modules, so the release path is incoherent.
- Location: spans `hooks/70-bashguard`, `bashguard/auditor.py`, `bashguard/seatbelt.py`. Fail-open is a repeated boundary policy, not an isolated implementation detail.
- Location: spans `README.md`, `bashguard/project_config.py`, `bashguard/types.py`, `bashguard/rules/network.py`. Public configuration promises are not covered by an end-to-end test from `.bashguard.yaml` through `NetworkRule`.

## Clean code worth preserving

- `bashguard.models:Finding` at `bashguard/models.py:48` — immutable evidence model with required `rule_id` validation.
- `bashguard.policy:decide` at `bashguard/policy.py:90` — pure policy mapping, separate from detection.
- `bashguard.project_config:merge_configs` at `bashguard/project_config.py:107` — clear ratcheting intent and metadata preservation.
- `bashguard.rules.error_nodes:ErrorNodesRule.check` at `bashguard/rules/error_nodes.py:36` — parse errors are represented as security findings.
- `bashguard.rules.ci_workflow_inject:CiWorkflowInjectRule.check` at `bashguard/rules/ci_workflow_inject.py:127` — well-grounded rule covering multiple write paths.
- `spike.acl_shadow_fs:ACLShadowFS._check_access` at `spike/acl_shadow_fs.py:50` — correct exact-or-subtree path containment.
- `bashguard.audit_log:read_log` at `bashguard/audit_log.py:35` — robust JSONL reading for operational logs.

## Notebook system map

### Entry points

`bin/bashguard`, `hooks/70-bashguard`, `hooks/75-bashguard-mount`, `hooks/75-bashguard-unmount`, `bashguard.cli:main`, `Entry.hook_mode`, `AnalyzeScript`, and `RunScript`.

### Core data structures

`CommandNode`, `Finding`, `ExecutionContext`, `Verdict`, `PolicyConfig`, `RulePolicy`, and `ProjectConfig`.

### Subsystems

CLI/hook integration, parse/audit/policy, runtime boundaries, FUSE spike, and tests.

### Object model

The core uses cohesive value objects and coordinator functions. Adapters are shell hooks, local files, macOS seatbelt, HTTP LLM fallback, and FUSE. Anomalies are the split FUSE integration, unused `allowed_hosts` config, and authorization downgrade by LLM fallback.

### Contracts and boundaries

Contracts are explicit in the core, but boundary enforcement is weakened by fail-open process behavior, ignored config, raw prefix path checks, and credential path normalization gaps.

## Verification

I ran:

```text
.venv/bin/python -m pytest tests/test_bash_ast_cli.py tests/test_seatbelt.py tests/test_project_config.py -q
```

Result: 41 passed, 4 failed. All failures were in `tests/test_seatbelt.py` with `sandbox-exec: sandbox_apply: Operation not permitted`, confirming the sandbox path is environment-sensitive and currently not green in this workspace.

END_OF_REVIEW
