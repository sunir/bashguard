# Notebook: bashguard

## 1. System Map

### 1.1 Entry Points

- `bin/bashguard` dispatches to `.venv/bin/python -m bashguard.cli` if present, otherwise `python3 -m bashguard.cli` (`bin/bashguard:1-8`).
- `hooks/70-bashguard` is the blocking PreToolUse hook; it exits 0 if `bashguard` is missing and then executes `bashguard hook` (`hooks/70-bashguard:8-14`).
- `hooks/75-bashguard-mount` and `hooks/75-bashguard-unmount` are installed SessionStart/SessionEnd hooks but call `bashguard fuse-mount` and `bashguard fuse-unmount`, which are not in the CLI grammar (`hooks/75-bashguard-mount:24`, `hooks/75-bashguard-unmount:19`, `bashguard/grammar.bnf:25-80`).
- `bashguard.cli:main` builds the data-grammar interpreter and maps JSON output to process exit codes (`bashguard/cli.py:38-88`).
- `bashguard.types:Entry.hook_mode` reads Claude PreToolUse JSON from stdin and audits `tool_input.command` (`bashguard/types.py:146-153`).
- `bashguard.types:RunScript.execute_command` audits then executes allowed commands (`bashguard/types.py:300-354`).

### 1.2 Core Data Structures

- `Finding`, `ExecutionContext`, and `Verdict` are immutable-ish dataclasses carrying evidence, runtime context, and final policy output (`bashguard/models.py:48-95`).
- `CommandNode` is the parsed command abstraction from tree-sitter (`bashguard/parser.py:23-64`).
- `PolicyConfig` and `RulePolicy` map findings to verdicts (`bashguard/policy.py:29-58`).
- `ProjectConfig` represents `.bashguard.yaml` ratcheting configuration (`bashguard/project_config.py:49-55`).

### 1.3 Subsystems

#### 1.3.1 CLI And Hook Integration

Files: `bin/bashguard`, `hooks/*`, `bashguard/cli.py`, `bashguard/grammar.bnf`, `bashguard/types.py`, `bashguard/setup.py`.

Purpose: install and run the security gate in Claude/Colony hook flows.

Concern: session hooks are wired to unimplemented CLI commands, and PreToolUse is explicitly fail-open.

#### 1.3.2 Parse, Audit, Policy

Files: `bashguard/parser.py`, `bashguard/auditor.py`, `bashguard/policy.py`, `bashguard/models.py`, `bashguard/rules/*`.

Purpose: parse shell, collect findings, and decide allow/confirm/block.

Concern: rules are broad and useful, but the design converts detector exceptions to empty findings, so audit integrity is not represented in the output.

#### 1.3.3 Runtime Boundaries

Files: `bashguard/seatbelt.py`, `bashguard/context.py`, `bashguard/project_config.py`, `bashguard/approval_cache.py`, `bashguard/credentials.py`, `bashguard/audit_log.py`, `bashguard/audit_stats.py`, `bashguard/llm_fallback.py`.

Purpose: build environment context, handle sandboxing, approval state, credential substitution, logging, stats, and optional LLM review.

Concern: `allowed_hosts` is parsed but not applied to `ExecutionContext`; sandbox enforcement silently degrades to normal execution.

#### 1.3.4 FUSE Spike

Files: `spike/session.py`, `spike/shadow_fs.py`, `spike/acl_shadow_fs.py`, `spike/token_auth_fs.py`, `spike/colony_hooks.py`, `spike/passthrough_fs.py`.

Purpose: prototype copy-on-write shadow filesystem with token/subtree access.

Concern: good containment logic exists in `ACLShadowFS`, but the installed hooks do not call this code path and `SessionManager.start` does not prove the daemon mounted before returning success.

#### 1.3.5 Tests

Files: `tests/**/*.py`, `tests/corpus.yaml`.

Purpose: large rule corpus plus focused unit/integration tests.

Concern: rule-level coverage is strong, but integration coverage misses the installed `fuse-mount`/`fuse-unmount` CLI mismatch and the `$HOME` credential bypass. Seatbelt tests fail in this environment with `sandbox-exec: sandbox_apply: Operation not permitted`.

## 2. Data Flow

### 2.1 Hook Path

`Claude PreToolUse JSON` -> `hooks/70-bashguard` -> `bashguard hook` -> `Entry.hook_mode` -> `_gates_output` -> `_run_audit` -> `auditor.audit` -> `policy.decide` -> optional `llm_review` -> `log_verdict` -> JSON permission decision.

Happy path is explicit (`bashguard/types.py:78-115`). Fatal path is not fail-closed at shell-hook level (`hooks/70-bashguard:8-14`).

### 2.2 Analyze Path

`bashguard analyze --command/--file` -> `AnalyzeScript` -> `_report_output` -> JSON report (`bashguard/types.py:118-138`, `bashguard/types.py:189-200`).

### 2.3 Run Path

`bashguard run -c CMD` -> audit -> block/confirm JSON or execute with `run_sandboxed` (`bashguard/types.py:300-354`). The `BASHGUARD_SEATBELT=0` path intentionally executes unsandboxed (`bashguard/types.py:337-343`).

### 2.4 Trust Boundaries

- User/hook input: stdin JSON and CLI args (`bashguard/types.py:146-153`, `bashguard/types.py:196-200`).
- Filesystem/config: `.bashguard.yaml`, audit logs, approval cache, credential store (`bashguard/project_config.py:58-104`, `bashguard/audit_log.py:12-73`, `bashguard/approval_cache.py:22-73`, `bashguard/credentials.py:31-110`).
- Network: optional LLM fallback (`bashguard/llm_fallback.py:85-113`).
- Process: `sandbox-exec`, `/bin/bash -c`, FUSE daemons (`bashguard/seatbelt.py:94-139`, `bashguard/types.py:337-345`, `spike/session.py:119-125`).

## 3. Object Model

### 3.1 Domain Objects

- `Finding`, `Verdict`, `ExecutionContext`, `PolicyConfig`, `ProjectConfig`, `CommandNode`.
- They are mostly cohesive value models. `ExecutionContext` is intentionally explicit and avoids hidden environment reads once constructed.

### 3.2 Coordinators

- `auditor.audit` coordinates rule execution (`bashguard/auditor.py:27-49`).
- `policy.decide` coordinates response policy (`bashguard/policy.py:90-151`).
- `_gates_output`, `_report_output`, and `RunScript.execute_command` coordinate CLI use cases (`bashguard/types.py:78-138`, `bashguard/types.py:300-354`).

### 3.3 Adapters

- Shell hooks and `bin/bashguard` are process adapters.
- `seatbelt.py` adapts to macOS `sandbox-exec`.
- `llm_fallback.py` adapts to Anthropic-compatible HTTP API.
- `audit_log.py`, `approval_cache.py`, `project_config.py`, `credentials.py` adapt to local files.
- `spike/*_fs.py` adapt to FUSE.

### 3.4 Anomalies

- FUSE integration is split between installed hooks, absent CLI grammar commands, and spike modules; this is architectural debt, not just labelling.
- Project config includes `additional_allowed_hosts` but no coordinator applies it to context, so the model carries data that never enters the use case.
- LLM fallback is positioned after deterministic policy and can reduce a `CONFIRM` to `ALLOW`; that mixes advisory review with authorization.

## 4. Contracts and Boundaries

### 4.1 Public Contracts

- `audit(script, context, rules=None) -> list[Finding]` returns sorted findings and does not raise on rule failure (`bashguard/auditor.py:27-49`).
- `decide(findings, context, config) -> Verdict` is pure and maps evidence to response (`bashguard/policy.py:90-151`).
- `load_project_config(path) -> ProjectConfig | None` returns `None` on absent or unreadable config (`bashguard/project_config.py:58-72`).
- `run_sandboxed(cmd, project_path, ...) -> SandboxResult` executes with or without sandbox depending on availability (`bashguard/seatbelt.py:94-139`).

### 4.2 Persistence, Network, Filesystem, Config, Security Boundaries

- Approval cache and logs are JSON files in `~/.bashguard`.
- Credentials are substituted after an `ALLOW` verdict (`bashguard/types.py:92-97`, `bashguard/credentials.py:110`).
- Project config is loaded from CWD and intended to ratchet policy only (`bashguard/project_config.py:1-10`).
- Network allowlisting depends on `ExecutionContext.allowed_hosts` (`bashguard/rules/network.py:70-80`).
- Filesystem boundary checks depend on string-normalized prefixes (`bashguard/rules/content_inspection.py:191-196`).

### 4.3 Contract Violations And Bypasses

- Hook-installed FUSE commands are not recognized by the grammar.
- `$HOME` credential paths are not normalized.
- Seatbelt and hook failure modes are fail-open despite product claims of sandbox protection.
- Rule failures become no findings rather than integrity failures.

## 5. Per-file Notes

All non-generated source files under `bashguard/`, `hooks/`, `bin/`, `spike/`, and `tests/` were included in the review scope. The detailed concern evidence is in `.qa-review/codesmells.md`; positive examples are in `.qa-review/cleancode.md`.

Representative file notes:

- `bashguard/parser.py`: owns tree-sitter parsing and `CommandNode` extraction. Public surface: `parse(script)`. Concern: docstring promises `ParseError` on ERROR root, but parse never checks `root.has_error`; the separate `ErrorNodesRule` currently covers that gap.
- `bashguard/auditor.py`: owns rule coordination. Public surface: `audit(script, context, rules=None)`. Concern: detector exceptions are logged and skipped.
- `bashguard/policy.py`: owns pure finding-to-verdict mapping. Public surface: `decide`. Good separation of policy from detection.
- `bashguard/types.py`: owns CLI use-case paths. Public surface: data-grammar document methods. Concerns: project config host data not applied to context; run mode can execute unsandboxed.
- `bashguard/rules/network.py`: owns network host findings. Public surface: `NetworkRule.check`. Depends entirely on `context.allowed_hosts`.
- `bashguard/rules/credentials.py`: owns credential path matching. Concern: only `~` and literal paths are normalized; `$HOME` bypasses.
- `bashguard/rules/content_inspection.py`: owns secret-in-args, exfiltration, and worktree boundary checks. Concern: raw prefix containment.
- `bashguard/seatbelt.py`: owns SBPL generation and execution adapter. Concern: fail-open when `sandbox-exec` is unavailable.
- `bashguard/setup.py`: owns symlink installation. Concern: installs session hooks whose CLI commands are absent.
- `spike/session.py`: owns FUSE session lifecycle. Concern: no daemon readiness/health check before state is saved and returned.
- `spike/acl_shadow_fs.py`: owns subtree enforcement and is one of the cleaner pieces.
- `hooks/70-bashguard`: owns PreToolUse integration. Concern: explicit fail-open.
- `hooks/75-bashguard-mount` and `hooks/75-bashguard-unmount`: own session integration but call absent commands.

## 6. Cross-file Observations

- The claimed execution protection is scattered across hooks, data-grammar CLI, seatbelt, and FUSE spike code; there is no single coherent release path from `bashguard claude setup` to mounted sandbox.
- The security architecture repeatedly chooses fail-open behavior at process, rule, and sandbox boundaries. That may preserve developer convenience, but it is inconsistent with the product's release claim.
- Several modules have the right local idea but no end-to-end contract test: project `allowed_hosts`, FUSE session hooks, and `$HOME` credential access are all examples.
