# Code Smells And Release Risks

## CRITICAL-1: Session FUSE hooks call commands the CLI grammar does not implement

Location: `hooks/75-bashguard-mount:24`, `hooks/75-bashguard-unmount:19`, `bashguard/grammar.bnf:25-80`

Evidence:
```bash
exec bashguard fuse-mount --session-id "$SESSION_ID" --project "$PWD"
exec bashguard fuse-unmount --session-id "$SESSION_ID"
```

```bnf
Entry = "hook" @required :hook_mode > Output
      | "analyze" @required :new > AnalyzeScript
      | "approve" @required &rule_id<TEXT> :approve_rule > Output
      | "run" @required :new_run > RunScript
      | "claude" @required :claude_subcommand > ClaudeSetup
```

Why it matters: `bashguard claude setup` installs these hooks, but the shipped CLI has no `fuse-mount` or `fuse-unmount` entry point, so the advertised session sandbox cannot start or stop through the installed integration.

## CRITICAL-2: Credential rules miss `$HOME` paths

Location: `bashguard/rules/credentials.py:70-82`, `bashguard/rules/content_inspection.py:178-183`

Evidence:
```python
expanded = path.replace("~", home)
raw = path
...
if expanded == expanded_e or raw == exact:
    return True
```

```python
if clean.startswith("~/"):
    clean = home + clean[1:]
elif clean == "~":
    clean = home
```

Observed:
```text
CMD cat $HOME/.ssh/id_rsa
allow []
```

Why it matters: `$HOME/.ssh/id_rsa`, `$HOME/.aws/credentials`, and similar forms are ordinary shell syntax for credential reads, and they bypass both the credential detector and the outside-boundary check.

## HIGH-1: The PreToolUse hook intentionally fails open

Location: `hooks/70-bashguard:8-14`, `bashguard/cli.py:72-88`

Evidence:
```bash
# PROTOCOL: Blocking. Exits 2 to deny, 0 to allow.
# FAIL-OPEN: If bashguard is not installed or errors, exits 0 (allow).
command -v bashguard >/dev/null 2>&1 || exit 0
exec bashguard hook
```

```python
except Exception as e:
    print(f"Unexpected error: {e}", file=sys.stderr)
    ...
    return 1
```

Why it matters: this is a security gate installed into an execution path; if the binary is absent or the CLI crashes, the hook does not emit a deny response and the dispatcher can continue without enforcement.

## HIGH-2: Seatbelt enforcement is fail-open and is advertised as protecting home directories

Location: `README.md:33-35`, `bashguard/seatbelt.py:101-125`, `bashguard/types.py:55-75`

Evidence:
```markdown
On ALLOW, the command runs inside `sandbox-exec` ... Your home directory is safe even if the audit misses something.
```

```python
if not sandbox_exec_available():
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
```

Why it matters: the implementation silently runs unsandboxed when `sandbox-exec` is missing, and `_seatbelt_wrap` returns `None` in the same case; that contradicts the safety claim and makes defense-in-depth optional at runtime.

## HIGH-3: Project `allowed_hosts` config is parsed but never reaches `ExecutionContext`

Location: `bashguard/project_config.py:90-104`, `bashguard/types.py:41-49`, `bashguard/rules/network.py:70-80`

Evidence:
```python
for host in context_section.get("allowed_hosts", []) or []:
    additional_allowed_hosts.add(str(host))
```

```python
trusted = project_cfg.trusted_paths if project_cfg else frozenset()
ctx = make_context(allowed_paths=trusted)
```

```python
if host and host not in context.allowed_hosts:
    findings.append(Finding(
        rule_id=self.rule_id,
```

Why it matters: README-documented configuration does not work for network allowlisting; users cannot declare legitimate hosts without changing code, which pushes them toward disabling the guard.

## HIGH-4: Path boundary checks use raw prefix matching

Location: `bashguard/rules/content_inspection.py:56-67`, `bashguard/rules/content_inspection.py:187-196`

Evidence:
```python
"_BOUNDARY_EXEMPT_PREFIXES = (
    "/tmp", "/var/tmp",
```

```python
if real.startswith(worktree):
    continue
if any(real.startswith(os.path.normpath(p)) for p in context.allowed_paths):
    continue
```

Observed:
```text
CMD rm -rf /tmpx
allow []
```

Why it matters: `/tmpx` is treated as exempt because it starts with `/tmp`, and sibling paths can match a worktree or trusted path prefix; this is a classic path-boundary leak.

## MEDIUM-1: Rule failures are systematically converted into no findings

Location: `bashguard/rules/__init__.py:25-28`, `bashguard/auditor.py:39-48`

Evidence:
```python
def check(self, script: str, context: ExecutionContext) -> list[Finding]:
    """Inspect the script and return zero or more findings.
    Must NEVER raise. Return [] on any internal error."""
```

```python
except Exception as e:
    _log.error(
        "Rule %s raised unexpectedly: %s", rule.rule_id, e, exc_info=True
    )
```

Why it matters: a detector bug in a security rule downgrades to "no evidence" instead of an explicit audit-integrity finding, so malformed or newly unsupported input can silently reduce enforcement coverage.

## MEDIUM-2: Session startup records success before the FUSE daemon is known to be mounted

Location: `spike/session.py:119-137`, `tests/test_shadow_fs_integration.py:66-78`

Evidence:
```python
proc = subprocess.Popen(
    [sys.executable, str(_TOKEN_AUTH_FS),
     real_root, str(mount_point), str(project_path)],
    ...
)
...
state.save(self.sessions_dir / f"{session_id}.json")
return state
```

```python
for _ in range(50):
    if list(mount.iterdir()):  # mount has content = ready
        break
...
pytest.fail("Shadow FS did not mount within 5 seconds")
```

Why it matters: production session startup lacks the readiness check used by the integration test, so callers can be told to `cd` into an empty unmounted directory while believing writes are captured.

## MEDIUM-3: LLM fallback can lower a human-confirmation verdict to allow

Location: `bashguard/llm_fallback.py:116-153`

Evidence:
```python
if verdict.verdict != VerdictType.CONFIRM:
    return verdict
...
"allow": VerdictType.ALLOW,
...
return Verdict(
    verdict=new_type,
```

Why it matters: deterministic rules can ask for human confirmation, but an optional remote model is allowed to turn that into `ALLOW`; this is a boundary inversion for a security decision.
