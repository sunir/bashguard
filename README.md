# bashguard

Bash command security interceptor for LLM agent sandboxing. Parses commands into ASTs via tree-sitter, runs pluggable security rules, returns structured verdicts (ALLOW/BLOCK/CONFIRM/REDIRECT).

## Architecture

Three-stage pipeline — detection orthogonal to response:

```
bash string → parse() → audit() → decide() → Verdict
              [CST]     [Findings]            [ALLOW/BLOCK/CONFIRM/REDIRECT]
```

## Install

```bash
uv pip install -e ".[dev]"
```

## Usage

### Hook mode (Claude Code integration)

```bash
echo "$CLAUDE_HOOK_INPUT" | bashguard hook
```

### Analyze mode (debugging)

```bash
bashguard analyze --command 'git push --force origin main'
```

### Audit log

```bash
bashguard log --verdict block --rule network.unknown_host -n 20 --json
bashguard stats --days 7
```

## Rules (342 tests, 70 corpus entries)

| Rule | Detects | ActionType |
|------|---------|------------|
| `parse.error_node` | malformed/obfuscated commands | OBFUSCATED |
| `credentials.privileged_path` | ~/.ssh, ~/.aws, /etc, .env | CREDENTIAL_ACCESS |
| `network.unknown_host` | curl/wget/nc to unknown hosts | NETWORK_OUTBOUND |
| `network.dev_tcp` | /dev/tcp bash trick | NETWORK_OUTBOUND |
| `destructive.irreversible` | rm -rf, dd, mkfs, shred | FILESYSTEM_DELETE |
| `package_install.global` | brew/apt/npm -g | PACKAGE_INSTALL |
| `git.destructive` | force push, reset --hard, branch -D | GIT_DESTRUCTIVE |
| `paths.protected_write` | write redirects to /etc /usr /sys | SYSTEM_CONFIG |
| `content.secret_in_args` | API keys/PEM/tokens in args | CREDENTIAL_ACCESS |
| `content.exfiltration_pattern` | sensitive files piped to network | NETWORK_OUTBOUND |
| `content.outside_boundary` | file access outside worktree | FILESYSTEM_READ |
| `self_protection.*` | attempts to modify bashguard itself | SYSTEM_CONFIG |
| `comms.*` | email/SMS/webhook sending | NETWORK_OUTBOUND |
| 13 `evasion.*` rules | eval, shell-in-shell, decode pipelines, IFS, etc. | OBFUSCATED/ENV_MUTATION |

### Strict mode (opt-in)

Allowlist-only: blocks any command not in the safe vocabulary. Not registered by default.

```python
from bashguard.strict_mode import StrictModeRule
```

## Configuration

### `.bashguard.yaml` (project-local, ratcheting)

Can only tighten policy (allow→block), never relax (block→allow):

```yaml
policy:
  severity:
    medium: block
rules:
  - rule_id: git.destructive
    verdict: block
context:
  allowed_hosts:
    - internal.corp.com
```

### LLM fallback (opt-in)

Optional LLM second opinion for CONFIRM verdicts:

```bash
export BASHGUARD_LLM_FALLBACK=1
export BASHGUARD_LLM_KEY=sk-...
```

## Python API

```python
from bashguard.auditor import audit
from bashguard.context import make_context
from bashguard.policy import PolicyConfig, decide

ctx = make_context()
findings = audit("rm -rf /", ctx)
verdict = decide(findings, ctx, PolicyConfig.default())
```

## Tests

```bash
.venv/bin/pytest tests/ -q
```
