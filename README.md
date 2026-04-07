# bashguard

**AI agents that don't blow up your laptop.**

bashguard intercepts every bash command Claude Code runs, audits it against a rule set, and either blocks it, wraps it in a kernel sandbox, or lets it through. Your files stay yours.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Quick start

```bash
pip install bashguard
bashguard claude setup      # installs the PreToolUse hook into Claude Code
```

That's it. Every bash command Claude runs now goes through bashguard before it executes.

---

## What it does

```
bash string → parse (tree-sitter AST)
            → audit (security rules → Findings)
            → decide (Findings → Verdict)
            → ALLOW: wrap in sandbox-exec, substitute credentials
              BLOCK: deny with reason
              CONFIRM: ask
```

**On ALLOW**, the command runs inside `sandbox-exec` — a deny-default macOS kernel sandbox that restricts writes to your project directory. Your home directory is safe even if the audit misses something.

**On BLOCK**, Claude Code sees a deny and never executes the command.

---

## What gets blocked

| Rule | Blocks |
|------|--------|
| `destructive.irreversible` | `rm -rf`, `dd`, `mkfs`, `shred` |
| `credentials.privileged_path` | reads from `~/.ssh`, `~/.aws`, `.env` |
| `network.unknown_host` | `curl`/`wget` to hosts not in your allowlist |
| `git.destructive` | force push, `reset --hard`, `branch -D` |
| `paths.protected_write` | writes to `/etc`, `/usr`, `/sys`, `/boot` |
| `content.secret_in_args` | API keys, PEM headers in command arguments |
| `content.exfiltration_pattern` | sensitive files piped to network endpoints |
| `evasion.*` (13 rules) | `eval`, shell-in-shell, base64 decode pipelines, IFS manipulation |
| `self_protection.*` | attempts to modify bashguard itself |
| `comms.*` | email, SMS, Slack/Discord webhooks |
| `sql_destruction.*` | `DROP DATABASE`, `TRUNCATE`, bulk deletes |
| `crypto_mining.*` | xmrig and friends |
| `tunneling.*` | ngrok, localtunnel, serveo |

---

## Credential injection

Keep secrets out of Claude's context entirely. Put placeholders in your prompts:

```bash
curl -H "Authorization: Bearer {{GITHUB_TOKEN}}" https://api.github.com/...
```

bashguard substitutes real values from `~/.bashguard/credentials.yaml` at execution time. Claude never sees the actual token.

---

## Audit log

```bash
bashguard log --verdict block -n 20          # recent blocks
bashguard log --rule network.unknown_host    # by rule
bashguard stats --days 7                     # weekly summary
```

---

## Configuration

Per-project policy in `.bashguard.yaml`. Ratcheting: can only tighten (allow→block), never relax (block→allow):

```yaml
policy:
  severity:
    medium: block
context:
  allowed_hosts:
    - api.openai.com
    - internal.corp.com
```

---

## Python API

```python
from bashguard.auditor import audit
from bashguard.context import make_context
from bashguard.policy import PolicyConfig, decide

ctx = make_context()
findings = audit("rm -rf /", ctx)
verdict = decide(findings, ctx, PolicyConfig.default())
# Verdict(verdict=BLOCK, message="rm -rf on non-/tmp path: /")
```

---

## Debug mode

```bash
bashguard analyze --command 'git push --force origin main'
```

Returns full JSON: parsed commands, all findings, verdict, reason.

---

## Disable seatbelt

The kernel sandbox wraps allowed commands by default. To disable:

```bash
BASHGUARD_SEATBELT=0 bashguard hook
```

---

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -q        # 525 tests
```

---

## License

MIT
