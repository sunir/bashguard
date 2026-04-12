# CLI Contract

## Two modes

### Hook mode (drop-in for `gates/bin/claude-tools`)

```bash
echo "$CLAUDE_HOOK_INPUT" | bash-ast hook
```

Reads Claude PreToolUse hook JSON from stdin. Evaluates. Outputs gates-compatible
response JSON or exits 0 silently.

Output contract:
- `deny` → `{"permissionDecision": "deny", "reason": "..."}` to stdout, exit 0
- `ask` → `{"permissionDecision": "ask", "reason": "..."}` to stdout, exit 0
- `allow` → silent, exit 0
- `redirect` → `{"action": "redirect", "tool": "git_status", "args": {}}` to stdout, exit 0

### Analyze mode (human/debug)

```bash
bash-ast analyze --command 'git push origin main'
bash-ast analyze --file script.sh
```

Outputs structured JSON:
```json
{
  "commands": [...],
  "violations": [...],
  "response": {"action": "deny", "reason": "..."}
}
```

## Entry point

`pyproject.toml` should expose:
```toml
[project.scripts]
bash-ast = "bash_ast.cli:main"
```

## Example hook integration

```bash
#!/bin/bash
# .claude/hooks/PreToolUse/bash-gate
echo "$(cat)" | bash-ast hook
```

Replaces the current `_bash_gated` in `prompt/tools/executor.py`.
