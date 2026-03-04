# bash-ast — Story

## Who wants what and why

LLM agents (like `prompt repl`) execute bash commands on behalf of users.
Today, safety is enforced by a string-matching allowlist (`SAFE_COMMANDS` in
`tools/impl/shell.py`). This is brittle — it matches command names but ignores
flags, arguments, redirect targets, and command substitutions.

We need a parser that understands bash structure so policies can reason about
what a command actually does, not just what it's named.

## Core use case

An agent tries to run:

```bash
cat /etc/passwd > /tmp/out && git push origin main
```

bash-ast should:
1. Parse this into structured CommandNodes (name, flags, args, redirect targets)
2. Run security policies against each node
3. Return a response: deny / ask user / allow / redirect to safe tool

## Primary users

- `prompt repl` bash-gate (`tools/executor.py` → `_bash_gated`)
- Claude Code PreToolUse hooks (via CLI, like `gates/bin/claude-tools`)
- Any agent that needs to gate shell execution

## Success looks like

- `rm -rf /etc` → denied (DangerousCommandPolicy)
- `echo hello > /etc/passwd` → denied (FileWritePolicy)
- `git push origin main` → denied (GitPolicy)
- `git status` → allowed, optionally redirected to `git_status()` safe tool
- `cat README.md` → allowed, optionally redirected to `read_file()` safe tool
- `rm -rf /tmp/build` → allowed

## What's already built

- `bash_ast/parser.py` — tree-sitter bash → CommandNode list (33 tests passing)
- `bash_ast/policies/` — FileWritePolicy, GitPolicy, DangerousCommandPolicy, compose()
- `tests/test_parser.py`, `tests/test_policies.py`

## What's next

See `specs/02-response-policies.md` and `specs/03-cli.md`
