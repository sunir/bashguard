# Response Policies

## What a response policy does

Takes a `Violation` and returns a `Response` that tells the caller what to do.

## Data shapes

```python
@dataclass
class Response:
    action: Literal["deny", "ask", "allow", "redirect"]
    reason: str
    redirect_to: str | None = None   # safe tool name if action=redirect
    redirect_args: dict | None = None  # args for the safe tool
```

## Built-in response policies

### DenyResponse
Map violation → `claude-deny` style output. Used for critical violations.

### AskResponse
Map violation → `claude-ask` style output. Used for uncertain/risky ops.

### RedirectResponse
Map violation → redirect to a safe structured tool.

Key redirects to implement:
- `cat <file>` → `read_file(path=<file>)`
- `ls <dir>` → `list_dir(path=<dir>)`
- `git status` → `git_status()`
- `git log ...` → `git_log(n=...)`

This is what `prompt repl` needs: instead of blocking `cat README.md`,
reroute to `read_file("README.md")` transparently.

### AllowResponse
Pass-through. Used for safe commands that don't need redirection.

## Composition

```python
responder = ResponsePolicy([
    (GitPolicy(), RedirectResponse(safe_tool_map)),
    (FileWritePolicy(), DenyResponse()),
    (DangerousCommandPolicy(), DenyResponse()),
])

result = responder.evaluate(script)
# result.action in ("deny", "ask", "allow", "redirect")
```

## Integration with gates

CLI output should map to `gates` conventions:
- `deny` → emit `claude-deny` JSON + exit 0
- `ask` → emit `claude-ask` JSON + exit 0
- `allow` → exit 0 silently
- `redirect` → emit JSON with safe tool name + args

See `specs/03-cli.md` for CLI contract.
