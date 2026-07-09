---
id: BG-AWK-SYSTEM
---
# Detect awk/gawk system() and pipe abuse

GTFOBins documents awk, gawk, mawk as shell-escape vectors:

  awk 'BEGIN{system("/bin/sh")}'
  awk 'BEGIN{cmd="id"; cmd | getline result; print result}'

The `system()` call executes arbitrary shell commands. The `cmd | getline`
pipe-getline idiom also runs commands. Both bypass existing detection
because they look like normal awk invocations from the parser's perspective.

## Contract

Rule: `evasion.awk_shell`
Severity: CRITICAL
Detect:
- `awk`/`gawk`/`mawk`/`nawk` with `-f -` or inline program containing
  `system(`, `cmd |`, or `| getline`
- Inline programs accessed via `-v` assignments are excluded (legitimate)

## New rule file

`bashguard/rules/awk_shell.py` — `evasion.awk_shell`

## Tests

`tests/rules/test_awk_shell.py`
- system() in BEGIN block
- cmd | getline idiom
- print | "/bin/sh"
- gawk variant
- safe awk (field printing) is allowed
