---
id: TCLSH-INTERPRETER-SHELL
---
# tclsh/wish/expect: GTFOBins shell escape via pipe and heredoc

GTFOBins documents tclsh as a shell-escape vector:

  echo "exec /bin/sh" | tclsh
  tclsh <<'EOF'
  exec /bin/sh
  EOF

tclsh has no `-e` flag, so `evasion.interpreter_shell` misses it. The
pipe and heredoc patterns exist but `tclsh` isn't in the sets those
rules check (`_SHELLS` in evasion.py, `_SCRIPT_INTERPS` in evasion_gaps.py).

`wish` (Tcl/Tk) and `expect` have the same `exec` shell-escape vector.

## Contract

- `echo ... | tclsh` → BLOCK via `evasion.pipe_to_shell`
- `tclsh <<EOF` → BLOCK via `evasion.heredoc_interpreter`
- same for `wish`, `expect`

## Fix

- `evasion.py` `_SHELLS`: add `tclsh`, `wish`, `expect`
- `evasion_gaps.py` `_SCRIPT_INTERPS`: add `tclsh`, `wish`, `expect`

## Tests

`tests/rules/test_tclsh_detection.py`
- echo ... | tclsh → BLOCK pipe_to_shell
- tclsh heredoc → BLOCK heredoc_interpreter
- wish and expect variants → BLOCK
- plain tclsh script.tcl → ALLOW (can't inspect file content)
