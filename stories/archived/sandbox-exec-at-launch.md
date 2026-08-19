---
id: SANDBOX-EXEC-LAUNCH
---
# sandbox-exec/bwrap at launch: session-level deny-default sandbox

`colony-shell` provides session sandboxing via allow-default SBPL (deny foreign
repos, deny SSH/history). bashguard's per-command seatbelt uses deny-default
(allow only project dir writes). Neither applies a deny-default sandbox at the
session level — the entire claude process runs outside any hard boundary.

`bashguard launch -c 'CMD'` fills this gap: it wraps any command in a deny-default
sandbox-exec (macOS) or bwrap (Linux) profile before exec'ing, so the full process
tree inherits the constraint. Colony automode uses this to sandbox every agent
session at start rather than relying solely on hook-time interception.

The deny-default profile allows:
- Reads anywhere (agent needs system libs, tools, homebrew)
- Writes to the project dir (--project or CWD)
- Writes to ~/.claude (config, conversation history, hooks)
- Writes to /private/tmp and standard temp paths
- Writes to /var/db/ai/claude (prod deployments, colony state)
- Process exec + signal (subprocesses must work)
- Network: denied by default (same as per-command seatbelt)

DYLD interposer was explored and abandoned (SIP strips env vars for Dock-launched
apps). sandbox-exec/bwrap at launch is the "one habit to learn" alternative.

## Contract

CLI: `bashguard launch [-c CMD] [--project DIR]`
On exec: `sandbox-exec -f profile.sb /bin/sh -c CMD` (macOS)
         `bwrap --... /bin/sh -c CMD` (Linux -- stubbed, macOS-first)
Profile: stable path keyed to project root hash (cached, regenerated on upgrade)
Fail-open: if sandbox-exec unavailable, exec CMD directly.

## Tests

`tests/test_launch_mode.py`
- Profile generated with deny default + allow project writes + allow ~/.claude
- --project override changes the profile's allowed path
- CWD used as project when --project omitted
- sandbox-exec absent triggers fail-open (exit code passes through)
- Profile path is stable (same project → same file, not regenerated each call)
