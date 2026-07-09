
---

## Brainstorm — 2026-06-16

- awk/gawk `system()` call detection — `awk 'BEGIN{system("/bin/sh")}'` not yet caught; need inline program scanning
- bind shell pattern — `nc -lvp 4444 -e /bin/sh` (listen + exec); nc_e rule currently only catches connect mode
- FUSE session diff/commit/rollback — tilde's atomic transaction at the session level; FUSE overlay already captures writes, need the UX layer
- `bashguard diff` CLI mode — show what this session changed (overlay_diff output) without committing
- `evasion.interpreter_shell` for tclsh — `tclsh` with inline `exec /bin/sh` in a script; no `-e` flag, need program content scanning
- GTFOBins "file read" category — xxd/od/strings on /etc/shadow; partially covered by credentials.privileged_path but not all encoding tools

---

## Brainstorm — 2026-07-09

- CONTRACT ENFORCEMENT hook: the classification problem (is this bash command outside OWNS?) may not be fully solvable via static rules — could be a "semantic match against BOUNDARIES items" using a lightweight LLM call at CONFIRM verdict level
- Compiled directory refresh: cupdate is the right mechanism but there's also a lazy-init pattern — load on first miss, cache in /tmp with a TTL, invalidate on colony-contracts invocation
- bashguard as contract enforcer for itself: I wrote my own /contract; the recursive enforcement loop is interesting — when I block a command outside my OWNS, am I enforcing my own boundaries or the hook's?
- tclsh/wish/expect rules landed but `evasion.interpreter_shell` still doesn't cover inline exec — content scanning at heredoc level is the next gap (GTFOBins one-liners)
- nc listen-mode fix shipped — bind shell pattern (nc -e /bin/sh in listen mode) is the next nc gap
