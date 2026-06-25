
---

## Brainstorm — 2026-06-16

- awk/gawk `system()` call detection — `awk 'BEGIN{system("/bin/sh")}'` not yet caught; need inline program scanning
- bind shell pattern — `nc -lvp 4444 -e /bin/sh` (listen + exec); nc_e rule currently only catches connect mode
- FUSE session diff/commit/rollback — tilde's atomic transaction at the session level; FUSE overlay already captures writes, need the UX layer
- `bashguard diff` CLI mode — show what this session changed (overlay_diff output) without committing
- `evasion.interpreter_shell` for tclsh — `tclsh` with inline `exec /bin/sh` in a script; no `-e` flag, need program content scanning
- GTFOBins "file read" category — xxd/od/strings on /etc/shadow; partially covered by credentials.privileged_path but not all encoding tools
