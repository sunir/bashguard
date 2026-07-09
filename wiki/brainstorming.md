
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

---

## Brainstorm — Session 3 (2026-07-09)

- "similarity proposes, consequence disposes" — the Haiku semantic layer needs a feedback loop eventually; right now it fires and forgets, which means its proposals are never validated. A consequence signal (the_management acking/rejecting alerts) would let it calibrate over time.
- path-ownership check generalizes beyond contract enforcement: any hook that validates "is this agent in its lane?" could use the same directory.json + colony path convention
- layer 2 Haiku call could be replaced by a local embedding similarity check if latency becomes an issue — contracts are short, embeddings are fast, no API needed
- session-questionnaire binary doesn't exist in this repo; would be worth adding to measure cross-session coherence for bashguard specifically

---

## Brainstorm — Session 4 (2026-07-09)

- GTFOBins still has gaps: `python -c "import os; os.system('sh')"` is caught by evasion.eval but `python3 -c "import pty; pty.spawn('/bin/sh')"` may not be — worth checking pty.spawn detection
- `vim` appears in forbidden_binary candidate list but should NOT be banned outright — only the shell-escape variant. evasion.vim_shell is the right split (detect patterns, not binaries)
- parser probe pattern is now stable enough to document as a wiki page: "rule authoring checklist" with the probe-first step
- `less` and `more` also have GTFOBins shell escape via `!cmd` in interactive mode — but they're non-interactive in automated context so may be low-value
- The 1336-test count feels like a milestone worth surfacing in readme or metrics endpoint
