---
id: CONTRACT-ENFORCEMENT-HOOK
---
# Contract Enforcement Hook

Agents in the colony each have a `/contract` in `core/identity.md` defining their ROLE, OWNS, BOUNDARIES, and COLLABORATES-WITH. When an agent acts outside its BOUNDARIES, it erodes trust and violates the governance model.

The trigger case: deploy agent committing into qa's repo — a path-ownership violation, computable from the directory.

A `/contract` is SEMANTIC (natural-language role/owns/boundaries) so it is NOT fully computable by a deterministic hook. Two layers:

1. **CHEAP DETERMINISTIC**: path-ownership — is this agent operating on files under another agent's repo? Computable from directory + cwd. Block/warn fast.
2. **SEMANTIC**: is this TASK within my role? Not computable deterministically → Haiku LLM with directory + action, out-of-band. Never blocks the hot path.

Both layers **fail-open** (advisory, never lockout). — Sunir's correction, 2026-07-09.

## Design decisions

**Three-way ownership split:**
- sysop: colony-contracts COMPILER (scans repos → JSON, includes `generated_at`)
- the_management: ARTIFACT (`the_management/contracts/directory.json`), regen on ratification
- bashguard: ENFORCEMENT hook (reads directory.json read-only, fail-open)

**Fail-open is non-negotiable.** If directory.json is missing, unparseable, or stale (generated_at > 24h): warn + alert the_management, then ALLOW. Never block. A wedged hook wedges every agent.

**Advisory only, never lockout.** The hook warns and routes; the_management escalates if needed.

## Layer 1: Path-ownership check (hot path, deterministic)

Fires on every tool invocation (Bash, Write, Edit, MultiEdit — any tool that touches files or runs commands):

1. Read stdin JSON: `tool_name`, `tool_input`, `cwd`.
2. Locate `the_management/contracts/directory.json`. Absent → silent allow.
3. Parse JSON; unparseable → warn stderr + allow.
4. Check `generated_at`; stale (> 24h) or missing → warn stderr + `msg alert the_management` + allow.
5. Resolve all file paths referenced by the tool call (command args for Bash, `file_path` for Write/Edit).
6. For each path: check if it falls under another agent's repo root (from directory). Each repo entry maps to a known colony path `<colony_root>/<repo>/`.
7. Current agent's own repo → always allow.
8. Another agent's repo root → warn stderr + `msg alert the_management "Path-ownership violation: <this_agent> touching <other_repo>"` + allow (advisory).

## Layer 2: Semantic check (out-of-band, Haiku)

For Bash tool calls that pass layer 1 (no path-ownership violation), spawn a background Haiku call with:
- The full directory.json
- The current agent's ROLE + OWNS
- The bash command being executed

Haiku answers: "Is this command within this agent's OWNS domain? If not, which BOUNDARIES clause does it violate?"

If Haiku says OUT_OF_SCOPE: `msg alert the_management` with Haiku's reasoning + allow through.

The Haiku call is **fire-and-forget** — the hook exits 0 immediately, Haiku runs in background. Never blocks.

## Directory.json schema

Sysop's compiler currently outputs a flat array. The `generated_at` wrapper is sysop's to add. Hook handles both:
- Flat array `[{repo, role, owns, boundaries, collaborates}]` → treat as infinitely stale (warn + allow)
- Wrapped `{generated_at, contracts: [...]}` → check freshness normally

## Files

- `hooks/11-contract-enforcement` — main hook (bash: parse stdin, path check, spawn layer 2)
- `hooks/lib/contract_path_check.py` — layer 1 path-ownership logic (Python, independently testable)
- `hooks/lib/contract_semantic_check.py` — layer 2 Haiku call (Python, fire-and-forget)
- `tests/test_contract_path_check.py` — layer 1 unit tests
- `tests/test_contract_semantic_check.py` — layer 2 unit tests
- `tests/test_contract_enforcement.py` — hook integration tests

## Tests

`tests/test_contract_path_check.py`:
- File path inside own repo → allow
- File path inside another agent's repo → warn + alert
- Bash command touching another repo's path → warn + alert
- File path outside all known repos → allow (not all paths are owned)
- Missing directory.json → allow silently
- Stale generated_at → warn + alert + allow

`tests/test_contract_enforcement.py`:
- Non-file tool (e.g., Read on own repo) → allow silently
- Write to another agent's repo → layer 1 fires, warn + allow
- Bash `git commit` in own repo → layer 2 spawned, layer 1 silent
- Unparseable JSON → warn + allow
- directory.json absent → silent allow

## Blocked on

1. sysop: add `generated_at` to colony-contracts compiler output
2. the_management: ratify + commit first `the_management/contracts/directory.json`
3. colony-root path map: need a stable way to map `repo` names to absolute paths (likely `<colony_root>/<repo>` convention)
