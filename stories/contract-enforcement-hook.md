---
id: CONTRACT-ENFORCEMENT-HOOK
---
# Contract Enforcement Hook

Agents in the colony each have a `/contract` in `core/identity.md` defining their ROLE, OWNS, BOUNDARIES, and COLLABORATES-WITH. When an agent acts outside its BOUNDARIES, it erodes trust and violates the governance model.

The contract enforcement hook reads the compiled contract directory (`the_management/contracts/directory.json`) and warns the_management when a bash command appears to operate outside the current agent's BOUNDARIES.

## Design decisions (from the_management, 2026-07-09)

**Three-way ownership split:**
- sysop: colony-contracts COMPILER (scans repos → JSON, includes `generated_at`)
- the_management: ARTIFACT (`the_management/contracts/directory.json`), regen on ratification
- bashguard: ENFORCEMENT hook (reads directory.json read-only, fail-open)

**Fail-open is non-negotiable.** A hard-failing hook could wedge every agent. If the directory.json is missing, unparseable, or stale (generated_at > 24h), the hook must: warn + alert the_management, then ALLOW. Never block.

**MVP: advisory (warn-only), never block.** Classification is not exact. The hook warns and routes to the_management for escalation. Blocking comes after classification is validated.

## Contract

The hook (`hooks/11-contract-enforcement`) fires on every Bash tool invocation:

1. Check `tool_name` from stdin JSON — only fire for `Bash`. Non-Bash tools exit 0 immediately.
2. Locate `the_management/contracts/directory.json`. If absent → silent allow.
3. Parse JSON. If unparseable → warn stderr + allow.
4. Check `generated_at` field. If stale (> 24h) or missing → warn stderr + `msg alert the_management` + allow.
5. Find current repo's contract entry (match `repo` = basename of cwd git root).
6. If no entry → silent allow (not all repos have contracts yet).
7. For each BOUNDARIES item, check bash command against pattern heuristics.
8. On match: warn stderr + `msg alert the_management "Contract boundary: <item>"` + allow.
9. No match: silent allow.

## Boundary pattern matching

BOUNDARIES items are free-text. The classifier (`hooks/lib/contract_classifier.py`) converts boundary `item` fields to heuristic keyword sets, matched against the bash command. Only HIGH-confidence matches fire — false positives are worse than misses for an advisory hook.

## Directory.json schema

Sysop's compiler currently outputs a flat array. The `generated_at` wrapper is sysop's to add. The hook handles both:
- Flat array `[{repo, role, owns, boundaries, collaborates}]` → treat as infinitely stale (warn-only)
- Wrapped object `{generated_at, contracts: [...]}` → check freshness

## Files

- `hooks/11-contract-enforcement` — main hook (bash)
- `hooks/lib/contract_classifier.py` — boundary pattern matching (Python, independently testable)
- `tests/test_contract_enforcement.py` — hook integration tests
- `tests/test_contract_classifier.py` — classifier unit tests

## Tests

`tests/test_contract_enforcement.py`:
- Missing directory.json → allow, no error
- Unparseable JSON → allow, warn stderr
- Stale generated_at (> 24h) → allow, warn stderr, alert the_management
- Repo not in directory → allow, silent
- Command matches BOUNDARY pattern → allow, warn stderr, alert the_management
- Command does NOT match BOUNDARY pattern → allow, silent
- Non-Bash tool → exit 0 immediately

`tests/test_contract_classifier.py`:
- Boundary "deploy" + git push → match
- Boundary "contract" + colony-contracts command → match
- Boundary "secret storage" + aws secretsmanager → match
- Boundary "auth" + unrelated command → no match

## Blocked on

1. sysop: add `generated_at` to colony-contracts compiler output
2. the_management: ratify + commit first `the_management/contracts/directory.json`
3. the_management: confirm warn-only MVP (no block) for P11 — awaiting reply
