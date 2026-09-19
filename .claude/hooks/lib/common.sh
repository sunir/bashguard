#!/bin/bash
# Hook Common Library - Shared boilerplate for all Claude Code hooks
# Version: 1.0
#
# PURPOSE: Provide consistent environment setup for all hook dispatchers
# USAGE: source "$(dirname "$0")/lib/common.sh" && setup_hook_env && check_hook_guards || exit 0
#
# WHAT THIS DOES:
#   1. Enables strict error checking (fail on unset variables)
#   2. Locates gates and colony tool binaries
#   3. Adds those tools to PATH so plugins can use them
#   4. Reads JSON input from Claude Code
#   5. Extracts session ID for state tracking
#
# AFTER SOURCING:
#   - INPUT contains the JSON from Claude Code
#   - SESSION_ID contains unique session identifier
#   - PATH includes the colony tools dir (wherever `colony` resolves from)
#   - SCRIPT_DIR points to .claude/hooks directory
#   - REPO_ROOT points to repository root
#
# setup_hook_env does ONLY the above — it never exits and never checks
# guards. check_hook_guards (below) is a separate, explicit call every
# dispatcher makes on its own: it reports whether guard_no_session/
# guard_network_down/guard_auth_failed fired, it does not decide what to do
# about it. Each dispatcher decides for itself (almost always: exit 0).

# OS abstraction layer — portable os_* primitives (mtime/mem/cpu/user/pids/sed) so hook
# code runs UNCHANGED on macOS (lisbeth) + Linux (ocean). Sourced here so every hook that
# sources common.sh gets it for free. Source-once guarded; safe if a hook also sources it.
source "$(dirname "${BASH_SOURCE[0]}")/os.sh"

setup_hook_env() {
    # Strict mode: fail if we reference undefined variables
    # This catches typos and missing env vars early
    set -u

    # Find where we are in the filesystem
    # BASH_SOURCE[1] = the script that called this function
    # We go up from .claude/hooks/<HookName> to .claude/hooks
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"

    REPO_ROOT="$(cd "$SCRIPT_DIR" && command -v gitroot >/dev/null 2>&1 && gitroot)"
    if [ -z "$REPO_ROOT" ]; then
        # Go up two more levels: .claude/hooks -> .claude -> repo root
        REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    fi

    # Locate the colony tools dir (msg, todo, automode, colony, gates tools
    # like wait-until/pipe-events, gitroot, subagents -- everything any repo's
    # deploy.toml ships) via wherever `colony` itself already resolves on the
    # inherited PATH. Self-validating (type -P only succeeds if colony is
    # genuinely runnable from there) and it's the ONE target directory.
    CLAUDE_BIN="${CLAUDE_BIN:-}"
    if [ -z "$CLAUDE_BIN" ]; then
        _colony_path="$(type -P colony 2>/dev/null)"
        [ -n "$_colony_path" ] && CLAUDE_BIN="$(dirname "$_colony_path")"
        unset _colony_path
    fi

    # Add the tools dir to PATH
    # ${VAR:+$VAR:} means: if VAR is set and non-empty, use "$VAR:", otherwise use nothing
    # This prevents adding an empty entry to PATH
    PATH="${CLAUDE_BIN:+$CLAUDE_BIN:}$PATH"

    # Read JSON input from Claude Code (comes via stdin)
    # Claude Code sends hook data as JSON: {tool_name, tool_input, session_id, etc.}
    INPUT="$(cat)"

    # Extract session ID for state tracking
    # Try these fields in order: session_id, transcript_path, or "unknown"
    # Session ID is used by has-changed to track state across hook invocations
    SESSION_ID="$(printf '%s' "$INPUT" | jq -r '.session_id // .transcript_path // "unknown"')"

    # Derive hook name from the calling script, UNLESS one was already
    # exported (Story: REAPER-OUTER-HOOK-ENTRYPOINT) -- ${BASH_SOURCE[1]}
    # resolves to whatever file directly sourced common.sh, which is now
    # "Stop.body" (etc), not "Stop": the real dispatcher moved behind
    # lib/hook-entrypoint.sh's exec chain (stub -> hook-entrypoint.sh ->
    # [reaper] -> *.body), and `exec`/subprocess boundaries mean the
    # *.body process has no bash call-stack connection to the original
    # stub at all. hook-entrypoint.sh exports the real event name before
    # its own final exec specifically so this stays correct; env vars
    # DO survive exec and reaper's subprocess.Popen (no env= override,
    # so it inherits). Falls back to the old introspection for anything
    # that sources common.sh directly, bypassing the entrypoint (tests,
    # standalone invocations).
    HOOK_NAME="${HOOK_NAME:-$(basename "${BASH_SOURCE[1]}")}"

    # Codex can keep using the hooks.json that was active when a session was
    # created even after the working directory moves to a sibling checkout.
    # When that happens, the hook command path and the JSON cwd disagree. Trust
    # cwd once, and hand off to that repo's dispatcher so repo-scoped tools
    # (msg, todo, git checks) inspect the active repo instead of the stale one.
    HOOK_INPUT_CWD="$(printf '%s' "$INPUT" | jq -r '.cwd // ""' 2>/dev/null || true)"
    if [ -n "$HOOK_INPUT_CWD" ] && [ "${COLONY_HOOK_REROOTED:-}" != "1" ]; then
        HOOK_INPUT_ROOT="$(cd "$HOOK_INPUT_CWD" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null || true)"
        if [ -z "$HOOK_INPUT_ROOT" ]; then
            HOOK_INPUT_ROOT="$(cd "$HOOK_INPUT_CWD" 2>/dev/null && pwd -P || true)"
        fi
        if [ -n "$HOOK_INPUT_ROOT" ] && [ "$HOOK_INPUT_ROOT" != "$REPO_ROOT" ]; then
            HOOK_INPUT_DISPATCHER="$HOOK_INPUT_ROOT/.claude/hooks/$HOOK_NAME"
            if [ -x "$HOOK_INPUT_DISPATCHER" ]; then
                export COLONY_HOOK_REROOTED=1
                exec "$HOOK_INPUT_DISPATCHER" <<<"$INPUT"
            fi
        fi
        unset HOOK_INPUT_ROOT HOOK_INPUT_DISPATCHER
    fi
    unset HOOK_INPUT_CWD

    # Export for plugins that might need them
    export SCRIPT_DIR REPO_ROOT SESSION_ID HOOK_NAME

    # Debug log this invocation
    _debug_log "$HOOK_NAME" "$INPUT"
}

# check_hook_guards — runs guard_no_session/guard_network_down/guard_auth_failed
# in order and reports, it does not decide. Returns 0 if none fired. Returns 1
# and prints "<guard_name>: <one-line reason>" to stdout if one did — what to
# DO about it (exit code, message shown to the agent, log-and-continue) is the
# caller's call, not this function's. Every dispatcher calls this explicitly
# right after setup_hook_env; it is not run implicitly as part of setup.
#
# Pure: always evaluates, no test-mode awareness inside. Whether to call it
# at all is the caller's decision, not this function's -- SKIP_GUARDS=1 means
# "don't call check_hook_guards", not "call it and have it silently no-op".
# Call sites: `[[ "${SKIP_GUARDS:-}" == "1" ]] || check_hook_guards >/dev/null || exit 0`.
#
# NETWORK_GUARD_BLOCKING=1 swaps the fast guard_network_down for the
# retry-with-backoff guard_network_down_blocking (Story: NETWORK-DOWN-GUARD).
# Stop.body is the only call site that sets it -- it's the only dispatcher
# with the 24-hour hook timeout budget the retry loop needs; every other
# dispatcher stays on the fast default so a real outage can't hard-kill it
# mid-retry under Claude Code's 60s default hook timeout.
check_hook_guards() {
    if guard_no_session; then
        _debug_log "$HOOK_NAME" "guard=no_session fired"
        printf 'no_session: SESSION_ID could not be established\n'
        return 1
    fi
    if [[ "${NETWORK_GUARD_BLOCKING:-}" == "1" ]]; then
        guard_network_down_blocking
    else
        guard_network_down
    fi
    if [[ $? -eq 0 ]]; then
        _debug_log "$HOOK_NAME" "guard=network_down fired"
        printf 'network_down: api.anthropic.com is unreachable\n'
        return 1
    fi
    if guard_auth_failed; then
        _debug_log "$HOOK_NAME" "guard=auth_failed fired"
        printf 'auth_failed: sustained auth errors in the transcript\n'
        return 1
    fi
    return 0
}

# Resolve a writable per-repo log dir under <base>, namespaced by uid so two
# OS users (e.g. claude, sunir) hitting the same repo can never collide on
# directory ownership. Echoes the dir (created). Story: HOOK-TMP-LOG,
# HOOK-LOG-DIR-SIMPLIFY.
# Usage: _hook_log_dir /tmp "Cascade"  ->  /tmp/<uid>/Cascade
_hook_log_dir() {
    local dir="$1/$(id -u)/$2"
    mkdir -p "$dir" 2>/dev/null
    printf '%s' "$dir"
}

# Append timestamped invocation to <log_dir>/<hook>.log (best-effort).
# Usage: _debug_log "Stop" "$INPUT"
_debug_log() {
    local hook="$1" input="$2"
    local repo_name="$(basename "${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}")"
    local log_dir="$(_hook_log_dir "${TMPDIR:-/tmp}" "$repo_name")"  # HOOK-TMP-LOG
    local ts="$(date -u +%FT%TZ)"
    printf '%s %s\n' "$ts" "$input" >> "$log_dir/${hook}.log" 2>/dev/null
}

# log_plugin_run <hook> <plugin_name> <exit> <stdout_len> <stderr_len> <effect_file>
#
# Story: PLUGIN-TELEMETRY
#
# Records one line per plugin per dispatch, in the format the Stop dispatcher
# already used, so every hook becomes measurable the same way:
#   dispatcher plugin=NAME exit=N stdout_len=N stderr_len=N effect=...
#
# WHY THE effect FIELD. Stop's log recorded stdout/stderr/exit only, and that
# metric wrongly declared three live components dead in a single day:
# git.sh's autocommit (acts via git), 61-index-memories-postgres (acts via
# postgres), 80-circuit-breaker (had sent 1,558 escalations via `msg send`).
# All three showed zero stdout. A format that can only see stdout teaches that
# same wrong lesson at scale. So a plugin may DECLARE what it did by writing to
# $HOOK_PLUGIN_EFFECT, and a plugin that declares nothing is recorded as
# effect=unobserved -- never as "did nothing". The format deliberately cannot
# express absence of activity, only absence of evidence.
#
# Best-effort throughout: telemetry must never change what a dispatcher does.
log_plugin_run() {
    local hook="$1" plugin="$2" ec="$3" out_len="$4" err_len="$5" effect_file="${6:-}"
    local effect="unobserved"
    if [ -n "$effect_file" ] && [ -s "$effect_file" ]; then
        effect="$(tr -d '\n\r' < "$effect_file" 2>/dev/null | cut -c1-120)"
        [ -n "$effect" ] || effect="unobserved"
    fi
    local repo_name log_dir
    repo_name="$(basename "${REPO_ROOT:-$(pwd)}")"
    log_dir="$(_hook_log_dir "${TMPDIR:-/tmp}" "$repo_name" 2>/dev/null)" || log_dir=""
    if [ -z "$log_dir" ] || ! printf 'dispatcher plugin=%s exit=%s stdout_len=%s stderr_len=%s effect=%s\n' \
            "$plugin" "$ec" "$out_len" "$err_len" "$effect" \
            >> "$log_dir/${hook}.log" 2>/dev/null; then
        # ABSENCE-AS-FACT: a silently missing log reads downstream as "this
        # plugin never ran", which is the same error the effect field exists to
        # prevent. Say so once per dispatch so a gap in the data is legible as a
        # gap rather than as a measurement. Once, not per plugin: a wedged log
        # dir affects every plugin in the pass and a storm would bury it.
        if [ -z "${_HOOK_TELEMETRY_WARNED:-}" ]; then
            _HOOK_TELEMETRY_WARNED=1
            printf '[hooks] telemetry unavailable for %s (log dir %s) — plugin activity for this dispatch is UNRECORDED, not absent\n' \
                "$hook" "${log_dir:-<unresolved>}" >&2
        fi
    fi
    return 0
}

# Log hook errors to colony system issues (JSONL format)
# Usage: log_hook_error "HookName" "plugin-name" exit_code "output"
log_hook_error() {
    local hook="$1" plugin="$2" ec="$3" output="$4"
    # Walk up from REPO_ROOT to find colony/system/issues
    local issues_dir="${REPO_ROOT:-$(pwd)}"
    while [ "$issues_dir" != "/" ]; do
        issues_dir="$(dirname "$issues_dir")"
        if [ -d "$issues_dir/colony/system/issues" ]; then
            issues_dir="$issues_dir/colony/system/issues"
            break
        fi
    done
    [ -d "$issues_dir" ] || return 0  # fail-open: no issues dir found, skip
    local repo_name="$(basename "${REPO_ROOT:-$(pwd)}")"
    local ts="$(date -u +%FT%TZ)"
    printf '{"ts":"%s","repo":"%s","hook":"%s","plugin":"%s","exit":%d,"output":"%s"}\n' \
        "$ts" "$repo_name" "$hook" "$plugin" "$ec" \
        "$(printf '%s' "$output" | head -c 500 | tr '"' "'" | tr '\n' ' ')" \
        >> "$issues_dir/hook-errors.jsonl" 2>/dev/null
}

# ── Hook guards ───────────────────────────────────────────────────────────
# Shared by all Stop-family dispatchers. Source common.sh to get these.

# Returns 0 (true) when SESSION_ID is absent — hooks can't do session work.
guard_no_session() {
    [[ -z "${SESSION_ID:-}" ]]
}

# Returns 0 (true) only for a curl error that is NOT itself evidence of
# outage-vs-contention ambiguity (shared by both guards below).
_network_down_connectivity_error() {
    [[ $1 -eq 6 || $1 -eq 7 || $1 -eq 28 ]]
}

# Returns 0 (true) when the Anthropic API endpoint is unreachable. Fast,
# single-shot -- the safe default used by every dispatcher via
# check_hook_guards. A single curl call on a 2s/5s budget can fail from
# host scheduling contention as easily as a real outage, but this guard
# must stay fast: PreToolUse, PostToolUse, UserPromptSubmit, SessionStart,
# and PreCompact all call check_hook_guards too, and none of them carry
# Stop's 24-hour hook timeout override (claude/settings.json leaves them
# at Claude Code's 60s default). See guard_network_down_blocking for the
# retry-with-backoff variant Stop opts into, which has the budget to
# afford it.
guard_network_down() {
    local ec=0
    curl --connect-timeout 2 --max-time 5 -so /dev/null https://api.anthropic.com 2>/dev/null || ec=$?
    _network_down_connectivity_error "$ec"
}

# Blocks until api.anthropic.com is reachable, then returns 1 (false --
# not down). Never reports "down": five colony repos hit guard_network_down
# within one 12-minute window on 2026-09-17, each falling through the Stop
# hook on what cross-repo evidence showed was host contention, not an
# outage, so one failed attempt is not sufficient evidence to end a
# session's automation loop. Retries with exponential backoff (1s, 2s,
# 4s, ...) capped at 300s (5 minutes), then continues polling every 5
# minutes indefinitely.
#
# Opt-in only, via check_hook_guards' NETWORK_GUARD_BLOCKING=1 -- Stop.body
# sets it because Stop alone has the 24-hour hook timeout budget to retry
# inside. Every other dispatcher (PreToolUse, PostToolUse,
# UserPromptSubmit, SessionStart, PreCompact) stays on the fast
# guard_network_down above: at Claude Code's 60s default hook timeout, a
# real outage longer than that would otherwise hard-kill any of them
# mid-retry, surfacing as hook-cancelled errors on every tool call and
# every prompt -- worse than the fall-through this guards against.
# Story: NETWORK-DOWN-GUARD.
#
# A curl error that is NOT a connectivity failure (DNS/connect/timeout) is
# a different fact -- e.g. a real HTTP-layer problem -- and returns
# immediately without retrying, same as guard_network_down.
guard_network_down_blocking() {
    local backoff=1
    local max_backoff=300
    while true; do
        local ec=0
        curl --connect-timeout 2 --max-time 5 -so /dev/null https://api.anthropic.com 2>/dev/null || ec=$?
        _network_down_connectivity_error "$ec" || return 1
        sleep "$backoff"
        if [[ $backoff -lt $max_backoff ]]; then
            backoff=$(( backoff * 2 ))
            [[ $backoff -gt $max_backoff ]] && backoff=$max_backoff
        fi
    done
}

# Returns 0 (true) when the transcript shows sustained auth errors (not transient 500s).
# Threshold ≥ 3 so a single Anthropic 500 doesn't kill automode.
guard_auth_failed() {
    guard_no_session && return 1
    local n
    if ! n=$(transcript latest -10 filter api_error count 2>/dev/null); then
        # Story: trace-sweep-stop-lib — this is one of the three guards that
        # decide whether the ENTIRE Stop cycle proceeds at all (called
        # directly from claude/hooks/Stop). A `transcript`
        # command failure (missing binary, corrupt transcript) was
        # previously indistinguishable from "genuinely zero auth errors" —
        # both silently return 1 (not auth-failed) here. That distinction
        # matters colony-wide: if `transcript` ever regressed, this guard
        # would stop detecting sustained auth failure on every Stop cycle,
        # for every agent, with nothing to show it had gone dark.
        _debug_log "${HOOK_NAME:-guard_auth_failed}" "guard_auth_failed transcript-command-failed — treating as no-auth-failure (fail-open, unchanged)"
        return 1
    fi
    [[ "${n:-0}" -ge 3 ]]
}

# hook_field_nonempty <jq_field_path>
# Returns 0 (true) when a claimed field in $INPUT is present and non-empty.
# Companion to hook_field_path_exists; both back the per-event input-validation
# gate (HookEventOps.REQUIRED_VALID_FIELDS) that rejects an orphaned event
# before any plugin runs. Story: SUBAGENTSTOP-ORPHANED-EVENTS.
# RESTORED: db0e37f (a strip-trace-printfs refactor) deleted this function
# outright instead of just stripping its printfs -- collateral, because the
# gate had already fallen out of system's dispatchers so it looked unused. A
# generated dispatcher calling a now-missing `hook_field_nonempty` gets 127 →
# `|| exit 0` → it silently blocks EVERY event before plugins. So the gate and
# this validator must be restored together (see fix/restore-subagentstop-orphan-gate).
hook_field_nonempty() {
    local field="$1" value
    value="$(printf '%s' "${INPUT:-}" | jq -r ".${field} // empty" 2>/dev/null)"
    [[ -n "$value" ]]
}

# hook_field_path_exists <jq_field_path>
# Returns 0 (true) when a claimed field in $INPUT is present, non-empty, AND
# names a path that actually exists on disk right now -- catches fields that
# claim a location that was never actually written (a common shape for
# internal/ephemeral events that reuse a real event's schema without being
# real). Story: SUBAGENTSTOP-ORPHANED-EVENTS -- Claude Code emits SubagentStop
# for at least one such internal mechanism (agent_type "", agent_transcript_path
# never written; matches upstream github.com/anthropics/claude-code/issues/27423,
# /issues/27755, both closed stale/unfixed). A JSON payload naming a path is a
# CLAIM, not a guarantee -- validate it, don't trust it.
hook_field_path_exists() {
    local field="$1" value
    value="$(printf '%s' "${INPUT:-}" | jq -r ".${field} // empty" 2>/dev/null)"
    [[ -n "$value" && -f "$value" ]]
}

# ── Cross-repo permissions ─────────────────────────────────────────────────
# Story: cross-repo-permissions
#
# check_permissions REPO_PATH AGENT_NAME
# Returns 0 if agent is allowed to write to repo, 1 if denied.
# Reads REPO_PATH/.permissions (top-to-bottom, first match wins).
# If no .permissions file exists, access is allowed (fail-open).
#
# .permissions format:
#   allow brook      # named agent allowed
#   allow *          # everyone allowed
#   deny  spiral     # named agent denied
#   deny  *          # everyone denied (evaluate AFTER specific allows)
#   # comment lines ignored; blank lines ignored
check_permissions() {
    local repo_path="$1"
    local agent_name="${2:-}"
    local perms_file="$repo_path/.permissions"

    if [[ ! -f "$perms_file" ]]; then
        _log_permissions_fail_open_once "$repo_path"
        return 0  # no .permissions = open (backwards-compatible)
    fi
    [[ -n "$agent_name" ]] || return 0  # unknown agent = open

    agent_name="$(printf '%s' "$agent_name" | tr '[:upper:]' '[:lower:]')"

    local action name
    while IFS= read -r line; do
        line="${line%%#*}"          # strip inline comments
        line="${line//  / }"        # collapse multiple spaces
        line="${line# }"            # strip leading space
        [[ -z "$line" ]] && continue  # skip blank
        read -r action name _ <<< "$line" 2>/dev/null || continue
        name="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
        if [[ "$name" == "$agent_name" || "$name" == "*" ]]; then
            [[ "$action" == "allow" ]] && return 0
            [[ "$action" == "deny" ]] && return 1
        fi
    done < "$perms_file"
    return 0  # no matching rule = open
}

# _log_permissions_fail_open_once REPO_PATH
# Story: CROSS-REPO-GUARD-COVERAGE-VISIBILITY (the_management %7486, measured
# 1/160 repos have adopted .permissions -- fail-open is the right default,
# but the gap should be discoverable without grep-counting files by hand).
#
# Logs via the same _debug_log convention guard_auth_failed uses for its own
# dark-path case, from the CALLING agent's own hook-log context (not the
# target repo's -- writing there would be exactly the cross-repo write this
# guard exists to gate). Deduped by a marker file keyed on the target repo's
# own path, under a central location, so this fires once per target repo
# (across every caller) rather than once per tool call.
_log_permissions_fail_open_once() {
    local repo_path="$1"
    local marker_dir="${TMPDIR:-/tmp}/$(id -u)/permissions-fail-open-seen"
    mkdir -p "$marker_dir" 2>/dev/null
    local marker="$marker_dir/$(printf '%s' "$repo_path" | tr '/' '_')"
    [[ -f "$marker" ]] && return 0
    touch "$marker" 2>/dev/null
    _debug_log "cross-repo-guard" "check_permissions fail-open: $repo_path has no .permissions file (allow-all default)"
}

# reaper_cmd_for <grace_ms> — sets the global array REAPER_CMD to the
# reaper prefix for wrapping one plugin invocation, or an empty array if
# reaper is unavailable.
#
# Story: REAPER-DISPATCHER-INTEGRATION (gates PRD, %170) -- the harness can
# kill a dispatcher's launcher process mid-hook; every plugin running as a
# descendant dies with it, immediately, mid-cleanup (a half-deleted lock
# file, a FIFO never closed). gates' bin/reaper detaches a supervisor that
# outlives the launcher kill, gives the plugin a grace period to finish on
# its own SIGTERM, then SIGKILLs the whole process group -- turning an
# abrupt, uncontrolled death into a bounded, supervised one.
#
# FAIL-OPEN: gates hasn't wired `reaper` into every host's PATH yet (no
# [bin] entry as of this story). Falls back to running the plugin directly,
# unprotected, exactly like before this integration existed -- a dispatcher
# must never fail or block because an optional supervisor isn't installed.
# Resolution order matches automode's own signal-cli fallback pattern
# (PATH first, then the known prod path) for consistency across tools that
# do this same "is the new gates primitive here yet" check.
#
# CALLER CONTRACT: reaper exits 143 (128+SIGTERM) when IT cancelled the
# plugin (harness killed the dispatcher) -- callers must treat 143 as
# "cancelled", not as the plugin's own failure exit code, and must not
# log it via log_hook_error the way a real nonzero plugin exit would be.
#
# Usage: reaper_cmd_for 5000; "${REAPER_CMD[@]+"${REAPER_CMD[@]}"}" "$plugin" ...
#
# That expansion, not the naive "${REAPER_CMD[@]}", is required: every
# dispatcher here runs under `set -u`, and this host's bash (3.2.57,
# macOS's shipped /bin/bash) throws "unbound variable" on "${ARR[@]}" for
# an EMPTY array under set -u -- confirmed directly, not assumed. The
# +"${REAPER_CMD[@]}" form is the portable idiom: expands to nothing when
# the array is empty, to every element unchanged when it isn't.
reaper_cmd_for() {
    local grace_ms="${1:-5000}"
    REAPER_CMD=()
    local _reaper_bin
    _reaper_bin="$(command -v reaper 2>/dev/null)"
    if [[ -z "$_reaper_bin" && -x "$HOME/prod/gates/bin/reaper" ]]; then
        _reaper_bin="$HOME/prod/gates/bin/reaper"
    fi
    [[ -n "$_reaper_bin" ]] && REAPER_CMD=("$_reaper_bin" --grace-ms "$grace_ms" --)
}

# Example usage in a hook:
#
#   #!/bin/bash
#   source "$(dirname "$0")/lib/common.sh"
#   setup_hook_env
#
#   # Now you can use:
#   # - $INPUT (JSON from Claude)
#   # - $SESSION_ID (unique session identifier)
#   # - any-errors, has-changed, claude-block-stop (from gates)
#   # - msg, todo (from colony)
#   # - check_permissions REPO_PATH AGENT_NAME → 0=allow 1=deny
