#!/bin/bash
# Shared hook entrypoint: reaper-wraps <EventName>.body.
#
# Story: REAPER-OUTER-HOOK-ENTRYPOINT
#
# gates PRD %170 asked every dispatcher to run its PLUGINS through reaper
# (see reaper_cmd_for, lib/common.sh) -- but a review of that integration
# (inbox/reaper.md) found a real gap: if the harness kills only the Stop
# process's own PID (not its whole process group), Stop dies, but the
# CURRENTLY-RUNNING plugin's own reaper launcher is an ordinary child --
# it survives as an orphan, its lifetime pipe stays open, and nothing ever
# tells its detached supervisor to cancel the plugin. Per-plugin reaper
# wrapping alone only protects the "harness kills the process group"
# case, not "harness kills just the launcher PID" -- and gates' own PRD
# specifically named "killing the ... launcher" as the trigger.
#
# The fix: make the hook PID the harness actually knows about -- the
# dispatcher file itself -- ALSO a reaper launcher, one level up from any
# plugin-level wrapping. Sunir: "instead of having a separate hook body
# for each hook, would it make sense to have one script that loads with
# the reaper, that takes the hook name as a parameter, and then loads the
# normal hook?" -- this file is that one script. Every event dispatcher
# (Stop, PreToolUse, ...) is now a 3-line stub that execs this, naming
# itself; the real dispatcher logic moved to a sibling <EventName>.body
# file (synced the same as any other top-level file under
# system/claude/hooks/ -- no change needed to colony setup's sync).
#
# Usage: exec lib/hook-entrypoint.sh <EventName> [harness args...]
#
# FAIL-OPEN: reaper not on PATH/prod fallback -> exec the body directly,
# unwrapped -- identical to this integration not existing. A missing
# optional supervisor must never block a hook.

set -uo pipefail

EVENT="${1:?hook-entrypoint.sh requires an event name as \$1}"
shift

# common.sh's setup_hook_env derives HOOK_NAME from ${BASH_SOURCE[1]} (the
# file that sourced it) when this isn't already set -- that resolves to
# "$EVENT.body", not "$EVENT", once the real dispatcher moves behind this
# exec chain. Export the real name explicitly; it survives exec and
# reaper's subprocess.Popen (env is inherited, not overridden).
export HOOK_NAME="$EVENT"

# Deliberately NOT named HOOK_DIR: that's a load-bearing external-override
# env var the dispatcher bodies read (HOOK_DIR="${HOOK_DIR:-$SCRIPT_DIR/...}")
# to point plugin discovery at a synthetic directory (tests do this).
# Naming this the same thing would clobber a real caller-supplied override
# before it ever reaches the body -- confirmed live: test-plugin-telemetry.sh
# broke silently this exact way during review.
_ENTRYPOINT_SELF_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
BODY="$_ENTRYPOINT_SELF_DIR/$EVENT.body"

if [[ ! -f "$BODY" ]]; then
    echo "FATAL: hook body missing: $BODY" >&2
    exit 2
fi
[[ -x "$BODY" ]] || chmod +x "$BODY" 2>/dev/null

# Grace period per event -- same values and same reasoning as
# reaper_cmd_for's own per-event choices (lib/common.sh): cleanup-critical
# hooks get longer, guard/validator hooks get shorter, everything else
# gets the default.
case "$EVENT" in
    Stop|SessionEnd) _grace_ms=10000 ;;
    PreToolUse|UserPromptSubmit) _grace_ms=2000 ;;
    *) _grace_ms=5000 ;;
esac

_reaper_bin="$(command -v reaper 2>/dev/null)"
if [[ -z "$_reaper_bin" && -x "$HOME/prod/gates/bin/reaper" ]]; then
    _reaper_bin="$HOME/prod/gates/bin/reaper"
fi

if [[ -n "$_reaper_bin" ]]; then
    exec "$_reaper_bin" --grace-ms "$_grace_ms" -- "$BODY" "$@"
else
    exec "$BODY" "$@"
fi
