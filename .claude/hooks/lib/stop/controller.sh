#!/bin/bash
# Stop controller library.
#
# Factored from claude/hooks/Stop. This file composes the Stop pieces:
# bootstrap, context/messagebag, plugin workers, next_turn decision. The
# session/network/auth guards (guard_no_session/guard_network_down/
# guard_auth_failed) live in lib/common.sh and are called directly from
# claude/hooks/Stop, not through here — Story: KILL-GUARD-GAUNTLET-WRAPPER.
#
# Story: STOP-HOOK-STRIP-AUTOMODE — this used to also dispatch to
# automode-controller as the default "nothing else spoke" behavior, gated
# behind a 3-item pre-plugin chain (force-stop / subagent-pending / relax
# sentinels under .automode/). All of that is gone: Stop no longer knows
# automode exists. It runs plugins, collects what they say, and decides.

_stop_controller_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$_stop_controller_dir/bootstrap.sh"
# shellcheck disable=SC1091
source "$_stop_controller_dir/context.sh"
# shellcheck disable=SC1091
source "$_stop_controller_dir/plugins.sh"
# shellcheck disable=SC1091
source "$_stop_controller_dir/decide.sh"

stop_run() {
    stop_context_init
    stop_collect_plugins

    local next_turn
    next_turn="$(stop_decide_after_plugins)"
    printf 'controller next_turn=%s\n' "$next_turn" >> "${_stop_log:-/dev/null}" 2>/dev/null

    if [[ "$next_turn" == "continue" ]]; then
        stop_messagebag_render_sections >&2
        printf '\nDebug: %s\n' "${_stop_log:-Stop.log}" >&2
        return 2
    fi

    # "stop" (a plugin explicitly said so) and "wait" (no plugin had an
    # opinion) both mean the same thing now: nothing to block on, allow it.
    return 0
}
