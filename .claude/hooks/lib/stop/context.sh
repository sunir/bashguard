#!/bin/bash
# Stop context and messagebag — the shared-state contract for lib/stop/*.
# Story: STOP-CONTROLLER-REBALANCE
#
# CONTRACT — every piece of mutable state shared across the Stop controller
# lives HERE and only here. Other lib/stop files must go through this API;
# they may not declare, write, or read these variables directly. Reading this
# header tells you the entire shared-state surface of the controller.
#
# State fields (all reset by stop_context_init at the top of stop_run):
#
#   _stop_message_sections             string ("" = none)
#       Human-readable briefing sections. Appended by plugins.sh via
#       stop_messagebag_add_section; rendered by briefing.sh via
#       stop_messagebag_render_sections.
#
#   _stop_next_turn_stop_requested     "true" | "false"
#       Set by stop_context_request_stop (plugins emitting next_turn=stop).
#       Read via stop_context_stop_requested.
#
#   _stop_next_turn_continue_requested "true" | "false"
#       Set by stop_messagebag_request_continue (plugins emitting
#       next_turn=continue). Read via stop_context_continue_requested.
#
# NOTE: the variable NAMES are frozen — tests assert against them directly —
# but all controller code goes through the accessors below.

# stop_context_init — resets all shared state. Must run once at the top of
# every stop_run before any plugin/gate executes. Side effects: state only.
stop_context_init() {
    _stop_message_sections=""
    _stop_next_turn_stop_requested=false
    _stop_next_turn_continue_requested=false
}

# stop_context_request_stop — records that this turn wants next_turn=stop.
# Idempotent; never fails. Writers: plugins.sh, stall.sh.
stop_context_request_stop() {
    _stop_next_turn_stop_requested=true
}

# stop_messagebag_request_continue — records that this turn wants
# next_turn=continue. Idempotent; never fails. Writer: plugins.sh.
# (Name kept for compatibility — it is a next-turn request, peer of
# stop_context_request_stop, not a messagebag operation.)
stop_messagebag_request_continue() {
    _stop_next_turn_continue_requested=true
}

# stop_context_stop_requested — returns 0 iff next_turn=stop was requested.
# Read-only; no side effects.
stop_context_stop_requested() {
    [[ "${_stop_next_turn_stop_requested:-false}" == "true" ]]
}

# stop_context_continue_requested — returns 0 iff next_turn=continue was
# requested. Read-only; no side effects.
stop_context_continue_requested() {
    [[ "${_stop_next_turn_continue_requested:-false}" == "true" ]]
}

# stop_messagebag_add_section <text> — appends a briefing section verbatim.
# Empty input is a no-op. Never fails.
stop_messagebag_add_section() {
    local section="$1"
    [[ -n "$section" ]] || return 0
    _stop_message_sections+="$section"
}

# stop_messagebag_render_sections — prints accumulated sections followed by a
# newline iff any exist; prints nothing otherwise. Read-only; no side effects.
stop_messagebag_render_sections() {
    [[ -n "${_stop_message_sections:-}" ]] || return 0
    printf '%s\n' "$_stop_message_sections"
}
