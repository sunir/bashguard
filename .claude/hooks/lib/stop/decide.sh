#!/bin/bash
# Stop deciders.

# stop_decide_after_plugins — maps the collected context state to the turn
# decision. Prints exactly one of: stop | continue | wait. Precedence:
# stop > continue > wait. Read-only; no side effects.
# Story: STOP-CONTROLLER-REBALANCE — reads context via accessors, not globals.
stop_decide_after_plugins() {
    if stop_context_stop_requested; then
        printf 'stop\n'
    elif stop_context_continue_requested; then
        printf 'continue\n'
    else
        printf 'wait\n'
    fi
}
