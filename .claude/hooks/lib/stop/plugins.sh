#!/bin/bash
# Stop plugin discovery and execution.

# Story: REAPER-DISPATCHER-INTEGRATION (gates PRD, %170) -- Stop is the
# "most critical, cleanup runs here" dispatcher per gates' own grace-period
# guidance, hence the 10s grace (plugins here may fsync/delete/signal on
# their way out). Computed once at source time (common.sh's reaper_cmd_for
# is defined before this file is sourced -- see Stop's own _source order),
# not per-plugin; every stop_collect_plugin call reuses the same REAPER_CMD.
# Guarded: several unit tests source controller.sh (and therefore this
# file) standalone, without common.sh -- reaper_cmd_for undefined there
# must be a silent no-op (REAPER_CMD stays empty/unset, same as fail-open),
# not a hard error.
declare -F reaper_cmd_for >/dev/null 2>&1 && reaper_cmd_for 10000

# stop_plugin_message_is_repeat <plugin_name> <output> — true iff this is a
# harness re-fire (INPUT.stop_hook_active == "true") AND this plugin's raw
# stdout is byte-identical to what it emitted on the immediately preceding
# Stop cycle.
#
# Story: STOP-CONTROLLER-DEDUP
#
# Centralizes the "don't repeat the identical block on every harness re-fire"
# contract for ordinary Stop.d plugins, in the ONE place they already funnel
# through (stop_collect_plugin, below) — not as bespoke per-plugin logic.
# `99-automode` is deliberately exempt: Automode owns a semantic three-stage
# repeat policy (calm message, direct order, then wait/once completion).
# Dispatcher-level byte dedup cannot distinguish a wait wakeup from the next
# gauntlet result with identical text; suppressing that result discards its
# `continue` decision and silently lets the agent stop.
#
# A plugin's stored signature is a hash of its RAW stdout — content-based,
# not next_turn-based — so a plugin whose message text changes (even with
# the same next_turn) is correctly treated as new, not a repeat.
#
# Fail-open: any error (no shasum, unwritable state dir) → not a repeat,
# the message always gets through. A missed suppression is a minor
# annoyance (one extra repeated block); a wrongly-suppressed GENUINE
# first-time block would hide real information from the agent — the two
# failure directions are not symmetric, so this defaults to the safer one.
stop_plugin_message_is_repeat() {
    local plugin_name="$1" output="$2"
    if ! command -v shasum >/dev/null 2>&1; then
        # Degraded, and it must say so: without shasum this returns "not a
        # repeat" forever, so suppression is permanently off while looking
        # exactly like "nothing was ever a duplicate".
        printf 'dispatcher plugin=%s dedup-degraded reason=no-shasum\n' \
            "$plugin_name" >> "${_stop_log:-/dev/null}" 2>/dev/null
        return 1
    fi

    local sig_dir="${REPO_ROOT:-.}/.automode/stop-plugin-sig"
    local sig_file="$sig_dir/$plugin_name"

    local sha
    sha="$(printf '%s' "$output" | shasum -a 256 2>/dev/null | cut -c1-16)"
    [[ -n "$sha" ]] || return 1

    local sig_prev=""
    [[ -f "$sig_file" ]] && sig_prev="$(cat "$sig_file" 2>/dev/null)"

    local is_active
    is_active="$(printf '%s' "${INPUT:-}" | jq -r '.stop_hook_active // false' 2>/dev/null)"

    if ! mkdir -p "$sig_dir" 2>/dev/null; then
        printf 'dispatcher plugin=%s dedup-degraded reason=mkdir-failed dir=%s\n' \
            "$plugin_name" "$sig_dir" >> "${_stop_log:-/dev/null}" 2>/dev/null
    elif ! printf '%s' "$sha" > "$sig_file" 2>/dev/null; then
        printf 'dispatcher plugin=%s dedup-degraded reason=write-failed file=%s\n' \
            "$plugin_name" "$sig_file" >> "${_stop_log:-/dev/null}" 2>/dev/null
    fi

    [[ "$is_active" == "true" && "$sha" == "$sig_prev" ]]
}

stop_collect_plugin() {
    local plugin="$1"

    export PLUGIN_NAME="$(basename "$plugin")"

    local _tmpstderr exit_code=0 stdout_out=""
    _tmpstderr="$(mktemp)"
    printf 'dispatcher plugin=%s start\n' "$PLUGIN_NAME" >> "$_stop_log" 2>/dev/null
    stdout_out="$(echo "${INPUT:-}" | (cd "${REPO_ROOT:-.}"; "${REAPER_CMD[@]+"${REAPER_CMD[@]}"}" "$plugin") 2>"$_tmpstderr")" || exit_code=$?
    local stderr_out
    stderr_out="$(cat "$_tmpstderr" 2>/dev/null)"
    rm -f "$_tmpstderr"
    printf 'dispatcher plugin=%s exit=%s stdout_len=%s stderr_len=%s\n' \
        "$PLUGIN_NAME" "$exit_code" "${#stdout_out}" "${#stderr_out}" \
        >> "$_stop_log" 2>/dev/null

    [[ -n "$stderr_out" ]] && printf '  stderr[%s]: %s\n' \
        "$PLUGIN_NAME" "$(printf '%s' "$stderr_out" | head -3 | tr '\n' '|')" \
        >> "$_stop_log" 2>/dev/null

    # Story: REAPER-DISPATCHER-INTEGRATION -- reaper's own contract: 143
    # (128+SIGTERM) means REAPER cancelled the plugin because the harness
    # killed the dispatcher's launcher, not that the plugin itself failed.
    # Must not be logged as a plugin error.
    [[ $exit_code -ne 0 ]] && [[ $exit_code -ne 2 ]] && [[ $exit_code -ne 143 ]] && \
        log_hook_error "Stop" "$PLUGIN_NAME" "$exit_code" "${stderr_out:-$stdout_out}"

    if [[ -n "$stdout_out" ]] && \
       printf '%s' "$stdout_out" | jq -e 'has("next_turn")' >/dev/null 2>&1; then
        local next_turn message_sections
        next_turn="$(printf '%s' "$stdout_out" | jq -r '.next_turn // ""' 2>/dev/null)"
        case "$next_turn" in
            stop|continue|wait) ;;
            *)
                printf '  stdout[%s] (ignored, invalid next_turn=%s): %s\n' \
                    "$PLUGIN_NAME" "$next_turn" "$(printf '%s' "$stdout_out" | head -1)" \
                    >> "$_stop_log" 2>/dev/null
                return
                ;;
        esac

        # Story: STOP-CONTROLLER-DEDUP — centralized repeat-suppression for
        # ordinary plugins. Automode is its own cycle controller and must
        # retain both its message and blocking decision on every response.
        if [[ "$PLUGIN_NAME" != "99-automode" && "$next_turn" != "wait" ]] && \
           stop_plugin_message_is_repeat "$PLUGIN_NAME" "$stdout_out"; then
            printf 'dispatcher plugin=%s suppressed=repeat-on-refire\n' "$PLUGIN_NAME" >> "$_stop_log" 2>/dev/null
            return
        fi

        message_sections="$(printf '%s' "$stdout_out" | jq -r '
            (.messages // [])
            | .[]
            | if type == "string" then .
              else
                [
                  (if ((.title // "") != "") then "---- " + .title else empty end),
                  (.body // .text // .message // empty),
                  (if ((.actions // []) | length) > 0 then
                    "NEXT ACTIONS",
                    ((.actions // [])[] | "* " + .)
                  else empty end)
                ]
                | map(select(. != ""))
                | join("\n")
              end
        ' 2>/dev/null)"
        if [[ -n "$message_sections" ]]; then
            stop_messagebag_add_section $'\n'"$message_sections"
        else
            printf 'dispatcher plugin=%s empty-messages next_turn=%s\n' \
                "$PLUGIN_NAME" "$next_turn" >> "$_stop_log" 2>/dev/null
        fi

        case "$next_turn" in
            stop) stop_context_request_stop ;;
            continue) stop_messagebag_request_continue ;;
            wait) ;;
        esac
        return
    fi

    if [[ -n "$stdout_out" ]]; then
        printf '  stdout[%s] (ignored, missing next_turn JSON): %s\n' \
            "$PLUGIN_NAME" "$(printf '%s' "$stdout_out" | head -1)" >> "$_stop_log" 2>/dev/null
    fi
}

stop_discover_plugins() {
    local plugin
    local old_nullglob
    old_nullglob="$(shopt -p nullglob || true)"
    shopt -s nullglob

    for plugin in "$HOOK_DIR/system"/* "$HOOK_DIR/plugin"/* "$HOOK_DIR/local"/*; do
        [[ -f "$plugin" ]] || continue
        [[ "$(basename "$plugin")" == .* ]] && continue
        [[ "$plugin" == *.md ]] && continue
        [[ -x "$plugin" ]] || continue
        printf '%s\n' "$plugin"
    done

    eval "$old_nullglob" 2>/dev/null || true
}

stop_collect_plugins() {
    local plugin
    while IFS= read -r plugin; do
        [[ -n "$plugin" ]] || continue
        stop_collect_plugin "$plugin"
        # Story: STOP-CONTROLLER-REBALANCE — context read via accessor.
        if stop_context_stop_requested; then
            printf 'dispatcher stop requested plugin=%s short_circuit=true\n' \
                "$(basename "$plugin")" >> "$_stop_log" 2>/dev/null
            break
        fi
    done < <(stop_discover_plugins)
}
