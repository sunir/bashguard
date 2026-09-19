#!/bin/bash
# Stop bootstrap: hook-specific paths and debug logging.

stop_bootstrap_env() {
    HOOK_DIR="${HOOK_DIR:-$SCRIPT_DIR/$HOOK_NAME.d}"
    if [[ ! -d "$HOOK_DIR" ]]; then
        # trace-sweep-stop-lib: caller does `stop_bootstrap_env || exit 0` --
        # a silent return here would skip every guard and plugin unnoticed.
        printf '[Stop] bootstrap failed: HOOK_DIR missing (%s) — allowing stop unconditionally, guard gauntlet and all plugins skipped\n' \
            "$HOOK_DIR" >&2
        return 1
    fi

    _stop_repo_name="$(basename "${REPO_ROOT:-$PWD}")"
    if declare -F _hook_log_dir >/dev/null 2>&1; then
        _stop_log_dir="$(_hook_log_dir /tmp "$_stop_repo_name")"
    else
        _stop_log_dir="/tmp/$_stop_repo_name"
        mkdir -p "$_stop_log_dir" 2>/dev/null || true
    fi

    # Every later _stop_log write is best-effort (>> ... 2>/dev/null) -- this
    # is the last point that can still say so if the dir isn't writable.
    if [[ -z "$_stop_log_dir" || ! -w "$_stop_log_dir" ]]; then
        printf '[Stop] bootstrap: log dir unwritable (%s) — this cycle runs with no Stop.log trace\n' \
            "${_stop_log_dir:-<empty>}" >&2
    fi

    _stop_log="${_stop_log_dir}/Stop.log"
    export HOOK_STOP_LOG_DIR="$_stop_log_dir"

    printf 'dispatcher entered ts=%s stop_hook_active=%s session_id=%s\n' \
        "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        "$(printf '%s' "${INPUT:-}" | jq -r '.stop_hook_active // "null"' 2>/dev/null)" \
        "$(printf '%s' "${INPUT:-}" | jq -r '.session_id // "null"' 2>/dev/null)" \
        >> "$_stop_log" 2>/dev/null
    printf '%s' "${INPUT:-}" > "${_stop_log_dir}/Stop.input" 2>/dev/null
}
