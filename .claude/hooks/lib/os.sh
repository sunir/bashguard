#!/bin/sh
# os.sh — cross-platform OS abstraction for colony scripts
# STORY: CROSS-PLATFORM-OS, STORY-OS-ABSTRACTION
#
# Source this file: . "${TOOL_REPO_ROOT}/.claude/hooks/lib/os.sh"
# (TOOL_REPO_ROOT is always set by the deploy-generated wrapper in ~/bin/)
#
# MERGE NOTE (2026-07-08): lisbeth (via gates) independently rewrote this file
# around a raw $_OS_TYPE variable and dropped several functions ocean's
# version had, unaware they were depended on colony-wide (os_mtime alone is
# used by colony-events, colony-invariants, statusline.sh,
# automode-liveness-monitor, and session-guard.sh). This reconciles both:
# lisbeth's simpler, macOS-verified implementations win where they overlap
# (os_timeout, os_ncpu, os_mem_avail_pct, os_pids_by_cwd), and everything
# ocean depended on that lisbeth's version omitted is restored, rewired onto
# the same $_OS_TYPE convention rather than kept as a separate idiom.
#
# Provides:
#   os_kind               — 'macos' | 'linux'
#   os_ncpu                — number of logical CPUs
#   os_mem_avail_pct       — free/available memory as integer 0-100
#   os_load_avg            — 1-minute load average (decimal string)
#   os_mtime FILE           — mtime as unix epoch (integer); non-zero exit if gone
#   os_stat_size FILE       — size in bytes
#   os_current_user         — real effective username (never $USER)
#   os_process_rss_mb N     — RSS of process PID N in megabytes (integer)
#   os_timeout N cmd ...    — run cmd bounded to N seconds; exit 124 on timeout
#   os_pids_by_cwd DIR      — list PIDs whose cwd is DIR (one per line)
#   os_sed_inplace EXPR F...  — in-place sed edit (macOS needs empty backup suffix)
#   os_epoch_to_date EPOCH [FMT] — human date (UTC) from a unix epoch

# Guard against double-sourcing
[ "${_OS_SH_LOADED:-0}" = "1" ] && return 0
_OS_SH_LOADED=1

_OS_TYPE="$(uname -s 2>/dev/null)"

# os_kind — 'macos' | 'linux'. Kept for callers that predate the $_OS_TYPE
# convention (os_mtime, os_stat_size, os_sed_inplace, os_epoch_to_date).
os_kind() {
    case "$_OS_TYPE" in
        Darwin) echo macos ;;
        *)      echo linux ;;
    esac
}

os_ncpu() {
    case "$_OS_TYPE" in
        Darwin) sysctl -n hw.logicalcpu 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1 ;;
        *)      nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1 ;;
    esac
}

os_mem_avail_pct() {
    case "$_OS_TYPE" in
        Darwin)
            # memory_pressure: "System-wide memory free percentage: 42%"
            memory_pressure 2>/dev/null \
                | grep -oE 'free percentage: *[0-9]+' \
                | grep -oE '[0-9]+$' \
                || echo 0
            ;;
        *)
            # /proc/meminfo: MemAvailable / MemTotal * 100
            awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{
                if(t>0) printf "%d\n", a*100/t; else print 0
            }' /proc/meminfo 2>/dev/null || echo 0
            ;;
    esac
}

os_load_avg() {
    case "$_OS_TYPE" in
        Darwin)
            # sysctl -n vm.loadavg returns "{ 0.42 1.23 1.56 }"
            sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}' || echo 0
            ;;
        *)
            # /proc/loadavg: "0.42 1.23 1.56 2/312 12345"
            awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0
            ;;
    esac
}

# os_mtime <file> — mtime as a unix epoch (integer). Non-zero exit if the file is gone.
os_mtime() {
    [ -e "$1" ] || return 1
    if [ "$(os_kind)" = macos ]; then stat -f '%m' "$1" 2>/dev/null
    else stat -c '%Y' "$1" 2>/dev/null; fi
}

# os_stat_size <file> — size in bytes.
os_stat_size() {
    [ -e "$1" ] || return 1
    if [ "$(os_kind)" = macos ]; then stat -f '%z' "$1" 2>/dev/null
    else stat -c '%s' "$1" 2>/dev/null; fi
}

# os_current_user — the REAL effective username. NEVER $USER (empty under tmux/cron,
# which took the sudo branch and downed the colony). id -un asks the kernel.
os_current_user() { id -un 2>/dev/null; }

# os_process_rss_mb PID — RSS in megabytes (integer), 0 if process not found
os_process_rss_mb() {
    local pid="${1:-}"
    [ -z "$pid" ] && { echo 0; return; }
    # ps -o rss= gives kilobytes on both macOS and Linux
    local rss_kb
    rss_kb=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{print $1+0}')
    [ -z "$rss_kb" ] && { echo 0; return; }
    echo $(( rss_kb / 1024 ))
}

# os_timeout N cmd [args...] — run cmd bounded to N seconds
# Exit 124 on timeout, else the child's own exit code.
# Prefers system timeout/gtimeout; falls back to a fork+kill implementation
# when neither is on PATH (GNU coreutils' timeout is not part of stock macOS/BSD).
# BUG-038: duplicated in gates/bin/catch+finally+automode-message as _gates_timeout;
# STORY-OS-ABSTRACTION: this is the canonical shared version.
os_timeout() {
    local _ot_secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$_ot_secs" "$@"; return $?
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$_ot_secs" "$@"; return $?
    fi
    local _ot_sentinel _ot_out _ot_err
    _ot_sentinel=$(mktemp "${TMPDIR:-/tmp}/os-timeout.XXXXXX")
    _ot_out=$(mktemp "${TMPDIR:-/tmp}/os-timeout-out.XXXXXX")
    _ot_err=$(mktemp "${TMPDIR:-/tmp}/os-timeout-err.XXXXXX")
    # Redirect child output to files (not pipes) so an orphaned grandchild
    # cannot hold the pipe open and block a caller's $(...) substitution.
    ( "$@" >"$_ot_out" 2>"$_ot_err"; echo $? >"$_ot_sentinel" ) &
    local _ot_cmd_pid=$!
    ( sleep "$_ot_secs"; kill -TERM "$_ot_cmd_pid" 2>/dev/null ) >/dev/null 2>&1 &
    local _ot_watcher=$!
    wait "$_ot_cmd_pid" 2>/dev/null
    kill "$_ot_watcher" 2>/dev/null
    wait "$_ot_watcher" 2>/dev/null
    cat "$_ot_out"
    cat "$_ot_err" >&2
    local _ot_rc=124
    [ -s "$_ot_sentinel" ] && _ot_rc=$(cat "$_ot_sentinel")
    rm -f "$_ot_sentinel" "$_ot_out" "$_ot_err"
    return "$_ot_rc"
}

# os_pids_by_cwd DIR — list PIDs whose current working directory is DIR (one per line)
# Used by the colony monitor to find which agent process owns a given repo directory.
# Validated on ocean (Linux) 2026-07-08 — was flagged pending in the lisbeth commit.
os_pids_by_cwd() {
    local dir="${1:-}"
    [ -z "$dir" ] && return
    case "$_OS_TYPE" in
        Darwin)
            # lsof -F fn: output pid ('p') and name ('n') fields only
            # -d cwd: restrict to file descriptor named 'cwd'
            lsof -F fn -d cwd 2>/dev/null | awk -v dir="$dir" '
                /^p/ { pid=substr($0,2) }
                /^n/ { if (substr($0,2) == dir) print pid }
            ' ;;
        *)
            # /proc/PID/cwd is a symlink to the process's cwd on Linux
            local f pid target
            for f in /proc/*/cwd; do
                pid=$(printf '%s' "$f" | grep -o '[0-9]*')
                [ -z "$pid" ] && continue
                target=$(readlink "$f" 2>/dev/null)
                [ "$target" = "$dir" ] && printf '%s\n' "$pid"
            done ;;
    esac
}

# os_sed_inplace <sed-expr> <file...> — in-place edit. macOS sed needs an empty backup
# suffix arg; GNU/Linux sed rejects it.
os_sed_inplace() {
    local expr="$1"; shift
    if [ "$(os_kind)" = macos ]; then sed -i '' -e "$expr" "$@"
    else sed -i -e "$expr" "$@"; fi
}

# os_epoch_to_date <epoch> [date-fmt] — human date (UTC) from a unix epoch.
os_epoch_to_date() {
    local e="$1" fmt="${2:-+%Y-%m-%dT%H:%M:%SZ}"
    if [ "$(os_kind)" = macos ]; then date -r "$e" -u "$fmt" 2>/dev/null
    else date -d "@$e" -u "$fmt" 2>/dev/null; fi
}
