#!/bin/bash
# Shared transport for automode.d posters.
# Story: POSTER-LIB (%POSTER-LIB)
#
# A poster answers one domain question -- "is there something worth waking for,
# and what should it say?" -- and this file does everything else: find
# gates `signal`, build valid JSON, write the fact, and run the --once/--watch
# loop.
#
# WHY SHARED AT ALL, given PRINCIPLES #8 says the domain owns its own behaviour.
# Because the transport is not behaviour. Every watcher carried an identical
# copy of the scaffold around a single different question, and the copies had
# already drifted: each grew its own suppression file, its own signature
# hashing, its own pre-check ordering, and each had to be fixed separately when
# the wakeup semantics changed. #8 says a domain owns its own CHECK; it does not
# say a domain owns its own plumbing. Three private copies of the plumbing is
# three places for it to rot, which is the shape the suppression files became.
#
# USAGE, from a poster:
#
#     . "$(dirname "${BASH_SOURCE[0]}")/../lib/post.sh"
#     automode_poster_message() { ...; printf '%s' "$msg"; }   # empty = nothing to say
#     automode_post_main "$1" todo_available .todo.json
#
# The poster never mentions the signal transport, JSON, or the loop.

set -uo pipefail

AUTOMODE_STATE_FILE="${AUTOMODE_STATE_FILE:-.automode/state.json}"

# Locate the signal writer. It is nine lines of sh precisely so that a notifier
# does not need a library to link against -- but it does need to be FOUND, and a
# poster that silently cannot post is the quiet failure gates warned about.
_automode_signal_cmd() {
    # Post a durable signal via gates' consolidated `signal` transport, which
    # automode consumes with `signal wait`. (The earlier design
    # called `hfsm-signal`, which was never built, so every post 127'd; a first
    # rewrite used the wrong spool/name — automode corrected it, %145.)
    #
    # Consolidated signal contract (authoritative: automode bin/automode
    # configure_wait_boundary): `signal raise <spool-dir> <name> <json>`;
    # `signal wait <spool-dir> <name>` claims the BARE name (no extension).
    #   spool = $AUTOMODE_SIGNAL_SPOOL, else <state-dir>/signals/<SESSION_ID>
    #           (parent dir of the state file + /signals/<session>; default
    #            session "repo" — matches bin/automode exactly).
    #   name  = bare <name> (todo_available, NOT todo_available.signal).
    #   binary = $AUTOMODE_SIGNAL (bin/automode sets it), else PATH, else
    #            $HOME/prod/gates/bin/signal.
    # `signal raise` sets {"signal":"<name>",…}, so no payload
    # folding is needed. Returns 127 (fail-loud upstream, but silenced there for
    # 127) if the consolidated signal tool is genuinely absent.
    local state_file="$1" name="$2" payload="${3:-null}" spool signal_cmd
    spool="${AUTOMODE_SIGNAL_SPOOL:-$(dirname "$state_file")/signals/${SESSION_ID:-repo}}"
    if [ -n "${AUTOMODE_SIGNAL:-}" ] && [ -x "$AUTOMODE_SIGNAL" ]; then
        signal_cmd="$AUTOMODE_SIGNAL"
    elif command -v signal >/dev/null 2>&1; then
        signal_cmd="signal"
    elif [ -x "$HOME/prod/gates/bin/signal" ]; then
        signal_cmd="$HOME/prod/gates/bin/signal"
    else
        return 127
    fi
    "$signal_cmd" raise "$spool" "$name" "$payload"
}

# Build a JSON object carrying the message. jq when present; a conservative
# hand-escape otherwise, because a malformed payload makes the WAITER fail on a
# message rather than on something it can see.
_automode_payload() {
    local message="$1"
    if command -v jq >/dev/null 2>&1; then
        jq -nc --arg m "$message" '{message: $m}'
    else
        printf '{"message":"%s"}' \
            "$(printf '%s' "$message" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r\t')"
    fi
}

# Post the signal iff the poster's own question says there is something to say.
#
# THE TRANSPORT MUST NOT LIE. system's review (msg 171) caught the first version
# swallowing every failure -- missing binary, unwritable spool, malformed payload
# -- behind `|| return 0`. A poster that decided there IS something worth waking
# for, and then could not say so, reported that it did. The comment twelve lines
# above warned about exactly that and the code below it did it anyway. If a
# caller must survive a failed post, the CALLER decides that; the transport
# reports what happened.
#
# DUAL-EMIT, deliberately temporary. The shipped bin/automode has no durable-
# signal consumption yet: it reads merge-stdout's fifo, and bin/automode:1044
# extracts WHICH watcher fired from the [label] prefix on the emitted line, which
# is what selects the matching automode.message.d plugin. Posting only a signal
# would mean msg and todo write into a spool nobody reads, emit no line, and
# automode never wakes for mail or todos -- silently, colony-wide, looking like
# msg or todo broke rather than like a transport swap. So we do both until the
# waiter lands, and then delete exactly one line. Reversible by construction.
automode_post_once() {
    local signal_name="$1" message ec=0
    message="$(automode_poster_message)" || return 0
    [ -n "$message" ] || return 0

    _automode_signal_cmd "$AUTOMODE_STATE_FILE" "$signal_name" \
        "$(_automode_payload "$message")" >/dev/null 2>&1 || ec=$?
    # ec=127 means the durable transport (gates signal) is ABSENT, not that
    # it ran and failed. On the current HFSM architecture the waiter polls the
    # gauntlet independently and the stdout dual-emit below still carries the
    # old merge-stdout wakeup, so NO wakeup is lost when the transport is simply
    # not deployed — alarming there is a false positive (automode confirmed, %141).
    # Fail loud ONLY on a REAL transport failure: signal present but errored.
    if [ "$ec" -ne 0 ] && [ "$ec" -ne 127 ]; then
        printf 'automode.d/post: FAILED to post signal %s (exit %s) -- the wakeup was decided and not delivered\n' \
            "$signal_name" "$ec" >&2
    fi

    # DELETE THIS LINE when the hfsm waiter is live. Nothing else here is
    # transitional.
    printf '%s\n' "$message"

    return "$ec"
}

# automode_post_main <mode> <signal-name> [watch-path]
#
# --once (default) is the primitive: it never blocks, so it can be run on any
# cadence -- per Stop cycle, from a scheduler, or by hand -- because posting
# twice is one fact. The spool is keyed by signal NAME, so a re-post overwrites.
#
# --watch is the same call in a loop on a filesystem change. There is no
# catch-up-then-watch distinction any more: a signal posted before anyone waits
# is the ordinary case, so both phases are just "say what is true".
automode_post_main() {
    local mode="${1:---once}" signal_name="$2" watch_path="${3:-.}"
    case "$mode" in
        --watch)
            while true; do
                automode_post_once "$signal_name"
                files-changed "$watch_path" >/dev/null 2>&1 || exit 0
            done
            ;;
        *)
            automode_post_once "$signal_name"
            return $?
            ;;
    esac
}

# NOTE, and it is the same bug twice: this function used to end in `return 0`,
# which discarded exactly the status automode_post_once had just been fixed to
# report. system's review caught the inner `|| return 0`; I fixed that and left
# the outer one, so the transport went on lying from one line further up, and
# only the failure-path test they asked for found it. Same family as
# PRINCIPLES #11 -- a statement in the return position quietly becomes the
# return value -- and the same lesson as everything else today: the fix for a
# swallowed failure has to be checked against a real failure, not read.
