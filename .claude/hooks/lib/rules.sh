#!/bin/bash
# Rules Library — Composable behavioral rules for Claude sessions
# Story: composable-rules
#
# PURPOSE: Compose behavioral rules from rules/*.md files.
#   rules/00-critical-rule.md              — family base rule (auto-provided by system)
#   rules/99-plan.md                       — session plan/ralph prompt (written by Claude)
#   rules/Stop/system/05-hooks.md          — hook infrastructure rules (Stop lifecycle)
#   rules/Stop/system/06-focusmode.md      — focusmode rules (Stop lifecycle)
#   rules/SessionStart/system/01-fajr.md   — startup discipline (SessionStart lifecycle)
#   rules/UserPromptSubmit/system/10-todo.md  — todo workflow (UserPromptSubmit lifecycle)
#
# LIFECYCLE SCOPING: Rules are organized into subdirs by hook lifecycle,
#   using the same 3-tier pattern as hooks: system/, plugin/, local/.
#   compose_rules "Stop"              → reads rules/Stop/{system,plugin,local}/*.md
#   compose_rules "UserPromptSubmit"  → reads rules/UserPromptSubmit/{system,plugin,local}/*.md
#   compose_rules                     → reads flat rules/*.md (legacy fallback)
#
# TIER ORDER: system/ → plugin/ → local/ (lexicographic within each tier).
#   system/ = synced from system repo (authoritative, never edit locally)
#   plugin/ = installed by colony plugin system
#   local/  = repo-specific overrides
#
# LEGACY FALLBACK: If no tier subdirs exist but rules/$hook/ has direct *.md
#   files, those are read (repos that haven't migrated to subdir layout).
#
# COMPOSABILITY: Files are concatenated in lexicographic order within each tier.
#   Only files matching [0-9]*.md are included (excludes README.md, etc.)
#
# FALLBACK: If rules/ does not exist, falls back to settings/CRITICAL_RULE.md.
#   If neither exists, silently produces no output (fail-open).
#
# USAGE:
#   source "$(dirname "$0")/lib/rules.sh"
#   compose_rules "Stop"        # outputs Stop-lifecycle rules to stdout
#   compose_rules >> /dev/stderr # redirect to stderr for hook use

# OS abstraction layer (os_mtime for the 99-plan.md staleness check below).
# Callers of this lib may run as their own process (not always inheriting
# common.sh's sourcing), so source it here directly; source-once guarded.
# Story: system/stories/os-abstraction-layer.md (STORY-OS-ABSTRACTION).
source "$(dirname "${BASH_SOURCE[0]}")/os.sh" 2>/dev/null || true

compose_rules() {
    local hook="${1:-}"
    local rules_dir="${REPO_ROOT:-$(pwd)}/rules"
    local fallback="${REPO_ROOT:-$(pwd)}/settings/CRITICAL_RULE.md"
    local rule_file tier hook_dir

    if [[ -n "$hook" ]]; then
        hook_dir="$rules_dir/$hook"
        # Lifecycle-scoped: read from tier subdirs (system/, plugin/, local/).
        # Fall back to flat rules/$hook/*.md for repos not yet on subdir layout.
        # Do NOT fall back to flat rules/ root — the flat root mixes all lifecycles
        # together, which causes SessionStart-only rules (e.g. fajr) to bleed
        # into Stop and UserPromptSubmit hooks.
        if [[ -d "$hook_dir" ]]; then
            local _has_tier=0
            for tier in system plugin local; do
                [[ -d "$hook_dir/$tier" ]] && _has_tier=1 && break
            done
            if [[ $_has_tier -eq 1 ]]; then
                # Tier layout: read system/ → plugin/ → local/ in order
                for tier in system plugin local; do
                    [[ -d "$hook_dir/$tier" ]] || continue
                    for rule_file in "$hook_dir/$tier"/[0-9]*.md; do
                        [[ -f "$rule_file" ]] || continue
                        cat "$rule_file"
                    done
                done
            else
                # Legacy flat layout within hook subdir (e.g. rules/Stop/05-hooks.md)
                for rule_file in "$hook_dir"/[0-9]*.md; do
                    [[ -f "$rule_file" ]] || continue
                    cat "$rule_file"
                done
            fi
        fi
        # Append rules/99-plan.md if fresh (< 8 hours). Stale plans are misleading.
        if [[ -f "$rules_dir/99-plan.md" ]]; then
            # STORY-OS-ABSTRACTION: raw `stat -f` does not fail cleanly on Linux (prints a
            # filesystem dump instead of erroring), corrupting this arithmetic —
            # verified as an actual bash "syntax error in expression" on this host.
            _plan_age=$(( $(date +%s) - $(os_mtime "$rules_dir/99-plan.md" 2>/dev/null || echo 0) ))
            [[ $_plan_age -lt 28800 ]] && cat "$rules_dir/99-plan.md"
        fi
    elif [[ -d "$rules_dir" ]]; then
        # Fallback: flat layout (legacy repos or flat rules like 00-critical-rule)
        for rule_file in "$rules_dir"/[0-9]*.md; do
            [[ -f "$rule_file" ]] || continue
            cat "$rule_file"
        done
    elif [[ -f "$fallback" ]]; then
        cat "$fallback"
    fi
    # If neither exists: no output, no error (fail-open)
}
