#!/bin/bash
# Model info: context window size from model ID or display name
# Story: CONTEXT-ENGINE-PLUGIN
#
# Usage: get_model_info <model_string>
# Prints two space-separated values: <context_tokens> <display_name>
# Fail-open: unknown models return 200000 Unknown

get_model_info() {
    local model
    model="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    if   [[ "$model" == *opus* ]];   then printf '1000000 Opus\n'
    elif [[ "$model" == *fable* ]];  then printf '1000000 Fable\n'
    elif [[ "$model" == *codex* ]];  then printf '1000000 Codex\n'
    elif [[ "$model" == *sonnet*5* ]]; then printf '976000 Sonnet5\n'
    elif [[ "$model" == *sonnet* ]]; then printf '200000 Sonnet\n'
    elif [[ "$model" == *haiku* ]];  then printf '200000 Haiku\n'
    else                                  printf '200000 Unknown\n'
    fi
}
