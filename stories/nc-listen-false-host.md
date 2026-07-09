---
id: NC-LISTEN-FALSE
---
# nc listen mode: port number misidentified as hostname

`network.unknown_host` uses `_extract_nc_host()` which takes the first
positional argument as the hostname. In listen mode (`nc -l PORT`), the
first positional is the PORT number, not a hostname. This causes the
confusing message "accesses unknown host '4444'" for `nc -l 4444`.

The block verdict is correct (listening sockets are suspicious in LLM
context), but the detection mechanism is wrong — a numeric port is not
a hostname, and the message misleads the operator about what was detected.

## Contract

`_extract_nc_host` must return None when nc is in listen mode
(any combined or separate flag containing 'l'). The fallback block
fires with the message "nc used — potential network access" instead.

## Fix

`bashguard/rules/network.py` — `_extract_nc_host`:
- Detect listen mode: any flag in `cmd.flags` that contains the letter 'l'
- Return None in listen mode so the fallback fires instead

## Tests

`tests/rules/test_network_nc_listen.py`
- nc -l 4444 → BLOCK, message must NOT say "unknown host '4444'"
- nc -lvp 4444 → BLOCK, message must NOT say "unknown host '4444'"
- nc host 4444 → BLOCK, message says "unknown host 'host'"
