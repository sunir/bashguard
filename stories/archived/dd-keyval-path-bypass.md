---
id: DD-KEYVAL-PATH
---
# dd key=value path bypass in credentials.privileged_path

`credentials.privileged_path` checks each command argument with `_is_protected`.
For `dd if=/etc/shadow`, tree-sitter parses `if=/etc/shadow` as a positional
argument. `_is_protected("if=/etc/shadow", ...)` does not match because the
string starts with `if=`, not `/etc/`.

Any command using `key=path` argument syntax (dd, rsync --files-from=, etc.)
can read protected files without triggering the rule.

## Contract

`credentials.privileged_path` must detect protected paths in `key=value` args
where the value is an absolute or home-relative path. For `dd if=/etc/shadow`,
it must extract `/etc/shadow` and check it.

## Fix

Add `_extract_path(arg)` helper that strips `key=` prefix when the value
starts with `/` or `~`. Apply in the `all_paths` loop in CredentialsRule.check.

## Tests

`tests/test_dd_kv_path.py`
- dd if=/etc/shadow → BLOCK credentials.privileged_path
- dd if=~/.ssh/id_rsa → BLOCK
- dd if=/tmp/data.bin → ALLOW (not a protected path)
- dd of=/etc/shadow → BLOCK (write to protected path)
- normal dd if=/dev/zero of=/tmp/x → ALLOW (/dev/zero not protected, /tmp not protected)
