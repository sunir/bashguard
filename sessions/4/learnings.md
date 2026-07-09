# Session 4 Learnings — 2026-07-09

## Technical learnings

1. **Parser probing is mandatory before writing a rule.** Run `parse()` on representative inputs and print `cmd.name`, `cmd.args`, `cmd.flags`, `cmd.raw` before writing any detection logic. The data shape is always slightly surprising (quoted strings stay quoted in args, flag values appear as args[0], etc.).

2. **`-c 'cmd'` pattern in bashguard:** When `-c` is in `flags`, the ex-command is `args[0]` (with quotes intact). Strip `"'\""` before matching. Same for `--cmd`.

3. **`+cmd` vim pattern:** Appears as a positional arg with the `+` prefix intact (e.g. `args=["+shell", "file.txt"]`). Match with `_RE_PLUS_CMD = re.compile(r"^\+(.+)$")` then check the body.

4. **`+N` line-number exclusion:** `vim +42 file.txt` is legitimate. Exclude with `_RE_LINE_NUMBER = re.compile(r"^\d+$")` before checking for shell escape.

5. **Rule registration:** New rule modules must be added to `_load_builtin_rules()` in `bashguard/rules/__init__.py`. The `@register` decorator alone isn't enough — the module must be imported.

## Heuristics wiki candidates

- **Rule authoring checklist:** (1) probe parser on real inputs, (2) write red tests, (3) implement, (4) register in `__init__.py`
- **Quoted args:** bashguard's parser preserves shell quoting in args — always strip `'\"` before matching content
