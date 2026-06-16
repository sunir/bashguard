---
id: FIX-DATA-GRAMMAR
---
# Fix data-grammar Flags validation for CLI flags

data-grammar validates that `--xxx` literals must be in `Flags` subtypes,
not in data `Document` rules. `StatsQuery` and `LogQuery` use `--json`,
`--days`, `--verdict`, `--rule`, `--limit` as flag-style tokens in data rules,
which now fails validation.

## Fix

1. Move all `--xxx` flag alternatives from `StatsQuery` and `LogQuery` into a
   `Flags < stdlib.Flags` rule in `grammar.bnf`.
2. Update `@end = Flags @output` so the Flags rule is processed before output.
3. Implement `Flags` Python class with methods: `set_days`, `use_json`,
   `filter_verdict`, `filter_rule`, `set_limit` — each writes to `self.flags`.
4. Update `StatsQuery.__init__(flags=None)` and `LogQuery.__init__(flags=None)`
   to store `self.flags = flags` (receives `interpreter.flags` dict via
   `gather_kwargs`).
5. Update `__str__` methods to read from `self.flags` instead of `self._*`.

## Story tag

BG-CLI-FLAGS-VALIDATION
