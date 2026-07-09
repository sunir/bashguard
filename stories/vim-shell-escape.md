---
id: VIM-SHELL-ESCAPE
---
# vim/vi shell escape via ex commands

GTFOBins documents vim/vi/view/ex as shell-escape vectors via ex commands:

    vim -c ":!id"           # -c executes ex command; :! runs shell
    vim -c ":shell"         # drops to interactive shell
    vim "+:!id" file.txt    # + prefix is ex command shorthand
    ex "+:!id" file.txt     # ex = vim line editor mode

Opening vim/vi normally is legitimate. The attack is the -c flag or +cmd
prefix that executes :! or :shell inside vim.

## Contract

Rule: `evasion.vim_shell`
Severity: HIGH
Binaries: vim, vi, view, ex, nvim, rvim, rview
Detect:
- `-c` or `--cmd` argument containing `:!` or `:shell`
- `+` prefix argument (the + is stripped, rest is ex cmd) containing `!` or `shell`
Allow: vim/vi without -c/:!/+shell args (legitimate editing)

## Tests

`tests/rules/test_vim_shell.py`
- vim -c ":!id" → BLOCK
- vim -c ":shell" → BLOCK
- vi "+:!id" file.txt → BLOCK
- vim "+!/bin/sh" file.txt → BLOCK
- ex "+:!id" file.txt → BLOCK
- nvim -c ":!id" → BLOCK
- vim file.txt → ALLOW
- vi README.md → ALLOW
- vim -c "set number" → ALLOW (legitimate -c without shell)
