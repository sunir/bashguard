"""Tests for evasion.vim_shell — vim/vi/ex shell escape via ex commands.

Story: VIM-SHELL-ESCAPE

GTFOBins: vim -c ":!id", vim "+:shell", ex "+:!id", nvim -c ":shell"
All are code execution with no legitimate use in an automated coding context.
"""
from __future__ import annotations

import pytest

from bashguard.auditor import audit
from bashguard.context import make_context


CTX = make_context()


def _findings(script: str):
    return [f for f in audit(script, CTX) if f.rule_id == "evasion.vim_shell"]


# ---------------------------------------------------------------------------
# Should BLOCK — shell escape patterns
# ---------------------------------------------------------------------------


class TestVimShellBlock:
    # Story: VIM-SHELL-ESCAPE

    def test_vim_c_bang_cmd(self):
        """vim -c ":!id" — ex command :! spawns shell"""
        assert _findings("vim -c ':!id'")

    def test_vim_c_shell(self):
        """vim -c ":shell" — ex command :shell drops to interactive shell"""
        assert _findings("vim -c ':shell'")

    def test_vi_plus_bang_cmd(self):
        """vi "+:!id" file — + prefix is ex command shorthand"""
        assert _findings("vi '+:!id' file.txt")

    def test_vim_plus_bang_sh(self):
        """vim "+!/bin/sh" — +! is another ex shorthand for shell"""
        assert _findings("vim '+!/bin/sh' file.txt")

    def test_ex_plus_bang_cmd(self):
        """ex "+:!id" — ex editor mode with shell escape"""
        assert _findings("ex '+:!id' file.txt")

    def test_nvim_c_bang_cmd(self):
        """nvim -c ":!id" — neovim same attack surface"""
        assert _findings("nvim -c ':!id'")

    def test_view_c_shell(self):
        """view -c ":shell" — read-only vim still executes ex commands"""
        assert _findings("view -c ':shell'")

    def test_rvim_c_bang(self):
        """rvim -c ":!id" — restricted vim, shell escape still works"""
        assert _findings("rvim -c ':!id'")

    def test_vim_cmd_flag_shell(self):
        """vim --cmd ":shell" — --cmd is alias for -c"""
        assert _findings("vim --cmd ':shell'")

    def test_vim_plus_shell(self):
        """vim +shell — bare +cmd without colon also runs ex command"""
        assert _findings("vim +shell file.txt")


# ---------------------------------------------------------------------------
# Should ALLOW — legitimate editor usage
# ---------------------------------------------------------------------------


class TestVimShellAllow:
    # Story: VIM-SHELL-ESCAPE

    def test_vim_open_file(self):
        """vim file.txt — plain editor invocation, no shell escape"""
        assert not _findings("vim file.txt")

    def test_vi_readme(self):
        """vi README.md — legitimate editing"""
        assert not _findings("vi README.md")

    def test_vim_c_set_number(self):
        """vim -c "set number" — benign ex command, no shell"""
        assert not _findings("vim -c 'set number'")

    def test_vim_c_syntax_on(self):
        """vim -c "syntax on" — benign ex command"""
        assert not _findings("vim -c 'syntax on'")

    def test_nvim_no_args(self):
        """nvim — open neovim without args"""
        assert not _findings("nvim")

    def test_vim_plus_line_number(self):
        """vim +42 file — +N jumps to line N, not a shell command"""
        assert not _findings("vim +42 file.txt")
