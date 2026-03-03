"""
Tests for bash_ast.parser — CommandNode extraction from bash scripts.

Story: As a security policy author, I need a parsed representation of bash
commands — name, flags, arguments, and structure — so I can write rules
without string-matching raw shell.

Success:
- Simple command: name + args + flags extracted
- Compound (&&, ||, ;): all commands extracted
- Pipeline (|): all commands extracted
- Subshell / command substitution: inner commands extracted
- Redirect targets (>, >>, <) extracted as paths
- Unknown/unparseable input raises ParseError
"""

import pytest
from bash_ast.parser import parse, CommandNode, ParseError


class TestSimpleCommand:
    def test_command_name(self):
        cmds = parse("git status")
        assert len(cmds) == 1
        assert cmds[0].name == "git"

    def test_args(self):
        cmds = parse("git commit -m 'fix bug'")
        assert cmds[0].name == "git"
        assert "commit" in cmds[0].args

    def test_flags(self):
        cmds = parse("rm -rf /tmp/foo")
        assert cmds[0].name == "rm"
        assert "-rf" in cmds[0].flags

    def test_positional_args(self):
        cmds = parse("cp src/file.py dest/")
        assert "src/file.py" in cmds[0].args
        assert "dest/" in cmds[0].args

    def test_raw_text_preserved(self):
        script = "ls -la /home"
        cmds = parse(script)
        assert cmds[0].raw == "ls -la /home"


class TestCompoundCommands:
    def test_and_list(self):
        cmds = parse("git add . && git commit -m 'msg'")
        names = [c.name for c in cmds]
        assert "git" in names
        assert len(cmds) == 2

    def test_or_list(self):
        cmds = parse("test -f file.txt || touch file.txt")
        assert len(cmds) == 2
        assert cmds[0].name == "test"
        assert cmds[1].name == "touch"

    def test_semicolon_sequence(self):
        cmds = parse("cd /tmp; ls -la")
        assert len(cmds) == 2

    def test_pipeline(self):
        cmds = parse("git log --oneline | grep fix")
        names = [c.name for c in cmds]
        assert "git" in names
        assert "grep" in names


class TestRedirects:
    def test_output_redirect_target(self):
        cmds = parse("echo hello > /tmp/out.txt")
        assert "/tmp/out.txt" in cmds[0].redirect_targets

    def test_append_redirect_target(self):
        cmds = parse("echo hello >> /tmp/log.txt")
        assert "/tmp/log.txt" in cmds[0].redirect_targets

    def test_input_redirect_target(self):
        cmds = parse("cat < /etc/passwd")
        assert "/etc/passwd" in cmds[0].redirect_targets


class TestCommandSubstitution:
    def test_backtick_substitution(self):
        cmds = parse("echo `whoami`")
        names = [c.name for c in cmds]
        assert "whoami" in names

    def test_dollar_substitution(self):
        cmds = parse("rm -rf $(cat /tmp/paths.txt)")
        names = [c.name for c in cmds]
        assert "rm" in names
        assert "cat" in names


class TestParseError:
    def test_empty_input(self):
        cmds = parse("")
        assert cmds == []

    def test_whitespace_only(self):
        cmds = parse("   \n  ")
        assert cmds == []
