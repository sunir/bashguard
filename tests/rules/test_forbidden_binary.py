"""Tests for exec.forbidden_binary rule.

Rule contracts (exec.forbidden_binary):
- msfconsole                              → BLOCK (Metasploit framework)
- sqlmap -u http://...                    → BLOCK (SQL injection tool)
- volatility -f mem.dmp ...               → BLOCK (memory forensics)
- hashcat -m 0 hashes.txt wordlist.txt   → BLOCK (password cracker)
- aircrack-ng capture.cap                → BLOCK (WiFi cracker)
- zathura document.pdf                   → BLOCK (GUI PDF viewer)
- gimp image.png                         → BLOCK (GUI image editor)
- wireshark                              → BLOCK (GUI packet analyzer)
- crash vmlinux                          → BLOCK (kernel debugger)
- debugfs /dev/sda1                      → BLOCK (filesystem debugger)
- jjs                                    → BLOCK (removed Nashorn JS shell)
- rtorrent                               → BLOCK (BitTorrent client)
- python3 script.py                      → ALLOW (legitimate interpreter)
- tshark -i eth0                         → ALLOW (CLI packet capture, legitimate)
- gdb ./binary                           → ALLOW (debugger, legitimate dev use)
- vim file.txt                           → ALLOW (editor, legitimate)
"""
from __future__ import annotations
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from bashguard.models import ExecutionContext, Severity


@pytest.fixture()
def ctx():
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.forbidden_binary import ForbiddenBinaryRule
    return ForbiddenBinaryRule()


class TestOffensiveTools:
    def test_msfconsole_blocked(self, ctx):
        findings = _rule().check("msfconsole", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "exec.forbidden_binary"
        assert findings[0].severity == Severity.HIGH
        assert "offensive tool" in findings[0].message

    def test_sqlmap_blocked(self, ctx):
        findings = _rule().check("sqlmap -u http://target.com/page?id=1", ctx)
        assert len(findings) == 1
        assert "offensive tool" in findings[0].message

    def test_volatility_blocked(self, ctx):
        findings = _rule().check("volatility -f memory.dmp imageinfo", ctx)
        assert len(findings) == 1

    def test_hashcat_blocked(self, ctx):
        findings = _rule().check("hashcat -m 0 hashes.txt wordlist.txt", ctx)
        assert len(findings) == 1

    def test_aircrack_blocked(self, ctx):
        findings = _rule().check("aircrack-ng -b 00:11:22:33:44:55 capture.cap", ctx)
        assert len(findings) == 1

    def test_hydra_blocked(self, ctx):
        findings = _rule().check("hydra -l admin -P passlist.txt ssh://target", ctx)
        assert len(findings) == 1

    def test_responder_blocked(self, ctx):
        findings = _rule().check("responder -I eth0 -rdwv", ctx)
        assert len(findings) == 1


class TestGuiApplications:
    def test_zathura_blocked(self, ctx):
        findings = _rule().check("zathura report.pdf", ctx)
        assert len(findings) == 1
        assert "GUI application" in findings[0].message

    def test_gimp_blocked(self, ctx):
        findings = _rule().check("gimp image.png", ctx)
        assert len(findings) == 1
        assert "GUI application" in findings[0].message

    def test_wireshark_blocked(self, ctx):
        findings = _rule().check("wireshark", ctx)
        assert len(findings) == 1

    def test_xdotool_blocked(self, ctx):
        findings = _rule().check("xdotool type 'hello'", ctx)
        assert len(findings) == 1


class TestLegacyExotic:
    def test_debugfs_blocked(self, ctx):
        findings = _rule().check("debugfs /dev/sda1", ctx)
        assert len(findings) == 1
        assert "legacy" in findings[0].message

    def test_jjs_blocked(self, ctx):
        findings = _rule().check("jjs", ctx)
        assert len(findings) == 1

    def test_rtorrent_blocked(self, ctx):
        findings = _rule().check("rtorrent", ctx)
        assert len(findings) == 1

    def test_crash_blocked(self, ctx):
        findings = _rule().check("crash vmlinux /proc/kcore", ctx)
        assert len(findings) == 1

    def test_jrunscript_blocked(self, ctx):
        findings = _rule().check("jrunscript -e 'java.lang.Runtime.getRuntime().exec(\"/bin/sh\")'", ctx)
        assert len(findings) == 1


class TestAllowed:
    def test_python_allowed(self, ctx):
        assert _rule().check("python3 script.py", ctx) == []

    def test_gdb_allowed(self, ctx):
        assert _rule().check("gdb ./binary", ctx) == []

    def test_vim_allowed(self, ctx):
        assert _rule().check("vim file.txt", ctx) == []

    def test_tshark_allowed(self, ctx):
        assert _rule().check("tshark -i eth0 -c 100", ctx) == []

    def test_git_allowed(self, ctx):
        assert _rule().check("git status", ctx) == []

    def test_nmap_allowed(self, ctx):
        # nmap has its own port_scan rule — not duplicated here
        assert _rule().check("nmap -sV localhost", ctx) == []
