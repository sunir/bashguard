"""
Story: As a security operator, I need the protected_paths rule to flag any
shell redirect that writes to protected system directories, so that LLMs
cannot overwrite system binaries, kernel interfaces, or OS configuration.

This is a port of the intent behind bash_ast.policies.FileWritePolicy
into the bash_audit rules framework.

Success:
- echo foo > /etc/anything → blocked (system config)
- echo foo > /usr/local/bin/evil → blocked (system binaries)
- echo foo > /sys/kernel/sysrq → blocked (kernel interface)
- echo foo > /proc/sys/kernel/panic → blocked (proc fs)
- echo foo > /boot/grub/grub.cfg → blocked (bootloader)
- echo foo > /bin/ls → blocked (system bin)
- echo foo > /dev/sda → blocked (device)
- echo foo > /tmp/out.txt → allowed (safe scratch)
- echo foo > output.txt → allowed (relative path)
- echo foo > /home/user/file → allowed (home dir)
"""

import pytest
from bash_audit.rules.protected_paths import ProtectedPathsRule
from bash_audit.context import make_context
from bash_audit.models import Severity


@pytest.fixture
def rule():
    return ProtectedPathsRule()


@pytest.fixture
def ctx():
    return make_context()


def test_write_to_etc_blocked(rule, ctx):
    findings = rule.check("echo hello > /etc/cron.d/evil", ctx)
    assert len(findings) > 0


def test_write_to_usr_blocked(rule, ctx):
    findings = rule.check("echo foo > /usr/local/bin/evil", ctx)
    assert len(findings) > 0


def test_write_to_sys_blocked(rule, ctx):
    findings = rule.check("echo 1 > /sys/kernel/sysrq", ctx)
    assert len(findings) > 0


def test_write_to_proc_blocked(rule, ctx):
    findings = rule.check("echo 0 > /proc/sys/kernel/panic", ctx)
    assert len(findings) > 0


def test_write_to_boot_blocked(rule, ctx):
    findings = rule.check("echo x > /boot/grub/grub.cfg", ctx)
    assert len(findings) > 0


def test_write_to_bin_blocked(rule, ctx):
    findings = rule.check("echo x > /bin/ls", ctx)
    assert len(findings) > 0


def test_write_to_dev_blocked(rule, ctx):
    findings = rule.check("cat data > /dev/sda", ctx)
    assert len(findings) > 0


def test_write_to_tmp_allowed(rule, ctx):
    findings = rule.check("echo hello > /tmp/out.txt", ctx)
    assert findings == []


def test_write_to_relative_allowed(rule, ctx):
    findings = rule.check("echo hello > output.txt", ctx)
    assert findings == []


def test_write_to_home_allowed(rule, ctx):
    findings = rule.check("echo hello > /home/user/notes.txt", ctx)
    assert findings == []


def test_no_redirect_no_finding(rule, ctx):
    findings = rule.check("echo hello", ctx)
    assert findings == []


def test_read_from_etc_no_finding(rule, ctx):
    # Input redirect reading FROM /etc is caught by credentials rule, not this one
    findings = rule.check("cat < /etc/passwd", ctx)
    assert findings == []  # this rule is write-only


def test_append_redirect_blocked(rule, ctx):
    findings = rule.check("echo x >> /etc/crontab", ctx)
    assert len(findings) > 0


def test_severity_is_high(rule, ctx):
    findings = rule.check("echo x > /usr/local/bin/evil", ctx)
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_rule_never_raises(rule, ctx):
    result = rule.check("\x00\x01", ctx)
    assert isinstance(result, list)
