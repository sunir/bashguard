"""Tests for persistence.boot_entry rule.

Story: Writing to autostart directories and loading launch agents establishes
boot persistence — the malicious program runs automatically on every login
without any additional agent involvement. This is the "plant and wait" pattern
from the 82-incident database.

Rule contracts (persistence.boot_entry):
- cat > ~/.config/autostart/evil.desktop          → BLOCK (Linux GNOME autostart)
- cp evil.desktop ~/.config/autostart/            → BLOCK
- cat > ~/Library/LaunchAgents/com.evil.plist     → BLOCK (macOS user LaunchAgent)
- cp evil.plist /Library/LaunchDaemons/           → BLOCK (macOS system LaunchDaemon)
- cp evil.plist /Library/LaunchAgents/            → BLOCK (macOS system LaunchAgent)
- launchctl load ~/Library/LaunchAgents/com.evil.plist → BLOCK (activate LaunchAgent)
- launchctl bootstrap gui/501 evil.plist          → BLOCK
- cat > ~/.config/systemd/user/evil.service       → BLOCK (systemd user unit)
- defaults write com.apple.loginwindow LoginHook /tmp/evil.sh → BLOCK (macOS login hook)
- launchctl unload plist                          → ALLOW (removal is safe)
- launchctl list                                  → ALLOW (listing)
- cat ~/.config/autostart/existing.desktop        → ALLOW (read-only)
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
    from bashguard.rules.boot_entry import BootEntryRule
    return BootEntryRule()


class TestLinuxAutostart:
    def test_write_desktop_blocked(self, ctx):
        findings = _rule().check("cat > ~/.config/autostart/evil.desktop", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.boot_entry"
        assert findings[0].severity == Severity.HIGH

    def test_cp_to_autostart_blocked(self, ctx):
        findings = _rule().check("cp evil.desktop ~/.config/autostart/", ctx)
        assert len(findings) == 1

    def test_read_autostart_allowed(self, ctx):
        assert _rule().check("cat ~/.config/autostart/existing.desktop", ctx) == []


class TestMacOSLaunchAgent:
    def test_write_user_launchagent_blocked(self, ctx):
        findings = _rule().check("cat > ~/Library/LaunchAgents/com.evil.plist", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.boot_entry"

    def test_cp_to_system_launchdaemon_blocked(self, ctx):
        findings = _rule().check("cp evil.plist /Library/LaunchDaemons/", ctx)
        assert len(findings) == 1

    def test_cp_to_system_launchagent_blocked(self, ctx):
        findings = _rule().check("cp evil.plist /Library/LaunchAgents/", ctx)
        assert len(findings) == 1


class TestLaunchctl:
    def test_launchctl_load_blocked(self, ctx):
        findings = _rule().check("launchctl load ~/Library/LaunchAgents/com.evil.plist", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.boot_entry"

    def test_launchctl_bootstrap_blocked(self, ctx):
        findings = _rule().check("launchctl bootstrap gui/501 evil.plist", ctx)
        assert len(findings) == 1

    def test_launchctl_unload_allowed(self, ctx):
        assert _rule().check("launchctl unload ~/Library/LaunchAgents/foo.plist", ctx) == []

    def test_launchctl_list_allowed(self, ctx):
        assert _rule().check("launchctl list", ctx) == []


class TestSystemdUserUnit:
    def test_write_user_service_blocked(self, ctx):
        findings = _rule().check("cat > ~/.config/systemd/user/evil.service", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.boot_entry"

    def test_write_user_timer_blocked(self, ctx):
        findings = _rule().check("cat > ~/.config/systemd/user/evil.timer", ctx)
        assert len(findings) == 1


class TestDefaults:
    def test_defaults_login_hook_blocked(self, ctx):
        findings = _rule().check(
            "defaults write com.apple.loginwindow LoginHook /tmp/evil.sh", ctx
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.boot_entry"

    def test_defaults_write_other_allowed(self, ctx):
        assert _rule().check("defaults write com.apple.finder ShowPathbar true", ctx) == []


class TestUnrelated:
    def test_git_status_allowed(self, ctx):
        assert _rule().check("git status", ctx) == []
