"""Tests for external communication rules — email, SMS, webhook, phone.

An AI agent should not autonomously send emails, make phone calls,
post to webhooks, or send SMS messages without explicit approval.
"""
import pytest

from bashguard.models import ActionType, Finding, Severity, ExecutionContext
from bashguard.rules.external_comms import ExternalCommsRule

CTX = ExecutionContext(cwd="/home/user/project")


def findings(script: str) -> list[Finding]:
    return ExternalCommsRule().check(script, CTX)


class TestEmailBlocking:
    def test_sendmail(self):
        fs = findings("echo 'body' | sendmail user@example.com")
        assert any(f.rule_id == "comms.email" for f in fs)

    def test_mail_command(self):
        fs = findings("mail -s 'Subject' user@example.com < body.txt")
        assert any(f.rule_id == "comms.email" for f in fs)

    def test_mutt(self):
        fs = findings("mutt -s 'hi' user@example.com")
        assert any(f.rule_id == "comms.email" for f in fs)

    def test_smtp_curl(self):
        fs = findings("curl --url 'smtp://mail.example.com' --mail-from 'me@x.com'")
        assert any(f.rule_id == "comms.email" for f in fs)


class TestSMSBlocking:
    def test_twilio_curl(self):
        fs = findings("curl -X POST https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json")
        assert any(f.rule_id == "comms.sms" for f in fs)

    def test_aws_sns(self):
        fs = findings("aws sns publish --phone-number +15555555555 --message 'hello'")
        assert any(f.rule_id == "comms.sms" for f in fs)


class TestWebhookBlocking:
    def test_slack_webhook(self):
        fs = findings("curl -X POST https://hooks.slack.com/services/T00/B00/xxxx")
        assert any(f.rule_id == "comms.webhook" for f in fs)

    def test_discord_webhook(self):
        fs = findings("curl -X POST https://discord.com/api/webhooks/123/abc")
        assert any(f.rule_id == "comms.webhook" for f in fs)

    def test_teams_webhook(self):
        fs = findings("curl -X POST https://outlook.office.com/webhook/abc123")
        assert any(f.rule_id == "comms.webhook" for f in fs)


class TestSafeOperations:
    def test_normal_curl_not_flagged(self):
        fs = findings("curl https://api.github.com/repos")
        assert not any(f.rule_id.startswith("comms.") for f in fs)

    def test_git_email_config_not_flagged(self):
        fs = findings("git config user.email 'me@example.com'")
        assert not any(f.rule_id.startswith("comms.") for f in fs)


class TestActionType:
    def test_comms_findings_are_network_outbound(self):
        fs = findings("echo 'body' | sendmail user@example.com")
        comms = [f for f in fs if f.rule_id.startswith("comms.")]
        assert all(f.action_type == ActionType.NETWORK_OUTBOUND for f in comms)
