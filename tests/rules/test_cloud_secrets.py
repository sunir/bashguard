"""Tests for credentials.cloud_secret rule.

Story: Cloud provider CLIs (aws, gcloud, az) can directly retrieve secrets
from managed secret stores. Unlike ~/.aws or ~/.kube which require a file read,
these commands reach out to cloud APIs and fetch secrets in plaintext.
An AI agent calling aws secretsmanager get-secret-value has direct access
to production credentials — no file read required.

Rule contracts (credentials.cloud_secret):
- aws secretsmanager get-secret-value --secret-id prod/db      → BLOCK
- aws secretsmanager get-secret-value --secret-id /prod/key    → BLOCK
- aws ssm get-parameter --name /prod/db/pass --with-decryption → BLOCK
- gcloud secrets versions access latest --secret=prod-db-key   → BLOCK
- gcloud secrets versions access 1 --secret my-secret          → BLOCK
- az keyvault secret show --name prod-db --vault-name myvault  → BLOCK
- git credential fill                                          → BLOCK
- git credential approve                                       → BLOCK
- aws secretsmanager list-secrets                              → ALLOW (listing, not reading)
- aws ssm get-parameters-by-path --path /prod/ (no decryption) → ALLOW
- aws s3 ls                                                    → ALLOW (unrelated)
- gcloud secrets list                                          → ALLOW (listing)
- gcloud compute instances list                                → ALLOW (unrelated)
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
    from bashguard.rules.cloud_secrets import CloudSecretRule
    return CloudSecretRule()


class TestAwsSecretsManager:
    def test_get_secret_value_blocked(self, ctx):
        findings = _rule().check(
            "aws secretsmanager get-secret-value --secret-id prod/db", ctx
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.cloud_secret"
        assert findings[0].severity == Severity.CRITICAL

    def test_get_secret_value_path_blocked(self, ctx):
        findings = _rule().check(
            "aws secretsmanager get-secret-value --secret-id /prod/key", ctx
        )
        assert len(findings) == 1

    def test_list_secrets_allowed(self, ctx):
        assert _rule().check("aws secretsmanager list-secrets", ctx) == []

    def test_unrelated_s3_allowed(self, ctx):
        assert _rule().check("aws s3 ls", ctx) == []


class TestAwsSsm:
    def test_ssm_get_with_decryption_blocked(self, ctx):
        findings = _rule().check(
            "aws ssm get-parameter --name /prod/db/password --with-decryption", ctx
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.cloud_secret"

    def test_ssm_get_without_decryption_allowed(self, ctx):
        """Reading a non-secret SSM param is allowed."""
        assert _rule().check("aws ssm get-parameter --name /config/env", ctx) == []

    def test_ssm_get_parameters_by_path_no_decrypt_allowed(self, ctx):
        assert _rule().check("aws ssm get-parameters-by-path --path /prod/", ctx) == []


class TestGcloudSecrets:
    def test_gcloud_secrets_access_blocked(self, ctx):
        findings = _rule().check(
            "gcloud secrets versions access latest --secret=prod-db-key", ctx
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.cloud_secret"

    def test_gcloud_secrets_access_numbered_blocked(self, ctx):
        findings = _rule().check(
            "gcloud secrets versions access 1 --secret my-secret", ctx
        )
        assert len(findings) == 1

    def test_gcloud_secrets_list_allowed(self, ctx):
        assert _rule().check("gcloud secrets list", ctx) == []

    def test_gcloud_compute_allowed(self, ctx):
        assert _rule().check("gcloud compute instances list", ctx) == []


class TestAzureKeyVault:
    def test_az_keyvault_secret_show_blocked(self, ctx):
        findings = _rule().check(
            "az keyvault secret show --name prod-db --vault-name myvault", ctx
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.cloud_secret"


class TestGitCredential:
    def test_git_credential_fill_blocked(self, ctx):
        findings = _rule().check("git credential fill", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.cloud_secret"

    def test_git_credential_approve_blocked(self, ctx):
        findings = _rule().check("git credential approve", ctx)
        assert len(findings) == 1


class TestUnrelated:
    def test_git_status_allowed(self, ctx):
        assert _rule().check("git status", ctx) == []

    def test_aws_sts_allowed(self, ctx):
        assert _rule().check("aws sts get-caller-identity", ctx) == []
