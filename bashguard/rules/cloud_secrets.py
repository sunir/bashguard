"""
bashguard.rules.cloud_secrets — Cloud/infra secret manager and git credential access.

credentials.cloud_secret:
  Cloud provider and infrastructure CLIs can retrieve secrets directly from
  managed secret stores without any filesystem read — the secret arrives in
  plaintext in the command output.

  AWS:
    secretsmanager get-secret-value — reads a secret value from Secrets Manager
    ssm get-parameter --with-decryption — decrypts a SecureString SSM parameter

  GCP:
    gcloud secrets versions access — reads a secret version from Secret Manager

  Azure:
    az keyvault secret show — reads a Key Vault secret

  HashiCorp Vault:
    vault kv get <path> — reads a secret from KV store
    vault read <path> — reads a secret from any backend

  HashiCorp Consul:
    consul kv get <key> — reads a key from the KV store

  Kubernetes:
    kubectl get secret <name> — reads a k8s Secret object (may include base64 data)

  Terraform:
    terraform output <name> — prints output values (can include sensitive outputs)
    terraform state pull — dumps full state file (contains all resource attributes)
    terraform state show — shows individual resource attributes

  Ansible Vault:
    ansible-vault decrypt — decrypts encrypted file in place
    ansible-vault view — shows decrypted content

  git credential:
    git credential fill/approve — invokes the credential helper

MITRE ATT&CK T1552.001 (Credentials in Files) / T1552.005 (Cloud Instance Metadata).
"""
from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# git credential subcommands that retrieve credentials
_GIT_CRED_RETRIEVE = frozenset({"fill", "approve"})


def _finding(message: str, matched: str, **meta) -> Finding:
    return Finding(
        rule_id="credentials.cloud_secret",
        severity=Severity.CRITICAL,
        action_type=ActionType.CREDENTIAL_ACCESS,
        message=message,
        matched_text=matched,
        metadata=meta,
    )


@register
class CloudSecretRule:
    rule_id = "credentials.cloud_secret"
    severity = Severity.CRITICAL
    description = "Cloud secret manager access — reads production credentials via CLI"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("cloud_secret rule error")
            return []

    def _scan(self, script: str):
        for cmd in parse(script):
            if cmd.name == "aws":
                yield from self._check_aws(cmd)
            elif cmd.name == "gcloud":
                yield from self._check_gcloud(cmd)
            elif cmd.name == "az":
                yield from self._check_az(cmd)
            elif cmd.name == "git":
                yield from self._check_git_credential(cmd)
            elif cmd.name == "vault":
                yield from self._check_vault(cmd)
            elif cmd.name == "consul":
                yield from self._check_consul(cmd)
            elif cmd.name == "kubectl":
                yield from self._check_kubectl(cmd)
            elif cmd.name == "terraform":
                yield from self._check_terraform(cmd)
            elif cmd.name == "ansible-vault":
                yield from self._check_ansible_vault(cmd)

    def _check_aws(self, cmd):
        args = cmd.args
        if not args:
            return
        service = args[0]
        if service == "secretsmanager":
            # aws secretsmanager get-secret-value [...]
            if len(args) > 1 and args[1] == "get-secret-value":
                yield _finding(
                    f"{self.description}: aws secretsmanager get-secret-value",
                    "aws secretsmanager get-secret-value",
                    service="secretsmanager",
                )
        elif service == "ssm":
            # aws ssm get-parameter --with-decryption (SecureString decrypt)
            # aws ssm get-parameters --with-decryption
            if len(args) > 1 and args[1] in ("get-parameter", "get-parameters"):
                all_flags = cmd.flags + cmd.args
                if "--with-decryption" in all_flags:
                    yield _finding(
                        f"{self.description}: aws ssm {args[1]} --with-decryption",
                        f"aws ssm {args[1]} --with-decryption",
                        service="ssm",
                    )

    def _check_gcloud(self, cmd):
        args = cmd.args
        # gcloud secrets versions access <version> [--secret=name]
        # args = ["secrets", "versions", "access", ...]
        if len(args) >= 3 and args[0] == "secrets" and args[1] == "versions" and args[2] == "access":
            yield _finding(
                f"{self.description}: gcloud secrets versions access",
                "gcloud secrets versions access",
                service="gcloud-secrets",
            )

    def _check_az(self, cmd):
        args = cmd.args
        # az keyvault secret show [...]
        if len(args) >= 3 and args[0] == "keyvault" and args[1] == "secret" and args[2] == "show":
            yield _finding(
                f"{self.description}: az keyvault secret show",
                "az keyvault secret show",
                service="azure-keyvault",
            )

    def _check_git_credential(self, cmd):
        args = cmd.args
        # git credential fill / approve
        if len(args) >= 2 and args[0] == "credential" and args[1] in _GIT_CRED_RETRIEVE:
            yield _finding(
                f"{self.description}: git credential {args[1]}",
                f"git credential {args[1]}",
                service="git-credential",
            )

    def _check_vault(self, cmd):
        args = cmd.args
        if not args:
            return
        # vault kv get <path>
        if args[0] == "kv" and len(args) > 1 and args[1] == "get":
            yield _finding(
                f"{self.description}: vault kv get",
                "vault kv get",
                service="vault",
            )
        # vault read <path> — reads from any secret backend
        elif args[0] == "read":
            yield _finding(
                f"{self.description}: vault read",
                "vault read",
                service="vault",
            )

    def _check_consul(self, cmd):
        args = cmd.args
        # consul kv get <key>
        if len(args) >= 3 and args[0] == "kv" and args[1] == "get":
            yield _finding(
                f"{self.description}: consul kv get",
                "consul kv get",
                service="consul",
            )

    def _check_kubectl(self, cmd):
        args = cmd.args
        # kubectl get secret <name> [...]
        if len(args) >= 3 and args[0] == "get" and args[1] == "secret":
            yield _finding(
                f"{self.description}: kubectl get secret",
                "kubectl get secret",
                service="kubernetes",
            )
        # kubectl exec -it <pod> -- env (environment variable exfil)
        elif len(args) >= 1 and args[0] == "exec":
            # Check if -- env or -- printenv follows
            joined = " ".join(args)
            if "-- env" in joined or "-- printenv" in joined:
                yield _finding(
                    f"{self.description}: kubectl exec dumps pod environment",
                    "kubectl exec -- env",
                    service="kubernetes",
                )

    def _check_terraform(self, cmd):
        args = cmd.args
        if not args:
            return
        subcmd = args[0]
        if subcmd == "output":
            # terraform output [name] — prints outputs (may include sensitive values)
            yield _finding(
                f"{self.description}: terraform output exposes state values",
                "terraform output",
                service="terraform",
            )
        elif subcmd == "state":
            # terraform state pull / terraform state show
            if len(args) > 1 and args[1] in ("pull", "show"):
                yield _finding(
                    f"{self.description}: terraform state {args[1]} exposes resource secrets",
                    f"terraform state {args[1]}",
                    service="terraform",
                )

    def _check_ansible_vault(self, cmd):
        args = cmd.args
        if not args:
            return
        # ansible-vault decrypt / view — decrypts or shows encrypted content
        if args[0] in ("decrypt", "view"):
            yield _finding(
                f"{self.description}: ansible-vault {args[0]} decrypts secrets",
                f"ansible-vault {args[0]}",
                service="ansible-vault",
            )
