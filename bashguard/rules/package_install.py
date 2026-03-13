"""
bashguard.rules.package_install — Flag global package manager installs.

Detects system-level mutations via:
- npm install -g / npm i -g
- brew install
- apt-get install / apt install
- yum install / dnf install
- pip install --break-system-packages

Does NOT flag:
- pip install <package> (assumed to be venv-local)
- pip install -r requirements.txt
- pip install -e .
"""

from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)


@register
class PackageInstallRule:
    rule_id = "package_install.global"
    severity = Severity.HIGH
    description = "Global system package install that modifies system state"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings = []

            for cmd in cmds:
                finding = None

                if cmd.name in {"brew", "apt-get", "apt", "yum", "dnf", "pacman",
                                 "zypper", "snap", "flatpak"}:
                    # Any install subcommand on these is a system mutation
                    subcommand = cmd.args[0] if cmd.args else ""
                    if subcommand in {"install", "add", "in"}:
                        finding = Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"System package install: {cmd.name} {subcommand}",
                            matched_text=cmd.raw,
                            metadata={"command": cmd.name, "subcommand": subcommand},
                            action_type=ActionType.PACKAGE_INSTALL,
                        )

                elif cmd.name in {"npm", "yarn", "pnpm", "bun"}:
                    subcommand = cmd.args[0] if cmd.args else ""
                    if subcommand in {"install", "i", "add", "global"}:
                        is_global = "-g" in cmd.flags or "--global" in cmd.flags
                        if is_global or subcommand == "global":
                            finding = Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                message=f"Global {cmd.name} install",
                                matched_text=cmd.raw,
                                metadata={"command": cmd.name},
                                action_type=ActionType.PACKAGE_INSTALL,
                            )

                elif cmd.name == "pip" or cmd.name == "pip3":
                    subcommand = cmd.args[0] if cmd.args else ""
                    if subcommand == "install":
                        if "--break-system-packages" in cmd.flags:
                            finding = Finding(
                                rule_id=self.rule_id,
                                severity=Severity.CRITICAL,
                                message="pip install --break-system-packages modifies system Python",
                                matched_text=cmd.raw,
                                metadata={"command": cmd.name},
                                action_type=ActionType.PACKAGE_INSTALL,
                            )
                        # pip install without venv flags is generally safe (venv assumed)
                        # Only flag explicit system-breaking patterns

                if finding:
                    findings.append(finding)

            return findings
        except Exception as e:
            _log.error("PackageInstallRule raised: %s", e, exc_info=True)
            return []
