"""
bashguard.rules.container_network — Container escape, firewall tamper, staging server.

container.escape:
  Docker --privileged grants full host capabilities. Mounting sensitive host
  paths (-v /:/host, -v /etc:/...) exposes the filesystem outside the container.
  Both are container breakout vectors from the 82-incident AI agent threat database.

network.firewall_tamper:
  iptables -F flushes all rules. iptables -P INPUT ACCEPT sets default-accept.
  ufw disable turns off the firewall entirely. nft flush ruleset clears nftables.
  All enable unrestricted lateral movement.

network.staging_server:
  python3 -m http.server and python -m SimpleHTTPServer create HTTP servers
  used by agents to host payloads or exfiltrate data. php -S and ruby httpd
  are equivalent staging mechanisms.
"""
from __future__ import annotations
import logging
import re

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Sensitive host paths that should never be mounted into containers
_SENSITIVE_MOUNT_PREFIXES = (
    "/etc", "/proc", "/sys", "/dev", "/run",
    "/boot", "/bin", "/sbin", "/usr", "/lib",
    "/root", "/home", "/var",
)

# HTTP staging server modules
_HTTP_SERVER_MODULES = frozenset({
    "http.server", "SimpleHTTPServer", "BaseHTTPServer",
})

# Firewall commands that disable/flush rules
_FIREWALL_CMDS = frozenset({"iptables", "ip6tables", "ip4tables", "nft", "ufw", "firewall-cmd"})


def _is_sensitive_volume(vol_spec: str) -> bool:
    """Return True if a -v mount spec maps a sensitive host path."""
    # vol_spec format: host_path:container_path[:options]
    parts = vol_spec.split(":")
    if not parts:
        return False
    host_path = parts[0].strip("'\"")
    if host_path == "/":
        return True
    return any(host_path == p or host_path.startswith(p + "/")
               for p in _SENSITIVE_MOUNT_PREFIXES)


@register
class ContainerEscapeRule:
    rule_id = "container.escape"
    severity = Severity.CRITICAL
    description = "Container escape: --privileged flag or sensitive host volume mount"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("container_escape rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name not in ("docker", "podman", "nerdctl"):
                continue
            # Only apply to 'run' subcommand
            if "run" not in cmd.args:
                continue
            if "--privileged" in cmd.flags or "--privileged" in cmd.args:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=f"{self.description}: --privileged grants full host capabilities",
                    matched_text="docker run --privileged",
                )
                return
            # Check if -v or --volume flag is present
            has_volume_flag = "-v" in cmd.flags or "--volume" in cmd.flags
            if not has_volume_flag:
                # Also check flags that embed the value: --volume=/etc:/etc
                for f in cmd.flags:
                    if f.startswith("--volume=") or f.startswith("-v/"):
                        vol_spec = f.split("=", 1)[1] if "=" in f else f[2:]
                        if _is_sensitive_volume(vol_spec):
                            yield Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                action_type=ActionType.OBFUSCATED,
                                message=f"{self.description}: sensitive host path mounted: {vol_spec}",
                                matched_text=f,
                            )
                        return
                continue
            # Volume flag present — check args for volume specs (contain ':')
            for arg in cmd.args:
                if ":" in arg and _is_sensitive_volume(arg):
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.OBFUSCATED,
                        message=f"{self.description}: sensitive host path mounted: {arg}",
                        matched_text=f"-v {arg}",
                    )
                    return


@register
class FirewallTamperRule:
    rule_id = "network.firewall_tamper"
    severity = Severity.HIGH
    description = "Firewall rules flushed or disabled — enables unrestricted lateral movement"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("firewall_tamper rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name not in _FIREWALL_CMDS:
                continue
            all_args = cmd.args + cmd.flags
            if cmd.name in ("iptables", "ip6tables", "ip4tables"):
                # -F (flush all) or -P ... ACCEPT (default accept policy)
                if "-F" in all_args:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.NETWORK_OUTBOUND,
                        message=f"{self.description}: {cmd.name} -F flushes all rules",
                        matched_text=f"{cmd.name} -F",
                    )
                elif "-P" in all_args and "ACCEPT" in all_args:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.NETWORK_OUTBOUND,
                        message=f"{self.description}: {cmd.name} -P ... ACCEPT sets default-accept",
                        matched_text=" ".join([cmd.name] + all_args[:4]),
                    )
            elif cmd.name == "ufw":
                if "disable" in all_args:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.NETWORK_OUTBOUND,
                        message=f"{self.description}: ufw disable",
                        matched_text="ufw disable",
                    )
            elif cmd.name == "nft":
                if "flush" in all_args and "ruleset" in all_args:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.NETWORK_OUTBOUND,
                        message=f"{self.description}: nft flush ruleset",
                        matched_text="nft flush ruleset",
                    )


# HTTP staging server module names
_STAGING_MODULES = frozenset({"http.server", "SimpleHTTPServer", "BaseHTTPServer"})

# php -S pattern
_PHP_SERVER_RE = re.compile(r"\bphp\b.*\s-S\s")

# ruby httpd pattern
_RUBY_HTTPD_RE = re.compile(r"\bruby\b.*-run\b.*-e\s+httpd\b")


@register
class StagingServerRule:
    rule_id = "network.staging_server"
    severity = Severity.HIGH
    description = "HTTP staging server — used to host payloads or exfiltrate data"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("staging_server rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        # php -S and ruby httpd — regex on the raw script
        if _PHP_SERVER_RE.search(script):
            yield Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                action_type=ActionType.NETWORK_OUTBOUND,
                message=f"{self.description}: php -S starts HTTP server",
                matched_text="php -S",
            )
            return
        if _RUBY_HTTPD_RE.search(script):
            yield Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                action_type=ActionType.NETWORK_OUTBOUND,
                message=f"{self.description}: ruby httpd starts HTTP server",
                matched_text="ruby -run -e httpd",
            )
            return
        # python -m http.server / SimpleHTTPServer
        # Parser puts -m in flags, module name as first arg
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name not in ("python", "python2", "python3"):
                continue
            if "-m" not in cmd.flags:
                continue
            # First arg is the module name
            module = cmd.args[0] if cmd.args else ""
            if module in _STAGING_MODULES:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.NETWORK_OUTBOUND,
                    message=f"{self.description}: python -m {module}",
                    matched_text=f"python -m {module}",
                )
