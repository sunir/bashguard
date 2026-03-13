"""
bashguard.rules.evasion — Layer 1 fail-close evasion detection.

Principle: if the command's intent cannot be read directly from the AST, block it.
Structural ambiguity is itself the signal.

See specs/05-fail-close.md for rationale and full rule descriptions.
All rules produce severity=CRITICAL → BLOCK under default policy.
"""

from __future__ import annotations
import logging

import tree_sitter_bash as tsb
from tree_sitter import Language, Parser as TSParser

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)
_LANG = Language(tsb.language())
_PARSER = TSParser(_LANG)

_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})

_INTERP_EXEC_FLAGS: dict[str, str] = {
    "python": "-c", "python3": "-c", "python2": "-c",
    "perl": "-e", "ruby": "-e",
    "node": "-e", "nodejs": "-e",
    "php": "-r",
}

_DECODE_TOOLS = frozenset({
    "base64", "xxd", "openssl", "gunzip", "zcat", "bzcat",
    "xz", "lzma", "rev", "tr",
})

_DANGEROUS_ENV_VARS = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "BASH_ENV", "ENV",
    "PROMPT_COMMAND",
})


# ─── Shared helpers ───────────────────────────────────────────────────────────

def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _collect(root, *node_types: str) -> list:
    """Depth-first collect all nodes matching any of the given types."""
    results = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in node_types:
            results.append(node)
        stack.extend(node.children)
    return results


def _parse_cst(script: str):
    source = script.encode("utf-8", errors="replace")
    tree = _PARSER.parse(source)
    return tree.root_node, source


def _unwrap_cmd_name(cmd_node):
    """Get the inner node of the command name, unwrapping any command_name wrapper.

    tree-sitter-bash wraps the name expression in a 'command_name' node:
      (command (command_name (word "echo")) ...)
    We need the inner node (word, command_substitution, simple_expansion, etc.)
    to determine whether the command name is a plain word or dynamic.
    """
    name_field = cmd_node.child_by_field_name("name")
    if name_field is None:
        return None
    if name_field.type == "command_name":
        return name_field.children[0] if name_field.children else None
    return name_field  # fallback if grammar doesn't wrap


def _cmd_name_text(cmd_node, source: bytes) -> str | None:
    """Get command name as plain text. Returns None if dynamic or absent."""
    inner = _unwrap_cmd_name(cmd_node)
    if inner is None:
        return None
    if inner.type == "word":
        return _text(inner, source)
    return None  # command_substitution, simple_expansion, ansi_c_string, etc.



def _finding(rule_id: str, message: str, script: str,
             action_type: ActionType = ActionType.OBFUSCATED, **meta) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        message=message,
        matched_text=script,
        metadata=meta,
        action_type=action_type,
    )


# ─── Rules using CommandNode ──────────────────────────────────────────────────

@register
class EvalRule:
    rule_id = "evasion.eval"
    severity = Severity.CRITICAL
    description = "eval executes opaque string payloads — unconditionally blocked"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            for cmd in parse(script):
                if cmd.name == "eval":
                    return [_finding(self.rule_id, "eval executes opaque payload", script)]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class ShellInShellRule:
    rule_id = "evasion.shell_in_shell"
    severity = Severity.CRITICAL
    description = "bash/sh/zsh -c executes opaque string payload"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            for cmd in parse(script):
                if cmd.name in _SHELLS and "-c" in cmd.flags:
                    return [_finding(
                        self.rule_id,
                        f"{cmd.name} -c executes opaque payload",
                        script, shell=cmd.name,
                    )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class InterpreterShellRule:
    rule_id = "evasion.interpreter_shell"
    severity = Severity.CRITICAL
    description = "Scripting language -c/-e/-r flag executes opaque string as code"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            for cmd in parse(script):
                exec_flag = _INTERP_EXEC_FLAGS.get(cmd.name)
                if exec_flag and exec_flag in cmd.flags:
                    return [_finding(
                        self.rule_id,
                        f"{cmd.name} {exec_flag} executes opaque payload",
                        script, interpreter=cmd.name,
                    )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class SourceRule:
    rule_id = "evasion.source"
    severity = Severity.CRITICAL
    description = "source/dot command executes file with opaque contents"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            for cmd in parse(script):
                if cmd.name in {"source", "."}:
                    return [_finding(
                        self.rule_id,
                        f"{cmd.name!r} executes file with opaque contents",
                        script,
                    )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class ExecShellRule:
    rule_id = "evasion.exec_shell"
    severity = Severity.CRITICAL
    description = "exec with shell interpreter replaces process and removes future oversight"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            for cmd in parse(script):
                if cmd.name == "exec":
                    for arg in cmd.args:
                        if not arg.startswith("-"):
                            basename = arg.split("/")[-1]
                            if basename in _SHELLS:
                                return [_finding(
                                    self.rule_id,
                                    f"exec replaces process with shell: {arg}",
                                    script, shell=basename,
                                )]
                            break  # only check first non-flag arg
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class AliasRule:
    rule_id = "evasion.alias"
    severity = Severity.CRITICAL
    description = "alias silently redefines trusted commands for subsequent execution"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            for cmd in parse(script):
                if cmd.name == "alias":
                    return [_finding(self.rule_id, "alias can silently redefine trusted commands", script)]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


# ─── Rules using tree-sitter CST ─────────────────────────────────────────────

@register
class PipeToShellRule:
    rule_id = "evasion.pipe_to_shell"
    severity = Severity.CRITICAL
    description = "Pipeline ending with shell interpreter (curl|bash pattern)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            root, source = _parse_cst(script)
            for pipeline in _collect(root, "pipeline"):
                cmd_children = [c for c in pipeline.children if c.type == "command"]
                if len(cmd_children) >= 2:
                    last_name = _cmd_name_text(cmd_children[-1], source)
                    if last_name in _SHELLS:
                        return [_finding(
                            self.rule_id,
                            f"Pipeline delivers to shell: {last_name}",
                            script, shell=last_name,
                        )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class ProcessSubExecRule:
    rule_id = "evasion.process_sub_exec"
    severity = Severity.CRITICAL
    description = "Process substitution <() feeding shell — fileless RCE"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            root, source = _parse_cst(script)
            for cmd in _collect(root, "command"):
                name = _cmd_name_text(cmd, source)
                if name in _SHELLS or name in {"source", "."}:
                    for arg in cmd.children_by_field_name("argument"):
                        if arg.type == "process_substitution":
                            return [_finding(
                                self.rule_id,
                                f"Process substitution <() feeding {name} — fileless RCE",
                                script, shell=name,
                            )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class DangerousEnvRule:
    rule_id = "evasion.dangerous_env"
    severity = Severity.CRITICAL
    description = "Assignment to execution-hijacking environment variable"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            root, source = _parse_cst(script)
            for va in _collect(root, "variable_assignment"):
                name_node = va.child_by_field_name("name")
                if name_node is None:
                    continue
                var_name = _text(name_node, source)
                if var_name in _DANGEROUS_ENV_VARS:
                    return [_finding(
                        self.rule_id,
                        f"Assignment to {var_name} hijacks execution",
                        script, action_type=ActionType.ENV_MUTATION, variable=var_name,
                    )]
                if var_name == "PATH":
                    val_node = va.child_by_field_name("value")
                    if val_node:
                        val = _text(val_node, source).strip("'\"")
                        if val.startswith("/tmp") or val.startswith("/var/tmp"):
                            return [_finding(
                                self.rule_id,
                                "PATH prepended with /tmp (possible command hijacking)",
                                script, action_type=ActionType.ENV_MUTATION, variable="PATH",
                            )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class DecodePipelineRule:
    rule_id = "evasion.decode_pipeline"
    severity = Severity.CRITICAL
    description = "Decoding utility in pipeline delivering to shell/eval (encoded payload)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            root, source = _parse_cst(script)
            for pipeline in _collect(root, "pipeline"):
                cmd_children = [c for c in pipeline.children if c.type == "command"]
                if len(cmd_children) < 2:
                    continue
                names = [_cmd_name_text(c, source) for c in cmd_children]
                has_decoder = any(n in _DECODE_TOOLS for n in names if n)
                last_name = names[-1] if names else None
                last_is_sink = last_name in _SHELLS or last_name in {"eval", "source", "."}
                if has_decoder and last_is_sink:
                    decoder = next(n for n in names if n and n in _DECODE_TOOLS)
                    return [_finding(
                        self.rule_id,
                        f"{decoder} decoding pipeline delivers to {last_name}",
                        script, decoder=decoder, sink=last_name,
                    )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class DynamicCommandNameRule:
    rule_id = "evasion.dynamic_command_name"
    severity = Severity.CRITICAL
    description = "Non-literal command name — command identity is opaque"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            root, source = _parse_cst(script)
            for cmd in _collect(root, "command"):
                inner = _unwrap_cmd_name(cmd)
                if inner is None:
                    continue
                if inner.type != "word":
                    return [_finding(
                        self.rule_id,
                        f"Dynamic command name via {inner.type} — intent is opaque",
                        script, node_type=inner.type,
                    )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class IfsManipulationRule:
    rule_id = "evasion.ifs_manipulation"
    severity = Severity.CRITICAL
    description = "IFS assignment used to reconstruct blocked commands from innocent parts"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            root, source = _parse_cst(script)
            for va in _collect(root, "variable_assignment"):
                name_node = va.child_by_field_name("name")
                if name_node and _text(name_node, source) == "IFS":
                    return [_finding(
                        self.rule_id,
                        "IFS assignment can reconstruct blocked commands from parts",
                        script,
                    )]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []


@register
class CoprocRule:
    rule_id = "evasion.coproc"
    severity = Severity.CRITICAL
    description = "coproc creates background IPC shell — no legitimate LLM use case"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            for cmd in parse(script):
                if cmd.name == "coproc":
                    return [_finding(self.rule_id, "coproc creates background shell process", script)]
            return []
        except Exception as e:
            _log.error("%s raised: %s", self.rule_id, e, exc_info=True)
            return []
