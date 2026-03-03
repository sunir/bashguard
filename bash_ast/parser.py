"""
bash_ast.parser — Parse bash scripts into CommandNode lists via tree-sitter.

Each CommandNode captures: name, flags, args, redirect_targets, raw text.
All commands in a script are extracted, including those in pipelines,
compound lists (&&, ||, ;), and command substitutions.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from tree_sitter import Language, Parser, Node
import tree_sitter_bash as tsb


_LANG = Language(tsb.language())
_PARSER = Parser(_LANG)


class ParseError(Exception):
    pass


@dataclass
class CommandNode:
    name: str
    args: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    redirect_targets: list[str] = field(default_factory=list)
    raw: str = ""

    @classmethod
    def _from_ts_node(cls, node: Node, source: bytes) -> CommandNode:
        """Build a CommandNode from a tree-sitter 'command' node."""
        name = ""
        args: list[str] = []
        flags: list[str] = []
        redirect_targets: list[str] = []

        for child in node.children:
            text = source[child.start_byte:child.end_byte].decode()

            if child.type == "command_name":
                # Descend to get the word value
                name = source[child.start_byte:child.end_byte].decode().strip()

            elif child.type in ("word", "number", "string", "raw_string",
                                 "ansi_c_string", "concatenation"):
                if text.startswith("-"):
                    flags.append(text)
                else:
                    args.append(text)

            elif child.type in ("redirect", "file_redirect",
                                 "heredoc_redirect", "herestring_redirect"):
                # Find the redirect target (the word after >, >>, <, etc.)
                for rchild in child.children:
                    if rchild.type in ("word", "string"):
                        redirect_targets.append(
                            source[rchild.start_byte:rchild.end_byte].decode()
                        )

        raw = source[node.start_byte:node.end_byte].decode()
        return cls(name=name, args=args, flags=flags,
                   redirect_targets=redirect_targets, raw=raw)


def _extract_redirects(node: Node, source: bytes) -> list[str]:
    """Collect redirect targets from file_redirect siblings."""
    targets = []
    for child in node.children:
        if child.type == "file_redirect":
            for rchild in child.children:
                if rchild.type == "word":
                    targets.append(source[rchild.start_byte:rchild.end_byte].decode())
    return targets


def _walk(node: Node, source: bytes, results: list[CommandNode]) -> None:
    """Recursively walk AST and collect all command nodes."""
    if node.type == "redirected_statement":
        # command is a child; redirects are siblings under this node
        for child in node.children:
            if child.type == "command":
                cmd = CommandNode._from_ts_node(child, source)
                cmd.redirect_targets = _extract_redirects(node, source)
                results.append(cmd)
                # Descend into args for command substitutions
                for grandchild in child.children:
                    if grandchild.type not in ("command_name",):
                        _walk(grandchild, source, results)
            elif child.type not in ("file_redirect",):
                _walk(child, source, results)

    elif node.type == "command":
        results.append(CommandNode._from_ts_node(node, source))
        for child in node.children:
            if child.type not in ("command_name",):
                _walk(child, source, results)

    else:
        for child in node.children:
            _walk(child, source, results)


def parse(script: str) -> list[CommandNode]:
    """
    Parse a bash script and return all CommandNodes.

    Returns [] for empty/whitespace-only input.
    Raises ParseError if tree-sitter produces an ERROR root node.
    """
    if not script.strip():
        return []

    source = script.encode()
    tree = _PARSER.parse(source)
    root = tree.root_node

    results: list[CommandNode] = []
    _walk(root, source, results)
    return results
