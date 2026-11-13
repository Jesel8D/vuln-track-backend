"""Wrap generated Python string literals without changing their evaluated values."""

import ast
import textwrap
from pathlib import Path


def wrap_long_literals(path: Path) -> None:
    source = path.read_text()
    lines = source.encode().splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    replacements = []

    def chunks(value, width=48):
        return (
            textwrap.wrap(
                value,
                width=width,
                replace_whitespace=False,
                drop_whitespace=False,
                break_long_words=True,
                break_on_hyphens=False,
            )
            if "\n" not in value
            else [value[i : i + width] for i in range(0, len(value), width)]
        )

    class Visitor(ast.NodeVisitor):
        def visit_Constant(self, node):
            if isinstance(node.value, str) and node.value:
                segment = ast.get_source_segment(source, node) or ""
                if any(len(line) + node.col_offset > 92 for line in segment.splitlines()):
                    values = chunks(node.value, max(20, 75 - node.col_offset))
                    replace(node, "(\n" + "\n".join(repr(value) for value in values) + "\n)")

        def visit_JoinedStr(self, node):
            segment = ast.get_source_segment(source, node) or ""
            if any(len(line) + node.col_offset > 92 for line in segment.splitlines()):
                values = []
                for value in node.values:
                    if isinstance(value, ast.Constant):
                        values.extend(repr(part) for part in chunks(value.value))
                    else:
                        values.append(ast.unparse(ast.JoinedStr(values=[value])))
                replace(node, "''.join((\n" + ",\n".join(values) + "\n))")

    def replace(node, value):
        start = offsets[node.lineno - 1] + node.col_offset
        end = offsets[node.end_lineno - 1] + node.end_col_offset
        replacements.append((start, end, value.encode()))

    Visitor().visit(ast.parse(source))
    raw = source.encode()
    for start, end, value in sorted(replacements, reverse=True):
        raw = raw[:start] + value + raw[end:]
    ast.parse(raw)
    path.write_bytes(raw)
