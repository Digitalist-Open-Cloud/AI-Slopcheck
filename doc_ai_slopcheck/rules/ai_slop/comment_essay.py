from __future__ import annotations

import ast
import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import non_code_lines
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Function detection shared with large_function, so both rules agree on spans.
from doc_ai_slopcheck.rules.maintainability.large_function import (
    _GO_FUNC_RE,
    _JS_ARROW_BRACE_RE,
    _JS_FUNC_RE,
    _PHP_FUNC_RE,
    _brace_end,
    _has_body,
)

_NAME_RE = re.compile(
    r"\bfunction\s+&?\s*(\w+)|\bfunc\s+(?:\([^)]*\)\s*)?(\w+)|(\w+)\s*=\s*(?:async\s*)?[(\w]"
)
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}

# Structured API docs are reference, not prose: @param/@return tags (PHPDoc,
# JSDoc), :param: fields, and Google/NumPy docstring sections, plus the indented
# description lines that continue them.
_TAG_RE = re.compile(
    r"^\s*(?:/\*\*|\*)?\s*(?:@\w+|:(?:param|type|returns?|rtype|raises?)\b"
    r"|(?:Args|Arguments|Parameters|Returns|Yields|Raises|Attributes|Examples?):\s*$)"
)
_DOC_PREFIX_RE = re.compile(r"^\s*(?:/\*\*|\*/|\*|//|#)?")


def _structured_lines(lines: list[str], prose: frozenset[int]) -> set[int]:
    """Comment lines that belong to structured API docs."""
    structured: set[int] = set()
    tag_indent: int | None = None
    for n, text in enumerate(lines, start=1):
        if n not in prose:
            tag_indent = None
            continue
        body = text[_DOC_PREFIX_RE.match(text).end():]
        indent = len(body) - len(body.lstrip())
        if _TAG_RE.match(text):
            structured.add(n)
            tag_indent = indent
        elif tag_indent is not None and body.strip() and indent > tag_indent:
            structured.add(n)
        elif body.strip():
            tag_indent = None
    return structured


def _python_spans(content: str) -> list[tuple[int, int, str]]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    return [
        (min([n.lineno] + [d.lineno for d in n.decorator_list]), n.end_lineno, n.name)
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _brace_spans(lines: list[str], ext: str) -> list[tuple[int, int, str]]:
    spans = []
    for lineno, line in enumerate(lines, start=1):
        if ext in _JS_EXTENSIONS:
            is_func = _JS_FUNC_RE.search(line) or _JS_ARROW_BRACE_RE.search(line)
        else:
            is_func = (_PHP_FUNC_RE if ext in PHP_EXTENSIONS else _GO_FUNC_RE).search(line)
        if is_func and _has_body(lines, lineno):
            m = _NAME_RE.search(line)
            name = next((g for g in m.groups() if g), "function") if m else "function"
            spans.append((lineno, _brace_end(lines, lineno), name))
    return spans


class CommentEssayRule(Rule):
    """Functions (or file headers) whose comments and docstrings dwarf the code:
    essays, design notes and decision logs that bury what the code does."""

    rule_id = "comment_essay"
    code_only = False
    title = "Comments and docstrings outweigh the code"
    supported_extensions = {".py", ".go"} | _JS_EXTENSIONS | PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.comment_essay
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        ext = Path(relative_path).suffix.lower()
        lines = content.splitlines()
        all_comments = non_code_lines(content, ext)
        prose = all_comments - _structured_lines(lines, all_comments)
        min_lines, ratio = rule_config.min_comment_lines, rule_config.max_ratio
        spans = _python_spans(content) if ext == ".py" else _brace_spans(lines, ext)

        findings: list[Finding] = []
        for start, end, name in spans:
            if start in all_comments:  # an example inside a docblock, not real code
                continue
            # Only what's inside the function (Python docstrings included). A
            # docblock above a PHP/JS function is API reference by convention.
            span = range(start, end + 1)
            comment = sum(1 for n in span if n in prose)
            code = sum(1 for n in span if n not in all_comments and lines[n - 1].strip())
            if comment >= min_lines and comment > ratio * max(code, 1):
                findings.append(self._finding(relative_path, start, lines, name, comment, code))

        # File header essay: a leading comment/docstring longer than all the code.
        header = 0
        for n, text in enumerate(lines, start=1):
            if n in prose:
                header += 1
            elif n not in all_comments and text.strip() and not text.startswith(("<?php", "#!")):
                break
        code_total = sum(
            1 for n, t in enumerate(lines, start=1) if t.strip() and n not in all_comments
        )
        if header >= 2 * min_lines and header > code_total:
            findings.append(self._finding(relative_path, 1, lines, None, header, code_total))
        return findings

    def _finding(
        self, relative_path: str, line: int, lines: list[str], name: str | None,
        comment: int, code: int,
    ) -> Finding:
        what = f"Function `{name}` has" if name else "The file header has"
        return self.build_finding(
            relative_path=relative_path,
            line=line,
            message=(
                f"{what} {comment} comment/docstring lines for {code} lines of code. "
                "Long prose next to little code is usually design notes or history that "
                "goes stale; keep the why, move the rest to docs or commits."
            ),
            severity=Severity.NOTE,
            confidence=Confidence.MEDIUM,
            evidence=lines[line - 1].strip()[:200],
            suggestion="Trim the comment to what a reader needs to change this code safely.",
            tags=["ai-slop", "comments"],
        )
