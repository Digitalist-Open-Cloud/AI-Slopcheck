from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

_FUNC_RE = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(")
_COMMENT_RE = re.compile(r"//[^\n]*|#(?!\[)[^\n]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")
_TODO_RE = re.compile(r"\b(?:TODO|FIXME|implement(?:ed|ation)?|stub|placeholder)\b", re.I)
_TRIVIAL_RETURN_RE = re.compile(
    r"^return\s*(?:null|false|true|\[\]|array\(\)|''|\"\"|0)?\s*;$", re.I
)
_NOT_IMPLEMENTED_RE = re.compile(
    r"^throw\s+new\s+\\?[\w\\]*Exception\s*\(\s*(['\"])[^'\"]*"
    r"(?:not\s+(?:yet\s+)?implemented|todo|implement)[^'\"]*\1\s*\)\s*;$",
    re.I,
)


# Strings and comments in one pass, so a quote inside a comment can't start a string.
_MASK_RE = re.compile(_STRING_RE.pattern + "|" + _COMMENT_RE.pattern, re.DOTALL)


def _mask(content: str) -> str:
    """content with strings and comments blanked, same length and offsets."""
    return _MASK_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), content)


def _body(content: str, masked: str, start: int) -> str | None:
    """Text inside the braces of the function whose signature ends at start,
    or None for abstract/interface methods that end in `;`."""
    brace, semi = masked.find("{", start), masked.find(";", start)
    if brace == -1 or (semi != -1 and semi < brace):
        return None
    depth = 0
    for i in range(brace, len(masked)):
        depth += {"{": 1, "}": -1}.get(masked[i], 0)
        if depth == 0:
            return content[brace + 1 : i]
    return None


class StubFunctionBodyPhpRule(Rule):
    rule_id = "stub_function_body_php"
    title = "Stub function body (PHP)"
    supported_extensions = PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        if not config.rules.stub_function_body_php.enabled:
            return []
        if not self.applies_to_path(relative_path):
            return []

        masked = _mask(content)
        findings: list[Finding] = []
        for m in _FUNC_RE.finditer(masked):
            name = m.group(1)
            if name == "__construct":  # empty body is normal with property promotion
                continue
            body = _body(content, masked, m.end())
            if body is None:
                continue
            code = _COMMENT_RE.sub("", body).strip()
            comments = " ".join(c.group(0) for c in _COMMENT_RE.finditer(body))
            if _NOT_IMPLEMENTED_RE.match(code):
                kind = "only throws a 'not implemented' exception"
            elif _TODO_RE.search(comments) and (not code or _TRIVIAL_RETURN_RE.match(code)):
                kind = "has only a TODO comment" + (" and a placeholder return" if code else "")
            else:
                continue
            line = content.count("\n", 0, m.start()) + 1
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=line,
                    message=f"Function `{name}` {kind}.",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    evidence=content.splitlines()[line - 1].strip(),
                    suggestion="Implement the function or remove it before merging.",
                    tags=["ai-slop", "stub"],
                )
            )
        return findings
