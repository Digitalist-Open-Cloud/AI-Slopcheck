from __future__ import annotations

import ast
import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

_JS_FUNC_RE = re.compile(
    r"\b(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?"
    r"(?:function\b|\([^)]*\)\s*=>))"
)
_JS_ARROW_BRACE_RE = re.compile(r"=>\s*\{")
_GO_FUNC_RE = re.compile(r"^func\s+")
# Named functions, methods and closures; \b keeps function_exists( out.
_PHP_FUNC_RE = re.compile(r"\bfunction\b\s*&?\s*\w*\s*\(")


def _has_body(lines: list[str], start_line: int) -> bool:
    """False for abstract/interface declarations, which end in `;` before any `{`."""
    for line in lines[start_line - 1 :]:
        brace, semi = line.find("{"), line.find(";")
        if brace != -1 or semi != -1:
            return brace != -1 and (semi == -1 or brace < semi)
    return False


def _brace_end(lines: list[str], start_line: int) -> int:
    """Line where the brace block opened at or after start_line closes."""
    depth = 0
    started = False
    for i, line in enumerate(lines[start_line - 1 :], start=start_line):
        depth += line.count("{") - line.count("}")
        started = started or "{" in line
        if started and depth <= 0:
            return i
    return start_line


class LargeFunctionRule(Rule):
    rule_id = "large_function"
    title = "Function exceeds maximum line count"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"} | PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.large_function
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        ext = Path(relative_path).suffix.lower()
        max_lines = rule_config.max_lines
        lines = content.splitlines()

        if ext == ".py":
            return self._scan_python(relative_path, content, max_lines)
        elif ext in {".js", ".jsx", ".ts", ".tsx"}:
            return self._scan_js(relative_path, lines, max_lines)
        elif ext == ".go":
            return self._scan_braced(relative_path, lines, max_lines, _GO_FUNC_RE)
        elif ext in PHP_EXTENSIONS:
            return self._scan_braced(relative_path, lines, max_lines, _PHP_FUNC_RE)
        return []

    def _scan_python(
        self, relative_path: str, content: str, max_lines: int
    ) -> list[Finding]:
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            func_len = node.end_lineno - node.lineno + 1
            if func_len > max_lines:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=node.lineno,
                        message=(
                            f"Function `{node.name}` is {func_len} lines long "
                            f"(max {max_lines}). "
                            "Large functions are harder to test, review, and maintain."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.HIGH,
                        evidence=lines[node.lineno - 1].strip(),
                        suggestion=(
                            "Break this function into smaller, focused helper functions "
                            "with single responsibilities."
                        ),
                        tags=["complexity", "maintainability"],
                    )
                )
        return findings

    def _scan_js(
        self, relative_path: str, lines: list[str], max_lines: int
    ) -> list[Finding]:
        findings: list[Finding] = []
        func_starts: list[tuple[int, str]] = []

        for lineno, line in enumerate(lines, start=1):
            if _JS_FUNC_RE.search(line) or _JS_ARROW_BRACE_RE.search(line):
                func_starts.append((lineno, line.strip()))

        for start_line, header in func_starts:
            # Walk forward counting brace depth to find end of function
            func_len = _brace_end(lines, start_line) - start_line + 1
            if func_len > max_lines:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=start_line,
                        message=(
                            f"Function is {func_len} lines long (max {max_lines}). "
                            "Large functions are harder to test, review, and maintain."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.LOW,
                        evidence=header,
                        suggestion=(
                            "Break this function into smaller, focused helper functions "
                            "with single responsibilities."
                        ),
                        tags=["complexity", "maintainability"],
                    )
                )

        return findings

    def _scan_braced(
        self, relative_path: str, lines: list[str], max_lines: int, func_re: re.Pattern[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        func_starts: list[tuple[int, str]] = []

        for lineno, line in enumerate(lines, start=1):
            if func_re.search(line) and _has_body(lines, lineno):
                func_starts.append((lineno, line.strip()))

        for start_line, header in func_starts:
            func_len = _brace_end(lines, start_line) - start_line + 1
            if func_len > max_lines:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=start_line,
                        message=(
                            f"Function is {func_len} lines long (max {max_lines}). "
                            "Large functions are harder to test, review, and maintain."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.LOW,
                        evidence=header,
                        suggestion=(
                            "Break this function into smaller, focused helper functions "
                            "with single responsibilities."
                        ),
                        tags=["complexity", "maintainability"],
                    )
                )

        return findings
