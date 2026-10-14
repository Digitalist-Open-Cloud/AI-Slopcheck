from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# JS/TS function declarations:
# function name(...) { ... }
# const name = (...) => { ... }
# const name = (...) => expr
# name(...) { ... }   (method shorthand in class/object)
# Keywords that look like method shorthand but are control flow
_JS_CONTROL_FLOW = frozenset({
    "if", "else", "for", "while", "switch", "catch", "with",
    "do", "return", "throw", "new", "delete", "typeof", "void",
})

# Intentional no-op/stub function name prefixes
_JS_NOOP_PREFIXES = ("empty", "noop", "mock", "fake", "stub", "dummy")

JS_FUNC_RE = re.compile(
    r"^(\s*)(?:(?:export\s+)?(?:async\s+)?function\s+(\w+)"  # function decl
    r"|(?:(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>)"  # arrow
    r"|(\w+)\s*\([^)]*\)\s*\{)"  # method shorthand
)

# Stub return values for JS/TS
JS_STUB_RETURN_RE = re.compile(
    r"^\s*return\s+(?:null|undefined|true|false|\[\]|\{\}|\"\"|\'\'"
    r"|0|0\.0|-1|void\s+0)\s*;?\s*$"
)

# Arrow function one-liner returning a stub
JS_ARROW_STUB_RE = re.compile(
    r"=>\s*(?:null|undefined|\[\]|\{\}|\"\"|\'\'"
    r"|0|false|true|void\s+0)\s*;?\s*$"
)

# Empty brace body: { } or { /* comment */ }
JS_EMPTY_BODY_RE = re.compile(r"^\s*\{\s*(?:/\*.*?\*/\s*)?\}\s*$")

_TODO_RE = re.compile(
    r"\b(?:TODO|FIXME)\b|@todo|\bnot\s+(?:yet\s+)?implemented\b|\bimplement\s+(?:me|this)\b",
    re.IGNORECASE,
)
# Throw NotImplementedError or similar
JS_THROW_NOT_IMPL_RE = re.compile(
    r"^\s*throw\s+new\s+(?:Error|NotImplementedError)"
    r'\(\s*["\'](?:not\s+implemented|todo|stub)',
    re.IGNORECASE,
)


class StubFunctionBodyJsRule(Rule):
    rule_id = "stub_function_body_js"
    title = "Stub function body (JS/TS)"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.stub_function_body
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        # Skip test and spec files
        lower_path = relative_path.lower()
        if any(
            seg in lower_path
            for seg in (".test.", ".spec.", "__test__", "__tests__", "fixture")
        ):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            func_match = JS_FUNC_RE.match(line)
            if func_match is None:
                continue

            func_name = (
                func_match.group(2)
                or func_match.group(3)
                or func_match.group(4)
                or "anonymous"
            )

            # Skip control flow keywords matched by method shorthand pattern
            if func_name in _JS_CONTROL_FLOW:
                continue

            # Skip intentional no-op/stub function names
            if func_name.lower().startswith(_JS_NOOP_PREFIXES):
                continue

            func_line = i + 1

            # Check for one-liner arrow function stubs
            if JS_ARROW_STUB_RE.search(line):
                findings.append(
                    self._make_finding(relative_path, func_line, func_name, line.strip())
                )
                continue

            # Check for empty brace body on same line: function() { }
            after_name = line[func_match.end():]
            if re.search(r"\{\s*\}\s*;?\s*$", after_name):
                findings.append(
                    self._make_finding(relative_path, func_line, func_name, "{ }")
                )
                continue

            # Look at the brace-delimited body
            body = self._extract_brace_body(lines, i)
            if body is None:
                continue
            comments = [ln for ln in body if ln.startswith(("//", "/*", "*"))]
            body_lines = [ln for ln in body if ln not in comments]
            if len(body_lines) == 1:
                stmt = body_lines[0].strip().rstrip(";")
                # A lone `return []` is often deliberate (Next.js
                # generateStaticParams, default handlers); only a TODO makes it a stub.
                if JS_THROW_NOT_IMPL_RE.match(body_lines[0]) or (
                    JS_STUB_RETURN_RE.match(body_lines[0])
                    and any(_TODO_RE.search(c) for c in comments)
                ):
                    findings.append(
                        self._make_finding(
                            relative_path, func_line, func_name, stmt
                        )
                    )

        return findings

    def _make_finding(
        self,
        relative_path: str,
        line: int,
        func_name: str,
        evidence_stmt: str,
    ) -> Finding:
        return self.build_finding(
            relative_path=relative_path,
            line=line,
            message=(
                f"Function `{func_name}` has a stub body "
                f"(`{evidence_stmt[:60]}`). "
                "This may be an incomplete AI-generated implementation."
            ),
            severity=Severity.WARNING,
            confidence=Confidence.LOW,
            evidence=f"{func_name}:{evidence_stmt[:60]}",
            suggestion=(
                "Implement the function body or mark it "
                "as intentionally empty."
            ),
            tags=["ai-stub", "incomplete"],
        )

    @staticmethod
    def _extract_brace_body(
        lines: list[str], func_idx: int
    ) -> list[str] | None:
        """Extract non-blank lines (comments included) from a brace-delimited body."""
        # Find opening brace
        j = func_idx
        while j < len(lines) and "{" not in lines[j]:
            j += 1
        if j >= len(lines):
            return None

        brace_depth = 0
        body: list[str] = []
        started = False

        for k in range(j, min(j + 20, len(lines))):  # limit search
            for ch in lines[k]:
                if ch == "{":
                    brace_depth += 1
                    started = True
                elif ch == "}":
                    brace_depth -= 1

            if started and brace_depth == 0:
                break

            if started and brace_depth > 0 and k > j:
                stripped = lines[k].strip()
                if stripped and stripped != "{":
                    body.append(stripped)

        return body if started else None
