from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import is_in_non_code_context, non_code_lines
from doc_ai_slopcheck.engine.repo_files import is_ignored
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule


class _Pattern(NamedTuple):
    regex: re.Pattern[str]
    label: str
    suggestion: str
    in_code: bool = True  # False: a directive that lives in a comment


_PATTERNS: list[_Pattern] = [
    _Pattern(
        regex=re.compile(r"\bas\s+any\b"),
        label="`as any` cast",
        suggestion=(
            "Replace `as any` with a proper type assertion or use `unknown` "
            "and narrow the type with a type guard."
        ),
    ),
    _Pattern(
        regex=re.compile(r"\bas\s+unknown\s+as\b"),
        label="`as unknown as` double assertion",
        suggestion=(
            "A double assertion forces any value into any type. Fix the type, or "
            "narrow `unknown` with a type guard."
        ),
    ),
    _Pattern(
        regex=re.compile(r"@ts-nocheck"),
        label="`@ts-nocheck` (type checking off for the whole file)",
        suggestion="Remove it and fix or narrowly suppress the remaining errors.",
        in_code=False,
    ),
    _Pattern(
        regex=re.compile(r"@ts-ignore"),
        label="`@ts-ignore` suppression",
        suggestion=(
            "Fix the underlying type error instead of suppressing it. "
            "If suppression is intentional, use `@ts-expect-error` with an explanation."
        ),
        in_code=False,
    ),
    _Pattern(
        # @ts-expect-error with nothing or only whitespace after it on the same line
        regex=re.compile(r"@ts-expect-error\s*$"),
        label="`@ts-expect-error` without explanation",
        suggestion=(
            "Add a short explanation after `@ts-expect-error` "
            "so reviewers understand why the error is expected."
        ),
        in_code=False,
    ),
]


class TypescriptAnyAbuseRule(Rule):
    rule_id = "typescript_any_abuse"
    title = "TypeScript type-safety bypass"
    supported_extensions = {".ts", ".tsx"}
    # @ts-ignore and friends live in comments; code patterns are checked per match.
    code_only = False

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.typescript_any_abuse
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        # Skip .d.ts declarations, @types/, and test code
        if (
            relative_path.endswith(".d.ts")
            or "@types/" in relative_path.lower()
            or is_ignored(relative_path, config.test_paths)
        ):
            return []
        prose = non_code_lines(content, Path(relative_path).suffix.lower())

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            for pat in _PATTERNS:
                m = pat.regex.search(line)
                if m and pat.in_code and (
                    lineno in prose or is_in_non_code_context(line, m.start(), "js")
                ):
                    continue  # `as any` mentioned in a comment or string
                if m:
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=(
                                f"TypeScript type-safety bypass: {pat.label} used."
                            ),
                            severity=Severity.WARNING,
                            confidence=Confidence.MEDIUM,
                            evidence=line.strip(),
                            suggestion=pat.suggestion,
                            tags=["typescript", "type-safety"],
                        )
                    )
                    break  # one finding per line
        return findings
