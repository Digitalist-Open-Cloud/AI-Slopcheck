from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

_THEN_RE = re.compile(r"\.then\s*\(")
_CATCH_RE = re.compile(r"\.catch\s*\(")


# Statement text before the first .then: awaited or returned promises reject
# into the caller, which handles them.
_HANDED_ON_RE = re.compile(r"\bawait\b|\breturn\b|=>\s*$|=>\s*[\w(]")
_STATEMENT_END_RE = re.compile(r"[;{},]\s*$")  # , ends object entries and arguments


def _caller_handles(lines: list[str], lineno: int) -> bool:
    start = lineno - 1
    while start > 0 and lineno - start < 5 and not _STATEMENT_END_RE.search(lines[start - 1]):
        start -= 1
    statement = "\n".join(lines[start:lineno])
    before = statement[: statement.find(".then")]  # up to the chain's first .then
    return bool(_HANDED_ON_RE.search(before))


class JsUnhandledPromiseRule(Rule):
    rule_id = "js_unhandled_promise"
    title = "Unhandled promise rejection (.then without .catch)"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.js_unhandled_promise
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []

        for lineno, line in enumerate(lines, start=1):
            if not _THEN_RE.search(line):
                continue

            # Check if .catch appears on the same line or within 3 lines below
            end = min(len(lines), lineno + 3)
            window = lines[lineno - 1 : end]
            combined = " ".join(window)

            if not _CATCH_RE.search(combined) and not _caller_handles(lines, lineno):
                evidence = line.strip()
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            "Promise .then() called without a .catch() handler. "
                            "Unhandled rejections can silently swallow errors."
                        ),
                        severity=Severity.WARNING,
                        confidence=Confidence.MEDIUM,
                        evidence=evidence,
                        suggestion=(
                            "Add a .catch() handler, or convert to async/await inside "
                            "a try/catch block."
                        ),
                        tags=["javascript", "promise", "error-handling"],
                    )
                )

        return findings
