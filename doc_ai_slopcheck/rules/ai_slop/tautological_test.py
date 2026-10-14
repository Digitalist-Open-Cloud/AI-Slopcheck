from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# A literal: true/false/null/None/undefined, a number, or a quoted string.
_LIT = (
    r"(?:true|false|TRUE|FALSE|True|False|null|NULL|None|undefined|-?\d+(?:\.\d+)?"
    r"""|'[^'\n]*'|"[^"\n]*")"""
)

# Assertions whose outcome is fixed: comparing a literal with itself, or
# asserting a literal truth. They pass whatever the code does.
_TAUTOLOGIES = [
    # JS/TS: expect(true).toBe(true), expect(1).toEqual(1), expect(true).toBeTruthy()
    re.compile(rf"\bexpect\(\s*(?P<a>{_LIT})\s*\)\s*\.\s*(?:toBe|toEqual|toStrictEqual)\(\s*(?P=a)\s*\)"),
    re.compile(r"\bexpect\(\s*true\s*\)\s*\.\s*toBeTruthy\(\s*\)|\bexpect\(\s*false\s*\)\s*\.\s*toBeFalsy\(\s*\)"),
    re.compile(r"\bassert(?:\.ok)?\(\s*true\s*\)"),
    # Python: assert True, assert 1 == 1, self.assertTrue(True), self.assertEqual(1, 1)
    # (`assert True in seen` is a real membership check, so nothing may follow True.)
    re.compile(rf"^\s*assert\s+(?:True\s*(?:$|,|#)|(?P<b>{_LIT})\s*==\s*(?P=b)\s*$)"),
    re.compile(r"\bassertTrue\(\s*(?:True|TRUE|true)\s*\)|\bassertFalse\(\s*(?:False|FALSE|false)\s*\)"),
    # Python unittest / PHPUnit / Node assert: assertEqual(s)/assertSame/equal(LIT, LIT)
    re.compile(rf"\b(?:assertEquals?|assertSame|strictEqual|deepEqual|equal)\(\s*(?P<c>{_LIT})\s*,\s*(?P=c)\s*[,)]"),
]


class TautologicalTestRule(Rule):
    """Assertions that cannot fail, e.g. `expect(true).toBe(true)`: a test that
    looks like coverage but checks nothing."""

    rule_id = "tautological_test"
    title = "Assertion that cannot fail"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"} | PHP_EXTENSIONS
    downgrade_in_tests = False  # only ever found in tests

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        if not config.rules.tautological_test.enabled:
            return []
        if not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if any(rx.search(line) for rx in _TAUTOLOGIES):
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            "This assertion compares fixed values, so it passes whatever "
                            "the code does."
                        ),
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        evidence=line.strip()[:200],
                        suggestion=(
                            "Assert on the result of the code under test, or delete the "
                            "placeholder test."
                        ),
                        tags=["ai-slop", "tests"],
                    )
                )
        return findings
