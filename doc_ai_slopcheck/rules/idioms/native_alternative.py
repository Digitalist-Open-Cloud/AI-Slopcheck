from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

_JS_SOURCE = r"""(?:from\s+|require\s*\(\s*|import\s*\(\s*)['"]{pkg}['"]"""

# (pattern, what it is, what the platform already ships). Only cases where the
# built-in is a drop-in replacement; lodash as a whole is not flagged.
_JS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(_JS_SOURCE.format(pkg=r"moment(?:-timezone)?")), "moment",
     "Intl.DateTimeFormat / Date (or Temporal)"),
    (re.compile(_JS_SOURCE.format(pkg=r"uuid")), "uuid", "crypto.randomUUID()"),
    (re.compile(_JS_SOURCE.format(pkg=r"(?:query-string|qs|querystring)")), "query-string/qs",
     "URLSearchParams"),
    (re.compile(_JS_SOURCE.format(pkg=r"left-pad")), "left-pad", "String.prototype.padStart"),
    (re.compile(_JS_SOURCE.format(pkg=r"node-fetch")), "node-fetch",
     "the global fetch (Node 18+)"),
    (re.compile(_JS_SOURCE.format(pkg=r"(?:lodash[./]clonedeep|lodash/cloneDeep)")
                + r"|\{[^}]*\bcloneDeep\b[^}]*\}\s*from\s*['\"]lodash['\"]"),
     "lodash cloneDeep", "structuredClone()"),
    (re.compile(r"JSON\.parse\(\s*JSON\.stringify\("), "JSON.parse(JSON.stringify(...)) clone",
     "structuredClone(), which also keeps Date, Map, Set and cycles"),
]
_PY: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^\s*(?:import|from)\s+pytz\b"), "pytz", "zoneinfo (Python 3.9+)"),
    (re.compile(r"^\s*(?:import|from)\s+six\b"), "six", "plain Python 3"),
    (re.compile(r"^\s*(?:import|from)\s+mock\b"), "mock", "unittest.mock"),
    (re.compile(r"^\s*(?:import|from)\s+simplejson\b"), "simplejson", "json"),
    (re.compile(r"^\s*(?:import|from)\s+toml\b"), "toml", "tomllib (Python 3.11+, reading)"),
]
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


class NativeAlternativeRule(Rule):
    """Dependencies or hacks for things the language or platform already ships."""

    rule_id = "native_alternative"
    title = "Dependency or hack where a built-in exists"
    supported_extensions = {".py"} | _JS_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        if not config.rules.native_alternative.enabled:
            return []
        if not self.applies_to_path(relative_path):
            return []

        checks = _PY if relative_path.endswith(".py") else _JS
        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            for pattern, what, builtin in checks:
                if pattern.search(line):
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=f"{what} where the platform already ships {builtin}.",
                            severity=Severity.NOTE,
                            confidence=Confidence.HIGH,
                            evidence=line.strip()[:200],
                            suggestion=f"Use {builtin} and drop the dependency or hack.",
                            tags=["ai-slop", "dependencies"],
                        )
                    )
                    break
        return findings
