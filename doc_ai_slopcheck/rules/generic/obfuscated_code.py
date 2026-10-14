from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS, is_ignored
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Matches bare eval( or exec(; method calls like /re/.exec(s) are not eval
_EVAL_RE = re.compile(r"(?<![\w.$>:])(?<!function )(eval|exec|create_function)\s*\(")
# PHP's exec() runs a shell command (see php_user_input_sink), not code.
_PHP_EVAL_RE = re.compile(r"(?<![\w.$>:])(?<!function )(eval|create_function)\s*\(")
# JS Function constructor: new Function(
_FUNCTION_CTOR_RE = re.compile(r"\bnew\s+Function\s*\(")
# atob( -- base64 decode in browser JS
_ATOB_RE = re.compile(r"\batob\s*\(")
# base64 decode calls (Python)
_B64_DECODE_RE = re.compile(
    r"\bb64decode\s*\(|base64\.b64decode\s*\("
    r"|\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\("  # PHP
)
# Hex escape sequences -- flag if more than 3 occur on one line
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
# Python bytes literals hold binary data (file signatures), not hidden code.
_BYTES_LITERAL_RE = re.compile(r"\b[bB][rR]?(?:\"[^\"]*\"|'[^']*')")


class ObfuscatedCodeRule(Rule):
    rule_id = "obfuscated_code"
    title = "Potentially obfuscated code detected"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"} | PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.obfuscated_code
        if not rule_config.enabled:
            return []

        if not self.applies_to_path(relative_path):
            return []

        if is_ignored(relative_path, config.test_paths):
            return []

        # Skip minified files: .min.js, .min.css, etc.
        lower_path = relative_path.lower()
        if ".min." in lower_path:
            return []

        # Skip vendor/bundled files by detecting long average line length.
        lines = content.splitlines()
        if lines:
            avg_line_len = sum(len(ln) for ln in lines) / len(lines)
            if avg_line_len > 200:
                return []

        is_php = Path(relative_path).suffix.lower() in PHP_EXTENSIONS
        eval_re = _PHP_EVAL_RE if is_php else _EVAL_RE
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, start=1):
            # Decoding base64 is normal (keys, auth headers); it only signals
            # obfuscation when the decoded data is executed.
            decodes = _ATOB_RE.search(line) or _B64_DECODE_RE.search(line)
            label: str | None = None
            if eval_re.search(line) or _FUNCTION_CTOR_RE.search(line):
                label = (
                    "eval/exec of base64-decoded data"
                    if decodes
                    else "eval/exec call"
                    if eval_re.search(line)
                    else "Function() constructor"
                )
            elif len(_HEX_ESCAPE_RE.findall(_BYTES_LITERAL_RE.sub("", line))) > 6:
                # Raised from 3 to 6 — standard string encoding often has a few hex escapes.
                label = "dense hex escape sequences"

            if label:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=f"Potentially obfuscated code: {label}.",
                        severity=Severity.WARNING,
                        confidence=Confidence.MEDIUM,
                        evidence=line.strip(),
                        suggestion=(
                            "Replace obfuscated patterns with readable code. "
                            "If intentional, add a suppression comment."
                        ),
                        tags=["obfuscation", "security"],
                    )
                )

        return findings
