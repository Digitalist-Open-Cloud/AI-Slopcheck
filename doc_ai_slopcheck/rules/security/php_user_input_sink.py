from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import is_in_non_code_context
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# $_SERVER only where the client controls the value (headers, URL parts).
_SUPERGLOBAL_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
    r"|\$_SERVER\s*\[\s*['\"](?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO)['\"]"
)

# Sinks where raw request data becomes code, commands, queries or output.
_SINKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?<![\w>:$])(?:eval|assert|create_function)\s*\("), "code execution"),
    (re.compile(r"\b(?:include|require)(?:_once)?\b"), "file inclusion"),
    (re.compile(r"(?<![\w>:$])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)"
                r"\s*\(|`"), "shell command"),
    (re.compile(r"\bunserialize\s*\("), "unserialize"),
    (re.compile(r"\b(?:extract|parse_str)\s*\("), "variable injection"),
    (re.compile(r"\b(?:mysqli?_query|pg_query|sqlite_query)\s*\(|->(?:query|exec|prepare)\s*\("),
     "SQL query"),
    (re.compile(r"^\s*(?:echo|print)\b|<\?="), "HTML output"),
    (re.compile(r"\bheader\s*\("), "HTTP header"),
    (re.compile(r"\b(?:file_get_contents|readfile|fopen|file_put_contents|unlink|"
                r"move_uploaded_file)\s*\("), "file system"),
]

# Escaping, casting or checking on the same line: assume the input is handled.
_SANITIZER_RE = re.compile(
    r"\b(?:htmlspecialchars|htmlentities|strip_tags|intval|floatval|boolval|filter_var|"
    r"filter_input|escapeshellarg|escapeshellcmd|basename|realpath|is_uploaded_file|"
    r"in_array|isset|empty|array_key_exists|check_plain|Html::escape|Xss::filter|"
    r"urlencode|rawurlencode|json_encode|ctype_\w+|preg_match)\b|\((?:int|float|bool)\)"
)


class PhpUserInputSinkRule(Rule):
    rule_id = "php_user_input_sink"
    title = "Raw request input passed to a dangerous function (PHP)"
    supported_extensions = PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        if not config.rules.php_user_input_sink.enabled:
            return []
        if not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            source = next(
                (m for m in _SUPERGLOBAL_RE.finditer(line)
                 if not is_in_non_code_context(line, m.start(), "php")),
                None,
            )
            if source is None or _SANITIZER_RE.search(line):
                continue
            label = next((label for rx, label in _SINKS if rx.search(line)), None)
            if label is None:
                continue
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=(
                        f"`{source.group(0)}` goes straight into {label} without "
                        "escaping or validation on this line."
                    ),
                    severity=Severity.ERROR,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip(),
                    suggestion=(
                        "Validate or escape request data before use (cast, filter_var, "
                        "htmlspecialchars, escapeshellarg, prepared statements), or use "
                        "the framework's request object and APIs."
                    ),
                    tags=["security", "user-input", "php"],
                )
            )
        return findings
