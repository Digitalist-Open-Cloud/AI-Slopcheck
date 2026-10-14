from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import is_in_non_code_context
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS, is_ignored
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

_DEBUG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bdebugger\b"), "debugger statement"),
    (re.compile(r"\bbreakpoint\s*\(\s*\)"), "breakpoint() call"),
    (re.compile(r"\bpdb\.set_trace\s*\(\s*\)"), "pdb.set_trace()"),
    (re.compile(r"\bconsole\.debug\s*\("), "console.debug("),
    (re.compile(r"\bbinding\.pry\b"), "binding.pry"),
    (re.compile(r"^\s*import\s+pdb\b"), "import pdb"),
    (re.compile(r"^\s*import\s+ipdb\b"), "import ipdb"),
]

# PHP dumps, plus Drupal devel and Laravel/Symfony helpers. The lookbehind
# skips methods ($logger->dump) and longer names (my_dpm).
_PHP_CALL = r"(?<![\w>:$\\])(?<!function )"
_PHP_DEBUG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(_PHP_CALL + r"var_dump\s*\("), "var_dump()"),
    (re.compile(_PHP_CALL + r"(print_r|var_export)\s*\("
                r"(?![^;]*,\s*(?:\$\w+\s*=\s*)?(?i:true|1)\s*\))"),
     "print_r()/var_export() output"),
    (re.compile(_PHP_CALL + r"(dd|dump|dpm|dsm|dvm|kpr|kint|ksm|xdebug_break)\s*\("),
     "debug helper call"),
    (re.compile(_PHP_CALL + r"debug_zval_dump\s*\("), "debug_zval_dump()"),
]



class DebugCodeLeftRule(Rule):
    rule_id = "debug_code_left"
    title = "Debug statement left in code"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"} | PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.debug_code_left
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        if is_ignored(relative_path, config.test_paths):
            return []

        patterns = _DEBUG_PATTERNS
        lang = "generic"
        if Path(relative_path).suffix.lower() in PHP_EXTENSIONS:
            patterns = _DEBUG_PATTERNS + _PHP_DEBUG_PATTERNS
            lang = "php"
        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            for pattern, label in patterns:
                m = pattern.search(line)
                if m and not is_in_non_code_context(line, m.start(), lang):
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=f"Debug statement left in code: {label}.",
                            severity=Severity.WARNING,
                            confidence=Confidence.HIGH,
                            evidence=line.strip(),
                            suggestion="Remove debug statements before committing.",
                            tags=["debug", "cleanup"],
                        )
                    )
                    break

        return findings
