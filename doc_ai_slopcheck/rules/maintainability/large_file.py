from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.repo_files import DEFAULT_CODE_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule


class LargeFileRule(Rule):
    rule_id = "large_file"
    title = "File exceeds recommended line count"
    supported_extensions = DEFAULT_CODE_EXTENSIONS - {".md"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.large_file
        if not rule_config.enabled:
            return []

        if not self.applies_to_path(relative_path):
            return []

        lines = content.splitlines()
        count = len(lines)
        if count <= rule_config.max_lines:
            return []

        return [
            self.build_finding(
                relative_path=relative_path,
                line=1,
                message=(
                    f"File has {count} lines, exceeding the limit of "
                    f"{rule_config.max_lines}. Consider splitting it."
                ),
                severity=Severity.NOTE,
                confidence=Confidence.HIGH,
                evidence=f"{count} lines",
                suggestion=(
                    "Split the file into smaller modules with focused responsibilities."
                ),
                tags=["large-file", "maintainability"],
            )
        ]
