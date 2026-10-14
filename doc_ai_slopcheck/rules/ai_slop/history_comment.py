from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import comments_for
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule


class HistoryCommentRule(Rule):
    """Comments that narrate how the code used to be: a changelog kept in the
    source. That history belongs in commits, PRs or decision records."""

    rule_id = "history_comment"
    code_only = False
    title = "Comment narrates code history"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"} | PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.history_comment
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        pattern = re.compile("|".join(f"(?:{p})" for p in rule_config.patterns), re.IGNORECASE)
        hits = [
            (line, m.group(0), text.strip(" #*/"))
            for line, text in comments_for(content, Path(relative_path).suffix.lower())
            if (m := pattern.search(text))
        ]
        if not hits:
            return []

        phrases = list(dict.fromkeys(h[1].lower() for h in hits))
        return [
            self.build_finding(
                relative_path=relative_path,
                line=hits[0][0],
                message=(
                    f"{len(hits)} comment line{'s' if len(hits) > 1 else ''} describe how the "
                    f"code used to be ({', '.join(repr(p) for p in phrases[:4])}). History "
                    "goes stale and buries what the code does now."
                ),
                severity=Severity.NOTE,
                confidence=Confidence.MEDIUM,
                evidence=hits[0][2][:200],
                suggestion=(
                    "Describe the current behaviour and why; keep the history in commit "
                    "messages, PRs or decision records."
                ),
                tags=["ai-slop", "comments"],
            )
        ]
