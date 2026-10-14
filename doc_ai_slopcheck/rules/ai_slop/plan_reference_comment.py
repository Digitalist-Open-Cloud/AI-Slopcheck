from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import comments_for
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Tool directives carry codes (B008, E501, S608) that look like plan IDs.
_DIRECTIVE_RE = re.compile(
    r"(noqa\b.*|type:\s*ignore\S*|pylint:.*|nosec\b.*|pragma:.*|ruff:.*|"
    r"eslint-disable.*|@ts-\S+|slopcheck:.*|NOSONAR.*)",
    re.IGNORECASE,
)
# In PHP files, D7/D8/D10 are Drupal major versions, not plan IDs.
_DRUPAL_VERSION_RE = re.compile(r"^D(?:[5-9]|1[0-3])$")
_URL_RE = re.compile(r"\b\w+://\S+")
_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"} | PHP_EXTENSIONS





class PlanReferenceCommentRule(Rule):
    rule_id = "plan_reference_comment"
    code_only = False
    title = "Plan or task ID in comment"
    supported_extensions = _EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.plan_reference_comment
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        patterns = [re.compile(p) for p in rule_config.patterns]
        ignore = set(rule_config.ignore)
        ext = Path(relative_path).suffix.lower()
        is_php = ext in PHP_EXTENSIONS
        comments = comments_for(content, ext)

        hits: list[tuple[int, str, str]] = []  # (line, id, comment)
        for line, text in comments:
            text = _URL_RE.sub("", _DIRECTIVE_RE.sub("", text))
            for pattern in patterns:
                for m in pattern.finditer(text):
                    if m.group(0) in ignore or (is_php and _DRUPAL_VERSION_RE.match(m.group(0))):
                        continue
                    hits.append((line, m.group(0), text.strip(" #*/")))
        if not hits:
            return []

        hits.sort()
        ids = list(dict.fromkeys(h[1] for h in hits))
        shown = ", ".join(ids[:6]) + (f" and {len(ids) - 6} more" if len(ids) > 6 else "")
        return [
            self.build_finding(
                relative_path=relative_path,
                line=hits[0][0],
                message=(
                    f"{len(hits)} plan/task reference{'s' if len(hits) > 1 else ''} in "
                    f"comments ({shown}). IDs from a plan or ticket mean nothing to "
                    "readers without that document and go stale as the plan moves on."
                ),
                severity=Severity.NOTE,
                confidence=Confidence.MEDIUM,
                evidence=hits[0][2][:200],
                suggestion=(
                    "Say why the code is the way it is in plain words; keep plan and "
                    "ticket history in commit messages, PRs or decision records."
                ),
                tags=["ai-slop", "comments"],
            )
        ]
