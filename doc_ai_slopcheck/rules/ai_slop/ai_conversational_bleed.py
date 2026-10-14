from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import non_code_lines
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Chat-style phrases that LLMs prepend to code output — never appear in human-written source.
CHAT_PHRASE_RE = re.compile(
    r"^(?:Here(?:'s| is) (?:the|an?|my|your) "
    r"(?:updated?|modified|complete|corrected|revised|new)?\s*"
    r"(?:code|implementation|solution|version|function|class|file|example|snippet))"
    r"|^(?:Certainly!|Sure!|Sure,?\s+(?:here|I can|let me))"
    r"|^(?:As requested,|As you asked,|I've (?:created|written|implemented|updated|modified))"
    r"|^(?:Let me (?:help|show|create|write|implement|fix|update))"
    r"|^(?:I'll (?:help|create|write|implement|fix|update))",
    re.IGNORECASE,
)

# Markdown code fences that should never appear in production source files
CODE_FENCE_RE = re.compile(
    r"^```(?:python|javascript|typescript|js|ts|java|go|rust|kotlin|csharp|c\+\+|cpp|ruby"
    r"|php|swift|scala|bash|sh|shell|sql|html|css|json|yaml|yml|toml|xml)?\s*$"
)


# Pictographs, plus the dingbats chat output favours (✅ ❌ ⚠️ ✨ ⭐ ✔ ➡).
_EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF\u2705\u274C\u26A0\u2728\u2B50\u2714\u27A1]")
_MESSAGE_RE = re.compile(
    r"\b(?:print|console\.\w+|log(?:ger)?\.\w+|logging\.\w+|error_log|Drupal::logger"
    r"|raise|throw)\b"
)


class AiConversationalBleedRule(Rule):
    rule_id = "ai_conversational_bleed"
    code_only = False
    title = "AI conversational text in source"
    # Restrict to source code files — not documentation (.md, .rst, .txt)
    supported_extensions = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs",
        ".java", ".kt", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp",
    } | PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.ai_conversational_bleed
        if not rule_config.enabled:
            return []

        # Skip prompt templates and AI-related content files
        lower_path = relative_path.lower()
        if any(
            seg in lower_path
            for seg in (
                "prompt", "template", "example", "fixture", "test",
                "generator", "dataset", "sample",
            )
        ):
            return []

        # Fences inside docstrings/comments are Markdown docs, not chat bleed.
        prose_lines = non_code_lines(content, Path(relative_path).suffix.lower())
        findings: list[Finding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue

            match = CHAT_PHRASE_RE.search(stripped)
            if match:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=line_number,
                        message=(
                            f"AI conversational text found: `{stripped[:80]}`. "
                            "This appears to be copy-pasted from an AI chat session."
                        ),
                        severity=Severity.ERROR,
                        confidence=Confidence.HIGH,
                        evidence=stripped[:120],
                        suggestion="Remove the conversational text and keep only the code.",
                        tags=["ai-bleed", "copy-paste"],
                    )
                )
                continue

            if CODE_FENCE_RE.match(stripped) and line_number not in prose_lines:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=line_number,
                        message=(
                            f"Markdown code fence found in source: `{stripped}`. "
                            "This was likely copy-pasted from an AI response."
                        ),
                        severity=Severity.ERROR,
                        confidence=Confidence.HIGH,
                        evidence=stripped,
                        suggestion="Remove the markdown fence — only the code should remain.",
                        tags=["ai-bleed", "markdown"],
                    )
                )

            # Emoji in comments, docstrings and log/error messages is chat
            # styling; in UI text it can be deliberate, so that is left alone.
            if _EMOJI_RE.search(line) and (
                line_number in prose_lines or _MESSAGE_RE.search(line)
            ):
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=line_number,
                        message="Emoji in a comment or log/error message, a chat-style habit.",
                        severity=Severity.NOTE,
                        confidence=Confidence.HIGH,
                        evidence=stripped[:120],
                        suggestion="Say it in words: 'Warning:', 'Done', 'Failed'.",
                        tags=["ai-bleed", "emoji"],
                    )
                )

        return findings
