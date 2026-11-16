from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Where the HTML value starts, for each DOM sink.
_SINK_RE = re.compile(
    r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)"  # el.innerHTML = value
    r"|\.insertAdjacentHTML\(\s*[^,]+,"  # el.insertAdjacentHTML(pos, value)
    r"|\bdocument\.write(?:ln)?\("  # document.write(value)
)
# A constant value: a plain string, or a template literal without ${...}.
_STATIC_RE = re.compile(r"""\s*(?:'[^'\n]*'|"[^"\n]*"|`[^`$]*`)\s*(?:[;),:]|$)""", re.MULTILINE)
# Names that suggest the value came from a request, a response or a user.
_EXTERNAL_RE = re.compile(
    r"\b(?:req|request|res|response|data|params?|query|body|input|value|user|message|"
    r"content|html|payload|result|json|text|name|title|description|comment)\b"
)
_STATEMENT_END_RE = re.compile(r"[;\n]")


class InnerHtmlAssignmentRule(Rule):
    """Raw HTML written into the DOM from a variable (innerHTML, outerHTML,
    insertAdjacentHTML, document.write). Constant markup is fine."""

    rule_id = "inner_html_assignment"
    title = "Dynamic HTML written into the DOM"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        if not config.rules.inner_html_assignment.enabled:
            return []
        if not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for m in _SINK_RE.finditer(content):
            if _STATIC_RE.match(content, m.end()):
                continue
            lineno = content.count("\n", 0, m.start()) + 1
            end = _STATEMENT_END_RE.search(content, m.end())
            value = content[m.end() : end.start() if end else m.end() + 300]
            external = bool(_EXTERNAL_RE.search(value))
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=(
                        "HTML built from a variable is written into the DOM. If any part "
                        "comes from users or an API, this is a cross-site scripting risk."
                    ),
                    severity=Severity.ERROR if external else Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=content.splitlines()[lineno - 1].strip()[:200],
                    suggestion=(
                        "Use textContent or DOM APIs (createElement, append) for text, or "
                        "sanitize the HTML (e.g. DOMPurify) before inserting it."
                    ),
                    tags=["security", "xss"],
                )
            )
        return findings
