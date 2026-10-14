from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import php_comments
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Tool directives carry codes (B008, E501, S608) that look like plan IDs.
_DIRECTIVE_RE = re.compile(
    r"(noqa\b.*|type:\s*ignore\S*|pylint:.*|nosec\b.*|pragma:.*|ruff:.*|"
    r"eslint-disable.*|@ts-\S+|slopcheck:.*|NOSONAR.*)",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\b\w+://\S+")
_JS_COMMENT_RE = re.compile(r"(?<![:\w\"'\\])//(.*)|/\*(.*?)\*/", re.DOTALL)
_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"} | PHP_EXTENSIONS


def _python_comments(content: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(content).readline):
            if tok.type == tokenize.COMMENT:
                out.append((tok.start[0], tok.string))
        tree = ast.parse(content)
    except (tokenize.TokenError, SyntaxError, ValueError):
        return out
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.body:
            first = node.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                for offset, line in enumerate(first.value.value.splitlines()):
                    out.append((first.lineno + offset, line))
    return out


def _js_comments(content: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for m in _JS_COMMENT_RE.finditer(content):
        start = content.count("\n", 0, m.start()) + 1
        for offset, line in enumerate((m.group(1) or m.group(2) or "").splitlines()):
            out.append((start + offset, line))
    return out


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
        is_py = relative_path.endswith(".py")
        if is_py:
            comments = _python_comments(content)
        elif Path(relative_path).suffix.lower() in PHP_EXTENSIONS:
            comments = php_comments(content)
        else:
            comments = _js_comments(content)

        hits: list[tuple[int, str, str]] = []  # (line, id, comment)
        for line, text in comments:
            text = _URL_RE.sub("", _DIRECTIVE_RE.sub("", text))
            for pattern in patterns:
                for m in pattern.finditer(text):
                    if m.group(0) not in ignore:
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
