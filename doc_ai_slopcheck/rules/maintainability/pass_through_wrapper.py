from __future__ import annotations

import ast
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule


def _forwarded_call(node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call | None:
    """The call when the body (docstring aside) is `return f(<same params>)`."""
    body = node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(
        getattr(body[0], "value", None), ast.Constant
    ):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return None
    value = body[0].value
    if isinstance(value, ast.Await):
        value = value.value
    if not isinstance(value, ast.Call) or value.keywords:
        return None
    params = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
    args = [a.id if isinstance(a, ast.Name) else None for a in value.args]
    return value if params and args == params else None


class PassThroughWrapperRule(Rule):
    """Functions that only call another function with the same arguments: an
    extra name to read and maintain with no behaviour of its own. Python only.

    Opt-in: frameworks sometimes need a callable of their own (dependency
    providers, hooks), which this rule can't tell apart."""

    rule_id = "pass_through_wrapper"
    title = "Function only forwards its arguments to another call"
    supported_extensions = {".py"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        if not config.rules.pass_through_wrapper.enabled:
            return []
        if not self.applies_to_path(relative_path):
            return []
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Decorated functions (routes, properties, fixtures) and dunders
            # exist for the framework or protocol, not as plain indirection.
            if node.decorator_list or node.name.startswith("__"):
                continue
            call = _forwarded_call(node)
            if call is None:
                continue
            callee = ast.unparse(call.func)
            # Class(...) is a factory; f()(...) / (await x).y binds late or does
            # work first; self._private.y(...) is encapsulation. None are wrappers.
            if (
                callee.split(".")[-1][:1].isupper()
                or not isinstance(call.func, (ast.Name, ast.Attribute))
                or "(" in callee
                or callee.startswith("self._")
            ):
                continue
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=node.lineno,
                    message=(
                        f"`{node.name}` only forwards its arguments to `{callee}`. "
                        "Call it directly unless the extra name is needed."
                    ),
                    severity=Severity.NOTE,
                    confidence=Confidence.MEDIUM,
                    evidence=f"def {node.name}(...): return {callee}(...)",
                    suggestion=f"Replace calls to `{node.name}` with `{callee}`.",
                    tags=["ai-slop", "indirection"],
                )
            )
        return findings
