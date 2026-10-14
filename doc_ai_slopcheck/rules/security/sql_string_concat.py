from __future__ import annotations

import ast
import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Two-stage detection: first check for SQL keyword, then for concatenation.
_SQL_KEYWORD_RE = re.compile(
    r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s",
    re.IGNORECASE,
)

# Concatenation indicators on the same line as SQL.
# Each alternative requires the operator to appear *after* a closing quote so
# that bare %s placeholders inside a parameterised query are not flagged.
_CONCAT_INDICATOR_RE = re.compile(
    r"""(?:"""
    r"""["']\s*\+\s*\w"""  # "sql " + var  (concat after closing quote)
    r"""|f["'][^"']*\{[^}]+\}"""  # f"sql {var}"  (f-string)
    r"""|["'][^"'"]*['"]\s*%\s*[\w(]"""  # "sql" % var  (% after closing quote)
    r"""|["'][^"'"]*['"]\s*\.\s*format\s*\("""  # "sql".format(
    r")"
)

# Python: the literal text of a dynamically built string must read as a SQL
# statement, not just mention a keyword ("unexpected UPDATE on {t}").
_SQL_STATEMENT_RE = re.compile(
    r"\bSELECT\b.+\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\s+\S+\s+SET\b|"
    r"\bDELETE\s+FROM\b|\bDROP\s+(?:TABLE|SCHEMA|INDEX|VIEW|TRIGGER|DATABASE)\b",
    re.IGNORECASE | re.DOTALL,
)
# Same check already reviewed and waived for ruff (S608) or Bandit (B608).
_REVIEWED_RE = re.compile(r"(?:noqa|nosec)\b[^#]*\b[SB]608\b")
_CONSTANT_RE = re.compile(r"^_*[A-Z][A-Z0-9_]*$")


def _is_constant(node: ast.expr) -> bool:
    """Module-level UPPER_CASE names (table names, column lists) are not user input."""
    if isinstance(node, ast.Name):
        return bool(_CONSTANT_RE.match(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_CONSTANT_RE.match(node.attr))
    return isinstance(node, ast.Constant)


def _dynamic_sql(node: ast.AST) -> bool:
    """True if node builds a string from literal SQL plus non-constant values."""
    literal: list[str] = []
    values: list[ast.expr] = []
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant):
                literal.append(str(part.value))
            else:
                values.append(part.value)  # FormattedValue
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        for side in (node.left, node.right):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                literal.append(side.value)
            elif isinstance(side, ast.Tuple):
                values.extend(side.elts)
            else:
                values.append(side)
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    ):
        literal.append(node.func.value.value)
        values.extend(node.args)
        values.extend(kw.value for kw in node.keywords)
    else:
        return False
    if not values or all(_is_constant(v) for v in values):
        return False
    return bool(_SQL_STATEMENT_RE.search(" ".join(literal)))


# PHP: `.` concatenation with a variable, or "$var"/"{$var}" interpolation in a
# double-quoted string. Drupal's {table} prefix placeholders are not interpolation.
_PHP_CONCAT_RE = re.compile(
    r"""["']\s*\.\s*\$"""  # "sql " . $var
    r"""|\$[\w\->\[\]'"]+\s*\.\s*["']"""  # $var . " sql"
    r'|"[^"]*(?:\$\w|\{\$)[^"]*"'  # "sql $var" / "sql {$var}"
)


# Where a value is spliced in: PHP "$x"/"{$x}", JS "${x}", Python f"{x}", or a
# closing quote followed by + / . concatenation.
_INSERTION_RE = re.compile(r"""\{\$|\$\{|\$\w|\{\w[^{}]*\}|['"`]\s*[.+]\s*[^\s'"]""")
# Text right before an insertion that puts it in a table/column name position.
_NAME_POSITION_RE = re.compile(
    r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE|EXISTS|SELECT(?:\s+DISTINCT)?)[\s`\"'(.+{$]*$",
    re.IGNORECASE,
)


_SQL_END_RE = re.compile(r"""["'`]\s*,""")
# Class or global constants (Writer::DONE, MAX_ROWS) can't carry user input.
_CONSTANT_EXPR_RE = re.compile(r"\s*(?:[\w\\]*::)?[A-Z_][A-Z0-9_]*\b(?!\s*\()")
_SQL_START_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b", re.IGNORECASE)


def _names_only(line: str) -> bool:
    """True if every spliced-in value sits where a table/column name goes,
    e.g. "SELECT * FROM $table WHERE id = ?"; values are then bound."""
    sql_start = _SQL_START_RE.search(line)
    if not sql_start:
        return False
    # The SQL text ends at a closing quote followed by a comma; what follows
    # ("...= ?", $login) are bound parameters, not spliced-in values.
    end = _SQL_END_RE.search(line, sql_start.start())
    stop = end.start() if end else len(line)
    sites = [
        m for m in _INSERTION_RE.finditer(line, sql_start.start(), stop)
        if not _CONSTANT_EXPR_RE.match(line, m.end() - 1)
    ]
    return bool(sites) and all(_NAME_POSITION_RE.search(line[: m.start()]) for m in sites)


class SqlStringConcatRule(Rule):
    rule_id = "sql_string_concat"
    title = "SQL built by string concatenation"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"} | PHP_EXTENSIONS

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.sql_string_concat
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        lines = content.splitlines()
        if relative_path.endswith(".py"):
            try:
                tree = ast.parse(content)
            except (SyntaxError, ValueError):
                return []
            # Report the outermost dynamic node only ("a" + b + "c" nests BinOps).
            flagged: set[int] = set()
            hit_lines: list[int] = []
            for node in ast.walk(tree):
                if id(node) in flagged or not _dynamic_sql(node):
                    continue
                flagged.update(id(child) for child in ast.walk(node))
                hit_lines.append(node.lineno)
        else:
            concat_re = (
                _PHP_CONCAT_RE
                if Path(relative_path).suffix.lower() in PHP_EXTENSIONS
                else _CONCAT_INDICATOR_RE
            )
            hit_lines = [
                lineno
                for lineno, line in enumerate(lines, start=1)
                if _SQL_STATEMENT_RE.search(line) and concat_re.search(line)
            ]

        findings: list[Finding] = []
        for lineno in sorted(set(hit_lines)):
            evidence = lines[lineno - 1].strip()
            if _REVIEWED_RE.search(evidence):
                continue
            if _names_only(evidence):
                severity = Severity.WARNING
                message = (
                    "SQL table or column name built from a variable. Names can't be "
                    "bound as parameters, so check the value comes from a fixed list."
                )
                suggestion = (
                    "Validate the name against an allow-list, or quote it as an identifier."
                )
            else:
                severity = Severity.ERROR
                message = (
                    "SQL query built via string concatenation or interpolation. "
                    "This is a SQL injection risk."
                )
                suggestion = (
                    "Use parameterised queries or a query builder. "
                    "Never concatenate user input into SQL strings."
                )
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=message,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    evidence=evidence,
                    suggestion=suggestion,
                    tags=["sql-injection", "security"],
                )
            )
        return findings
