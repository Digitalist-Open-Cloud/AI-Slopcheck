from __future__ import annotations

import re
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.models import Confidence, Finding, Severity
from doc_ai_slopcheck.rules.base import Rule

# Catastrophic backtracking needs a *repeated* group whose iterations can split
# the same text in many ways: (a+)+, (\w+\s?)*, (.*)*. A group with a required
# separator the repeated part cannot match, like (-[a-z0-9]+)*, matches one way.
# ponytail: atom-level heuristic, no full regex parse; alternation groups such
# as (a|ab)* are not analysed.


def _atom_end(body: str, i: int) -> int:
    """Index just past the regex atom starting at body[i]."""
    if body[i] == "\\":
        return i + 2
    if body[i] == "[":
        j = i + 1
        if j < len(body) and body[j] == "^":
            j += 1
        if j < len(body) and body[j] == "]":
            j += 1
        while j < len(body) and body[j] != "]":
            j += 2 if body[j] == "\\" else 1
        return j + 1
    if body[i] == "(":
        depth, j = 0, i
        while j < len(body):
            if body[j] == "\\":
                j += 2
                continue
            depth += {"(": 1, ")": -1}.get(body[j], 0)
            j += 1
            if depth == 0:
                break
        return j
    return i + 1


def _quantifier(body: str, i: int) -> tuple[str, int]:
    """('repeat' | 'optional' | 'once', index after the quantifier) at body[i]."""
    if i >= len(body):
        return "once", i
    ch = body[i]
    if ch in "+*":
        kind, i = "repeat", i + 1
    elif ch == "?":
        kind, i = "optional", i + 1
    elif ch == "{" and (close := body.find("}", i)) != -1:
        lo, _, hi = body[i + 1 : close].partition(",")
        if "," in body[i + 1 : close] and (not hi or hi.strip() != "1"):
            kind = "repeat"
        elif lo.strip() == "0":
            kind = "optional"
        else:
            kind = "once"
        i = close + 1
    else:
        return "once", i
    if i < len(body) and body[i] in "?+":  # lazy / possessive suffix
        i += 1
    return kind, i


def _ambiguous(body: str) -> bool:
    """True if repeating this group body can match the same text many ways."""
    if body.startswith("?"):  # (?:...), (?P<n>...), (?<n>...)
        body = body[2:] if body.startswith("?:") else body[body.find(">") + 1 :]
    repeating: list[str] = []
    separators: list[str] = []
    i = 0
    while i < len(body):
        if body[i] == "|":
            return False
        end = _atom_end(body, i)
        atom = body[i:end]
        kind, i = _quantifier(body, end)
        if kind == "repeat":
            repeating.append(atom)
        elif kind == "once" and atom not in ("^", "$"):
            separators.append(atom)
    if not repeating:
        return False
    if not separators:
        return True
    # `.` also matches the separator (except a newline).
    return "." in repeating and any(sep != "\\n" for sep in separators)


def _find_redos(literal: str) -> bool:
    i = 0
    while i < len(literal):
        ch = literal[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _atom_end(literal, i)
            continue
        if ch == "(":
            end = _atom_end(literal, i)
            kind, _ = _quantifier(literal, end)
            if kind == "repeat" and _ambiguous(literal[i + 1 : end - 1]):
                return True
            i += 1  # also inspect groups nested inside this one
            continue
        i += 1
    return False


# Match string literal delimiters to find context
_STRING_RE = re.compile(r'(?:"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'|`[^`]*`)')


class RegexDosRule(Rule):
    rule_id = "regex_dos"
    title = "Potential ReDoS: regex with nested quantifiers"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.regex_dos
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            # Search within string literals on the line
            for string_m in _STRING_RE.finditer(line):
                literal = string_m.group(0)
                body = literal[1:-1]
                start = string_m.start()
                prefix = line[max(0, start - 2) : start].lower()  # r"", rb"", br""
                is_raw = literal[0] == "`" or "r" in prefix
                if not is_raw:
                    body = body.replace("\\\\", "\\")  # "\\w" in source is regex \w
                if _find_redos(body):
                    evidence = line.strip()
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=(
                                "Regex with nested quantifiers detected. "
                                "Patterns like (a+)+ can cause catastrophic backtracking "
                                "(ReDoS) on adversarial input."
                            ),
                            severity=Severity.WARNING,
                            confidence=Confidence.MEDIUM,
                            evidence=evidence,
                            suggestion=(
                                "Rewrite the regex to avoid nested quantifiers. "
                                "Use possessive quantifiers or atomic groups where available, "
                                "or validate input length before applying the regex."
                            ),
                            tags=["security", "regex", "dos"],
                        )
                    )
                    break  # One finding per line is enough

        return findings
