"""Cross-file duplicate code detection (copy-paste blocks).

Works on normalised lines: whitespace collapsed, blank and comment-only lines
dropped. A block is reported when a window of `min_lines` normalised lines
appears in more than one place; consecutive duplicated windows merge into one
finding per copy.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from doc_ai_slopcheck.config import DuplicateCodeConfig
from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS
from doc_ai_slopcheck.engine.suppression import is_suppressed, parse_suppressions
from doc_ai_slopcheck.models import Confidence, Finding, Location, Severity
from doc_ai_slopcheck.rules.base import Rule

RULE_ID = "duplicate_code"
TITLE = "Duplicated code block"

_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".java", ".rb",
}) | PHP_EXTENSIONS
_COMMENT_RE = re.compile(r"^(#|//|/\*|\*|\"\"\"|''')")
_IMPORT_RE = re.compile(
    r"^(import\s|from\s.+\simport\b|\}?\s*from\s+['\"]|export\s.*\sfrom\s"
    r"|use\s+[\\\w]|namespace\s)"  # PHP
)
_WS_RE = re.compile(r"\s+")
_MAX_LINE = 400  # minified/generated lines are not hand-written copies


def _normalise(content: str) -> list[tuple[int, str]]:
    """(original line number, normalised text) for lines worth comparing."""
    out = []
    for lineno, raw in enumerate(content.splitlines(), start=1):
        line = _WS_RE.sub(" ", raw.strip())
        if not line or len(line) > _MAX_LINE or _COMMENT_RE.match(line):
            continue
        out.append((lineno, line))
    return out


def find_duplicates(
    repo_root: Path, files: list[Path], config: DuplicateCodeConfig
) -> tuple[list[Finding], int]:
    """Return (findings, suppressed_count)."""
    if not config.enabled:
        return [], 0

    n = config.min_lines
    normalised: dict[str, list[tuple[int, str]]] = {}
    contents: dict[str, str] = {}
    windows: dict[int, list[tuple[str, int]]] = defaultdict(list)

    for path in files:
        if path.suffix.lower() not in _EXTENSIONS:
            continue
        rel = path.relative_to(repo_root).as_posix()
        content = path.read_text(encoding="utf-8", errors="ignore")
        lines = _normalise(content)
        if len(lines) < n:
            continue
        normalised[rel] = lines
        contents[rel] = content
        for i in range(len(lines) - n + 1):
            text = [t for _, t in lines[i : i + n]]
            if sum(map(len, text)) < config.min_chars:
                continue
            if all(_IMPORT_RE.match(t) for t in text):
                continue
            windows[hash(tuple(text))].append((rel, i))

    # For each file: window index -> other places the same window appears.
    dup: dict[str, dict[int, list[tuple[str, int]]]] = defaultdict(dict)
    for places in windows.values():
        if len(places) < 2:
            continue
        for rel, i in places:
            others = [
                (r, j) for r, j in places if r != rel or abs(j - i) >= n
            ]
            if others:
                dup[rel][i] = others

    # Group runs of consecutive duplicated windows by (file, partner file).
    # Each pair is reported once, on the later path; with N copies of a block
    # that gives N-1 findings, each pointing back at the first copy.
    groups: dict[tuple[str, str], list[tuple[int, int, str, int]]] = defaultdict(list)
    suppressed = 0
    for rel, by_index in dup.items():
        lines = normalised[rel]
        suppressions = parse_suppressions(contents[rel])
        starts = sorted(by_index)
        run_start = prev = starts[0]
        for i in starts[1:] + [None]:
            if i is not None and i == prev + 1:
                prev = i
                continue
            others = by_index[run_start]
            partner = min(r for r, _ in others)
            first_line = lines[run_start][0]
            if rel < partner:
                pass
            elif is_suppressed(suppressions, first_line, RULE_ID):
                suppressed += 1
            else:
                groups[(rel, partner)].append((
                    first_line,
                    lines[prev + n - 1][0],
                    "\n".join(t for _, t in lines[run_start : prev + n]),
                    len({r for r, _ in others}) - 1,
                ))
            if i is not None:
                run_start = prev = i

    findings: list[Finding] = []
    for (rel, partner), runs in groups.items():
        spans: list[list[int]] = []
        for first, last, _, _ in runs:  # runs are in line order; merge overlaps
            if spans and first <= spans[-1][1] + 1:
                spans[-1][1] = max(spans[-1][1], last)
            else:
                spans.append([first, last])
        total = sum(last - first + 1 for first, last in spans)
        ranges = ", ".join(f"{first}-{last}" for first, last in spans[:5])
        if len(spans) > 5:
            ranges += f" and {len(spans) - 5} more"
        where = "elsewhere in this file" if partner == rel else f"in {partner}"
        extra = max(e for *_, e in runs)
        also = f" (and {extra} other file{'s' if extra > 1 else ''})" if extra else ""
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                message=f"{total} lines (lines {ranges}) duplicate code {where}{also}.",
                severity=Severity.NOTE,
                confidence=Confidence.HIGH,
                location=Location(path=rel, line=runs[0][0], end_line=runs[-1][1]),
                fingerprint=Rule.fingerprint(
                    RULE_ID, rel, partner, *(block for _, _, block, _ in runs)
                ),
                suggestion="Extract the shared code into one function or module.",
                evidence=runs[0][2].split("\n", 1)[0],
                tags=["duplication", "dry"],
            )
        )

    return findings, suppressed
