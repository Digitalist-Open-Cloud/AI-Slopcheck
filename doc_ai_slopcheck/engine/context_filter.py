"""Lightweight string/comment context detector.

Determines if a regex match position falls inside a string literal,
comment, or regex literal — without requiring tree-sitter or any
external dependency. Uses a single-pass character scanner.
"""
from __future__ import annotations

import io
import re
import tokenize
from bisect import bisect_right
from functools import lru_cache

from doc_ai_slopcheck.engine.repo_files import PHP_EXTENSIONS

_JS_REGEX_PREV = frozenset("=([,!&|:?{;+-*/%^~<>")


def is_in_non_code_context(
    line: str, match_start: int, lang: str = "generic"
) -> bool:
    """Return True if match_start is inside a string, comment, or regex.

    lang: "py" | "js" | "go" | "generic"
    Does NOT track multi-line state (triple-quotes, /* */) across lines.
    Callers must handle cross-line block comments separately.
    """
    state = "code"
    quote_char = ""
    i = 0
    n = len(line)

    while i < match_start:
        ch = line[i]
        nxt = line[i + 1] if i + 1 < n else ""

        if state == "code":
            if ch == "#" and (lang in ("py", "generic") or (lang == "php" and nxt != "[")):
                return True  # rest of line is comment
            if ch == "/" and nxt == "/" and lang in ("js", "go", "php", "generic"):
                return True  # rest of line is comment
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch in ('"', "'"):
                state = "string"
                quote_char = ch
                i += 1
                continue
            if ch == "`" and lang in ("js", "generic"):
                state = "template"
                i += 1
                continue
            if ch == "/" and lang in ("js", "generic"):
                prev = line[:i].rstrip()
                if not prev or prev[-1] in _JS_REGEX_PREV:
                    state = "regex"
                    i += 1
                    continue
        elif state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == quote_char:
                state = "code"
                quote_char = ""
        elif state == "template":
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                state = "code"
        elif state == "regex":
            if ch == "\\":
                i += 2
                continue
            if ch == "/":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
                continue

        i += 1

    return state != "code"


_C_STYLE_EXTENSIONS = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt",
    ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".scala",
})
_NON_CODE_TOKENS = frozenset({
    tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
    tokenize.DEDENT, tokenize.ENDMARKER,
})


_NON_SPACE_RUN_RE = re.compile(r"\S+")


@lru_cache(maxsize=32)
def non_code_lines(content: str, ext: str) -> frozenset[int]:
    """1-indexed lines that hold only comments or docstrings (no code).

    Covers multi-line docstrings and /* */ blocks, which is_in_non_code_context
    cannot see. Unknown file types and unparseable Python return an empty set.
    """
    if ext == ".py":
        return frozenset(_python_non_code_lines(content))
    if ext in PHP_EXTENSIONS:
        return frozenset(_php_non_code_lines(content))
    if ext in _C_STYLE_EXTENSIONS:
        return frozenset(_c_style_non_code_lines(content))
    return frozenset()


def _python_non_code_lines(content: str) -> set[int]:
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
    except (tokenize.TokenError, SyntaxError):
        return set()

    code: set[int] = set()
    significant = [t for t in tokens if t.type not in (tokenize.COMMENT, tokenize.NL)]
    for k, tok in enumerate(significant):
        if tok.type in _NON_CODE_TOKENS:
            continue
        if tok.type == tokenize.STRING:
            before = significant[k - 1].type if k else tokenize.NEWLINE
            after = significant[k + 1].type if k + 1 < len(significant) else tokenize.ENDMARKER
            standalone = before in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT) and (
                after in (tokenize.NEWLINE, tokenize.ENDMARKER)
            )
            if standalone:  # docstring or bare string statement
                continue
        code.update(range(tok.start[0], tok.end[0] + 1))

    lines = content.splitlines()
    return {i for i, line in enumerate(lines, start=1) if line.strip() and i not in code}


def _c_style_non_code_lines(content: str) -> set[int]:
    # ponytail: no regex-literal tracking; a regex containing quotes or /* can
    # mis-mark a line. Strings reset at newline (except backtick strings).
    code: set[int] = set()
    state = "code"
    quote = ""
    line = 1
    i, n = 0, len(content)
    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""
        if ch == "\n":
            line += 1
            if state == "line_comment" or (state == "string" and quote != "`"):
                state = "code"
            i += 1
            continue
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch in "\"'`":
                state, quote = "string", ch
            if not ch.isspace():
                code.add(line)
        elif state == "string":
            code.add(line)
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                state = "code"
        elif state == "block_comment" and ch == "*" and nxt == "/":
            state = "code"
            i += 2
            continue
        i += 1

    lines = content.splitlines()
    return {i for i, text in enumerate(lines, start=1) if text.strip() and i not in code}


# One alternative per PHP construct that is not plain code; matched left to right.
_PHP_TOKEN_RE = re.compile(
    r"(?P<comment>//.*?(?=\?>|$)|\#(?!\[).*?(?=\?>|$)|/\*.*?(?:\*/|\Z))"
    r"|(?P<string>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"
    r"|<<<[ \t]*['\"]?(?P<tag>\w+)['\"]?[ \t]*\n.*?^[ \t]*(?P=tag)\b)"
    r"|(?P<close>\?>)",
    re.MULTILINE | re.DOTALL,
)
_PHP_OPEN_RE = re.compile(r"<\?(?:php\b|=)")


def _php_spans(content: str):
    """Yield (kind, start, end) with kind in code/comment/string/html, in order."""
    pos, n = 0, len(content)
    while pos < n:
        opener = _PHP_OPEN_RE.search(content, pos)
        if not opener:
            yield "html", pos, n
            return
        yield "html", pos, opener.start()
        yield "code", opener.start(), opener.end()
        pos = opener.end()
        while pos < n:
            m = _PHP_TOKEN_RE.search(content, pos)
            if not m:
                yield "code", pos, n
                return
            yield "code", pos, m.start()
            pos = m.end()
            if m.lastgroup == "close":
                break
            yield ("comment" if m.group("comment") else "string"), m.start(), m.end()


def _line_index(content: str):
    starts = [0] + [i + 1 for i, ch in enumerate(content) if ch == "\n"]
    return lambda pos: bisect_right(starts, pos)


def _php_non_code_lines(content: str) -> set[int]:
    """Lines with only comments or inline HTML (outside <?php ... ?>).

    `#[...]` attributes, strings, heredoc/nowdoc and code count as code.
    """
    line_of = _line_index(content)
    code: set[int] = set()
    for kind, start, end in _php_spans(content):
        if kind == "string":
            code.update(range(line_of(start), line_of(end - 1) + 1))
        elif kind == "code":
            for m in _NON_SPACE_RUN_RE.finditer(content, start, end):
                code.update(range(line_of(m.start()), line_of(m.end() - 1) + 1))
    lines = content.splitlines()
    return {i for i, text in enumerate(lines, start=1) if text.strip() and i not in code}


def php_comments(content: str) -> list[tuple[int, str]]:
    """(line, text) for every line of every PHP comment."""
    line_of = _line_index(content)
    out: list[tuple[int, str]] = []
    for kind, start, end in _php_spans(content):
        if kind == "comment":
            first = line_of(start)
            out.extend(
                (first + k, text) for k, text in enumerate(content[start:end].splitlines())
            )
    return out


# C-style comments and strings, matched left to right so comment markers inside
# strings ('http://', "/*") are skipped. Line comments stop at the newline.
_C_TOKEN_RE = re.compile(
    r"(?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))"
    r"|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`",
    re.DOTALL,
)


def c_style_comments(content: str) -> list[tuple[int, str]]:
    """(line, text) for every line of every // or /* */ comment."""
    line_of = _line_index(content)
    out: list[tuple[int, str]] = []
    for m in _C_TOKEN_RE.finditer(content):
        if m.group("comment"):
            first = line_of(m.start())
            out.extend((first + k, text) for k, text in enumerate(m.group(0).splitlines()))
    return out
