from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig, RegexDosConfig
from doc_ai_slopcheck.rules.generic.regex_dos import RegexDosRule


def _scan(content: str, path: str = "src/validate.py") -> list:
    rule = RegexDosRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_nested_plus_quantifier() -> None:
    code = 're.compile("(a+)+")\n'
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "regex_dos"


def test_detects_nested_star_quantifier() -> None:
    code = 're.compile("(a*)+")\n'
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_non_capturing_nested() -> None:
    code = 'pattern = "(?:\\\\w+\\\\s?)+$";\n'
    findings = _scan(code, path="src/validate.ts")
    assert len(findings) == 1


def test_allows_simple_pattern() -> None:
    code = 're.compile(r"^[a-z]+$")\n'
    findings = _scan(code)
    assert len(findings) == 0


def test_allows_simple_repetition() -> None:
    code = 're.compile(r"a{3,5}")\n'
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_in_js_file() -> None:
    code = 'const re = new RegExp("(x+)+");\n'
    findings = _scan(code, path="src/parser.js")
    assert len(findings) == 1


def test_skips_unsupported_extension() -> None:
    rule = RegexDosRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/code.rb",
        content='r = Regexp.new("(a+)+")\n',
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.regex_dos = RegexDosConfig(enabled=False)
    rule = RegexDosRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/validate.py",
        content='re.compile("(a+)+")\n',
        config=config,
    )
    assert len(findings) == 0


def test_flags_dot_star_and_open_counted_repeats() -> None:
    assert len(_scan('re.compile(r"^(.*,)*x$")\n')) == 1
    assert len(_scan('re.compile(r"(\\d+){2,}")\n')) == 1


def test_allows_unambiguous_repeated_groups() -> None:
    """Patterns from a real codebase that were flagged before but cannot backtrack."""
    code = (
        're.compile(r"^k[0-9]+-[0-9]{4}-[0-9]{2}(-[0-9]+)?$")\n'  # optional, not repeated
        're.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")\n'  # '-' separates iterations
        're.compile(r"^service:\\n(?:.*\\n)*?\\s+port")\n'  # '.' never matches \\n
        're.compile(r"(\\d+\\.)*\\d+")\n'
        '"(rad på formen `*Verifierad YYYY-MM-DD (...)*`)"\n'  # prose, no quantifier inside
    )
    assert _scan(code) == []
