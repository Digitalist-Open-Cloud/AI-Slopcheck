"""Scanner-level noise filters: comment/docstring lines and test-code severity."""

from __future__ import annotations

from pathlib import Path

import pytest

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import non_code_lines
from doc_ai_slopcheck.engine.scanner import scan_paths


def test_python_non_code_lines() -> None:
    code = (
        '"""Module doc.\n'  # 1
        "\n"  # 2
        "```python\n"  # 3
        '"""\n'  # 4
        "x = 1  # trailing\n"  # 5
        "# only comment\n"  # 6
        's = """not a\n'  # 7
        'docstring"""\n'  # 8
    )
    assert non_code_lines(code, ".py") == {1, 3, 4, 6}


def test_c_style_non_code_lines() -> None:
    code = (
        "/*\n"  # 1
        " * never dangerouslySetInnerHTML\n"  # 2
        " */\n"  # 3
        'const url = "https://x.y"; // ok\n'  # 4
        "// only comment\n"  # 5
        "const t = `multi\n"  # 6
        "// inside template`;\n"  # 7
    )
    assert non_code_lines(code, ".tsx") == {1, 2, 3, 5}


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def test_code_rules_skip_comment_lines_but_comment_rules_do_not(tmp_path: Path) -> None:
    root = _repo(tmp_path, {
        "src/Markdown.tsx": (
            "/*\n"
            " * Never use dangerouslySetInnerHTML on model output.\n"
            " * TODO: remove this component\n"
            " */\n"
            "export const A = () => null;\n"
        ),
    })
    result = scan_paths(repo_root=root, targets=None, config=AppConfig())
    rule_ids = {f.rule_id for f in result.findings}
    assert "js_dangerously_set_html" not in rule_ids
    assert "placeholder_tokens" in rule_ids


def test_test_code_is_downgraded_one_level(tmp_path: Path) -> None:
    sql = 'q = "SELECT * FROM users WHERE id = " + user_id\n'
    root = _repo(tmp_path, {"app/db.py": sql, "app/tests/test_db.py": sql})
    result = scan_paths(repo_root=root, targets=None, config=AppConfig())
    by_path = {f.location.path: f for f in result.findings if f.rule_id == "sql_string_concat"}
    assert by_path["app/db.py"].severity == "error"
    assert by_path["app/tests/test_db.py"].severity == "warning"
    assert "test-code" in by_path["app/tests/test_db.py"].tags

    config = AppConfig(test_paths=[])
    result = scan_paths(repo_root=root, targets=None, config=config)
    assert all(
        f.severity == "error" for f in result.findings if f.rule_id == "sql_string_concat"
    )


def test_rules_that_skip_tests_follow_test_paths_setting() -> None:
    from doc_ai_slopcheck.rules.ai_slop.debug_code_left import DebugCodeLeftRule

    def scan(path: str, config: AppConfig) -> list:
        return DebugCodeLeftRule().scan_file(
            repo_root=Path("."), relative_path=path, content="breakpoint()\n", config=config
        )

    assert scan("tests/test_foo.py", AppConfig()) == []
    assert scan("spec/helper.py", AppConfig()) == []
    custom = AppConfig(test_paths=["qa/*"])
    assert scan("qa/check.py", custom) == []
    assert len(scan("tests/test_foo.py", custom)) == 1  # no longer a test path


@pytest.mark.parametrize(
    ("path", "line", "rule_id"),
    [
        ("src/app.ts", "// if (x = 1) { }", "assignment_in_conditional"),
        ("src/util.ts", "// if (x == 0) this would fire", "js_loose_equality"),
        ("src/util.py", "# eval(code)", "obfuscated_code"),
        # inside a docstring: invisible to the rule's own per-line check
        ("src/debug.py", '"""\nbreakpoint()\n"""', "debug_code_left"),
    ],
)
def test_code_rules_ignore_commented_out_code(
    tmp_path: Path, path: str, line: str, rule_id: str
) -> None:
    """The scanner drops code-rule findings on comment lines, so rules don't
    need their own comment checks."""
    root = _repo(tmp_path, {path: line + "\n"})
    result = scan_paths(repo_root=root, targets=None, config=AppConfig())
    assert rule_id not in {f.rule_id for f in result.findings}
