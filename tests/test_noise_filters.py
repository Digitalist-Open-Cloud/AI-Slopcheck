"""Scanner-level noise filters: comment/docstring lines and test-code severity."""

from __future__ import annotations

from pathlib import Path

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
