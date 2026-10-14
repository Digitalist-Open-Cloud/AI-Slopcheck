from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig, SqlStringConcatConfig
from doc_ai_slopcheck.rules.generic.sql_string_concat import SqlStringConcatRule


def _scan(content: str, path: str = "src/db.py") -> list:
    rule = SqlStringConcatRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_select_plus_var() -> None:
    code = 'query = "SELECT * FROM users WHERE id = " + user_id\n'
    findings = _scan(code)
    assert len(findings) == 1
    assert "SQL injection" in findings[0].message


def test_detects_fstring_interpolation() -> None:
    code = 'query = f"SELECT * FROM users WHERE name = {name}"\n'
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_percent_format() -> None:
    code = 'query = "SELECT * FROM orders WHERE id = %s" % order_id\n'
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_insert_concat() -> None:
    code = 'q = "INSERT INTO logs VALUES (" + data + ")"\n'
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_delete_concat() -> None:
    code = 'q = "DELETE FROM sessions WHERE token = " + tok\n'
    findings = _scan(code)
    assert len(findings) == 1


def test_safe_parameterised_query() -> None:
    code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    findings = _scan(code)
    assert len(findings) == 0


def test_plain_string_no_interpolation() -> None:
    code = 'query = "SELECT * FROM users"\n'
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_non_matching_extension() -> None:
    rule = SqlStringConcatRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="README.md",
        content='q = "SELECT * FROM t WHERE id = " + x\n',
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.sql_string_concat = SqlStringConcatConfig(enabled=False)
    rule = SqlStringConcatRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/db.py",
        content='q = "SELECT * FROM t WHERE id = " + x\n',
        config=config,
    )
    assert len(findings) == 0


def test_multiple_violations() -> None:
    code = (
        'q1 = "SELECT * FROM a WHERE x = " + x\n'
        'q2 = f"UPDATE b SET y = {y}"\n'
    )
    findings = _scan(code)
    assert len(findings) == 2


def test_python_ast_ignores_messages_and_constants() -> None:
    code = (
        'assert "UPDATE" not in grants, f"unexpected UPDATE on {t}"\n'
        'op.execute(f"DROP SCHEMA IF EXISTS {_SCHEMA}")\n'
        'q = f"UPDATE {_TABLE} SET prev_hash=:p WHERE id=:i"\n'
        'conn.execute("INSERT INTO t (a) VALUES ($1)", f"x-{uuid4()}")\n'
    )
    assert _scan(code) == []


def test_python_ast_flags_dynamic_sql_including_multiline() -> None:
    code = (
        'q = "SELECT * FROM users WHERE id = " + user_id\n'
        "sql = (\n"
        '    f"SELECT {columns} "\n'
        '    f"FROM {table} WHERE a = 1"\n'
        ")\n"
        'cur.execute("DELETE FROM t WHERE id = %s" % uid)\n'
    )
    assert [f.location.line for f in _scan(code)] == [1, 3, 6]


def test_reviewed_noqa_s608_is_respected() -> None:
    code = 'q = f"SELECT {cols} FROM t"  # noqa: S608 -- cols is a fixed list\n'
    assert _scan(code) == []


def test_php_concat_and_interpolation() -> None:
    code = (
        '$r = db_query("SELECT * FROM {node} WHERE nid = " . $nid);\n'
        '$r = $db->query("DELETE FROM users WHERE id = $id");\n'
        "$r = $db->query('UPDATE t SET a = 1 WHERE id = ' . $_GET['id']);\n"
    )
    assert [f.location.line for f in _scan(code, path="src/x.php")] == [1, 2, 3]


def test_php_placeholders_and_drupal_table_braces_ok() -> None:
    code = (
        '$r = db_query("SELECT * FROM {node} WHERE nid = :nid", [":nid" => $nid]);\n'
        "$r = $db->fetchAll('SELECT id FROM t WHERE a = ?', [$a]);\n"
        '$label = "Updated " . $count . " rows";\n'
    )
    assert _scan(code, path="web/modules/custom/x/x.module") == []
