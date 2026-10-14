"""PHP and Drupal support: discovery, context, extended rules and PHP-only rules."""

from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import non_code_lines, php_comments
from doc_ai_slopcheck.engine.scanner import scan_paths
from doc_ai_slopcheck.rules.generic.debug_code_left import DebugCodeLeftRule
from doc_ai_slopcheck.rules.generic.large_function import LargeFunctionRule
from doc_ai_slopcheck.rules.generic.obfuscated_code import ObfuscatedCodeRule
from doc_ai_slopcheck.rules.generic.php_user_input_sink import PhpUserInputSinkRule
from doc_ai_slopcheck.rules.generic.plan_reference_comment import PlanReferenceCommentRule
from doc_ai_slopcheck.rules.generic.sql_string_concat import SqlStringConcatRule
from doc_ai_slopcheck.rules.generic.stub_function_body_php import StubFunctionBodyPhpRule
from doc_ai_slopcheck.rules.generic.unreachable_code_after_return import (
    UnreachableCodeAfterReturnRule,
)


def _scan(rule, content: str, path: str = "src/Foo.php") -> list:
    return rule.scan_file(
        repo_root=Path("."), relative_path=path, content=content, config=AppConfig()
    )


def test_php_non_code_lines_and_comments() -> None:
    src = (
        "<p>html</p>\n"  # 1
        "<?php\n"  # 2
        "/** Doc with dpm($x) */\n"  # 3
        "#[Route('/x')]\n"  # 4
        "$re = '/[a-fA-F0-9]/'; // Task 4\n"  # 5
        "# K3 hash comment\n"  # 6
        "$h = <<<EOT\n"  # 7
        "  // not a comment\n"  # 8
        "  EOT;\n"  # 9
    )
    assert non_code_lines(src, ".php") == {1, 3, 6}
    assert [n for n, _ in php_comments(src)] == [3, 5, 6]


def test_drupal_files_discovered_and_core_contrib_skipped(tmp_path: Path) -> None:
    files = {
        "web/modules/custom/my/my.module": "<?php\n// TODO: finish\n",
        "web/modules/contrib/other/other.module": "<?php\n// TODO: theirs\n",
        "web/core/lib/Drupal.php": "<?php\n// TODO: core\n",
    }
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    result = scan_paths(repo_root=tmp_path, targets=None, config=AppConfig())
    assert {f.location.path for f in result.findings} == {"web/modules/custom/my/my.module"}


def test_stub_function_body_php() -> None:
    code = (
        "<?php\n"
        "class A {\n"
        "  public function __construct(private Foo $foo) {}\n"
        "  abstract public function shape(): string;\n"
        "  public function noop(): void {}\n"
        "  public function todo() {\n"
        "    // TODO: implement\n"
        "    return null;\n"
        "  }\n"
        "  public function later() { throw new \\LogicException('Not implemented yet'); }\n"
        "  public function real() { return $this->foo->bar(); }\n"
        "}\n"
    )
    findings = _scan(StubFunctionBodyPhpRule(), code)
    assert [f.location.line for f in findings] == [6, 10]


def test_php_user_input_sink() -> None:
    code = (
        "<?php\n"
        "echo $_GET['name'];\n"  # 2 XSS
        "$db->query(\"SELECT * FROM t WHERE id = \" . $_POST['id']);\n"  # 3 SQL
        "system('ls ' . $_REQUEST['dir']);\n"  # 4 shell
        "echo htmlspecialchars($_GET['name']);\n"  # escaped
        "$id = (int) $_GET['id'];\n"  # cast, no sink anyway
        "require $_SERVER['SCRIPT_FILENAME'];\n"  # server-controlled
        "header('X: ' . $_SERVER['HTTP_X_FOO']);\n"  # 8 client header
        "// echo $_GET['x'];\n"  # comment
    )
    assert [f.location.line for f in _scan(PhpUserInputSinkRule(), code)] == [2, 3, 4, 8]


def test_php_debug_calls() -> None:
    code = (
        "<?php\n"
        "var_dump($x);\n"  # 2
        "dpm($node);\n"  # 3 Drupal devel
        "$s = print_r($x, TRUE);\n"  # return mode
        "$s = var_export($x, 1);\n"  # return mode
        "public function dump($h = '') {}\n"  # definition
        "$logger->dump($x);\n"  # method
        "'debug' => true, // use {{ dump(var) }} in twig\n"  # comment
    )
    assert [f.location.line for f in _scan(DebugCodeLeftRule(), code)] == [2, 3]


def test_php_obfuscation_vs_shell_exec_and_methods() -> None:
    code = (
        "<?php\n"
        "eval(base64_decode($payload));\n"  # 2
        "exec($command, $output);\n"  # shell, not obfuscation
        "$pdo->exec($sql);\n"
        "public function exec($sql) {}\n"
    )
    findings = _scan(ObfuscatedCodeRule(), code)
    assert [f.location.line for f in findings] == [2]
    assert "base64-decoded" in findings[0].message


def test_php_sql_name_vs_value_positions() -> None:
    code = (
        '<?php\n$q = "SELECT * FROM " . $this->table . " WHERE id = ?";\n'
        '$q = "DELETE FROM users WHERE id = $id";\n'
        '$db->query("DELETE FROM " . $this->tokens . " WHERE `login` = ?", $login);\n'
        '$s = "UPDATE $archive SET value = " . Writer::DONE_INVALIDATED;\n'
    )
    findings = _scan(SqlStringConcatRule(), code)
    assert [(f.location.line, f.severity.value) for f in findings] == [
        (2, "warning"),
        (3, "error"),
        (4, "warning"),  # $login after the SQL string is a bound parameter
        (5, "warning"),  # class constant, not user input
    ]


def test_php_unreachable_needs_semicolon() -> None:
    code = (
        "<?php\nfunction f($a, $b) {\n"
        "    return $a\n"
        "    || $b;\n"
        "}\n"
    )
    assert _scan(UnreachableCodeAfterReturnRule(), code) == []


def test_php_large_function_and_abstract_methods() -> None:
    body = "\n".join(f"    $x{i} = {i};" for i in range(160))
    code = (
        "<?php\ninterface I {\n  public function a(): void;\n}\n"
        f"function big() {{\n{body}\n}}\n"
    )
    findings = _scan(LargeFunctionRule(), code)
    assert len(findings) == 1 and findings[0].location.line == 5


def test_php_plan_reference_only_in_comments() -> None:
    code = "<?php\n$m = ['A1' => 'x'];\n$re = '/[a-fA-F0-9]/';\n# Task 4: wire up\n"
    findings = _scan(PlanReferenceCommentRule(), code)
    assert len(findings) == 1 and "Task 4" in findings[0].message
