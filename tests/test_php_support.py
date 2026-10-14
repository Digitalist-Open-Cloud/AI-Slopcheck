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


# Regression cases from a Drupal codebase (kommunal-se backend).


def test_generated_files_are_skipped(tmp_path: Path) -> None:
    header = "<?php\n/**\n * @generated Generated by: https://openapi-generator.tech\n */\n"
    (tmp_path / "Api").mkdir()
    (tmp_path / "Api/ModelTest.php").write_text(header + "// TODO: implement\n")
    (tmp_path / "Api/Own.php").write_text("<?php\n// TODO: implement\n")
    result = scan_paths(repo_root=tmp_path, targets=None, config=AppConfig())
    assert {f.location.path for f in result.findings} == {"Api/Own.php"}


def test_secret_read_from_env_is_not_hardcoded() -> None:
    from doc_ai_slopcheck.rules.generic.hardcoded_secret import HardcodedSecretRule

    code = "$url = $_ENV['APP_URL'] . 'api/preview?secret=' . $_ENV['PREVIEW_TOKEN'];\n"
    assert _scan(HardcodedSecretRule(), code) == []


def test_explained_empty_catch_is_intentional() -> None:
    from doc_ai_slopcheck.rules.generic.bare_except_pass_js import BareExceptPassJsRule

    code = (
        "<?php\ntry { f(); }\n"
        "catch (PluginException $e) {\n  // Do nothing if the operation fails.\n}\n"
        "try { g(); }\ncatch (\\Exception $e) {\n}\n"  # truly empty: line 7
    )
    assert [f.location.line for f in _scan(BareExceptPassJsRule(), code)] == [7]


def test_documented_method_mentioning_implementation_is_not_a_stub() -> None:
    code = (
        "<?php\nclass P {\n  public function requiresReindexing() {\n"
        "    // The base implementation only reindexes in preprocess_index.\n"
        "    return TRUE;\n  }\n"
        "  public function submitForm() {\n    // @todo Implement submitForm() method.\n  }\n}\n"
    )
    findings = _scan(StubFunctionBodyPhpRule(), code)
    assert [f.message.split("`")[1] for f in findings] == ["submitForm"]


def test_definitions_and_closure_captures_are_not_calls() -> None:
    from doc_ai_slopcheck.rules.generic.many_positional_args import ManyPositionalArgsRule

    code = (
        "<?php\n"
        "public function resolve($type, $id, $language, $bundles, $access, $user, $op) {}\n"
        "$cb = function () use ($type, $bundles, $resolver, $context, $access, $user, $op) {};\n"
        "parent::__construct($configuration, $plugin_id, $plugin_definition, $a, $b, $c, $d);\n"
        "$x = resolve($type, $id, $language, $bundles, $access, $user, $op);\n"  # line 5: a call
    )
    findings = _scan(ManyPositionalArgsRule(), code)
    assert [f.location.line for f in findings] == [5]


def test_drupal_versions_are_not_plan_ids() -> None:
    code = "<?php\n// Re-shape D7 entries into D8 entries; implemented in D10.\n// See P13.\n"
    findings = _scan(PlanReferenceCommentRule(), code)
    assert len(findings) == 1 and "(P13)" in findings[0].message


# Regression cases from a second Drupal codebase (lakareutangranser).


def test_js_line_comment_does_not_swallow_following_code() -> None:
    code = (
        "// Check if d3 is available\n"
        "console.error('D3 library is not loaded');\n"
        "const FALLBACK = '^[A-Z0-9\\\\s\\\\-]{2,10}$'; // see '/*' handling\n"
        "// Task 4: wire up\n"
    )
    findings = _scan(PlanReferenceCommentRule(), code, path="src/form.js")
    assert len(findings) == 1 and "(Task 4)" in findings[0].message


def test_character_ranges_and_dotted_names_are_not_plan_ids() -> None:
    code = "<?php\n// Fallback ^[A-Z0-9\\s\\-]{2,10}$ and rule Guideline1_1.H37\n"
    assert _scan(PlanReferenceCommentRule(), code) == []


def test_vendored_file_with_license_banner_is_skipped(tmp_path: Path) -> None:
    lib = tmp_path / "web/modules/custom/x/libraries/regenerate"
    lib.mkdir(parents=True)
    (lib / "regenerate.js").write_text(
        "/*! https://mths.be/regenerate v1.3.3 by @mathias | MIT license */\n// TODO: theirs\n"
    )
    (lib / "own.js").write_text("// TODO: ours\n")
    result = scan_paths(repo_root=tmp_path, targets=None, config=AppConfig())
    assert {f.location.path.split("/")[-1] for f in result.findings} == {"own.js"}


def test_hex_escapes_in_regex_are_not_obfuscation() -> None:
    pattern = "/^(?:\\x22?\\x5C[\\x00-\\x7E]\\x22?|\\x22[^\\x5C\\x22]\\x22)$/"
    code = f"<?php\npreg_match('{pattern}', $e);\n"
    assert _scan(ObfuscatedCodeRule(), code) == []


# Regression cases from a Next.js frontend (kommunal-se frontend).


def test_js_promise_awaited_or_returned_is_handled_by_caller() -> None:
    from doc_ai_slopcheck.rules.generic.js_unhandled_promise import JsUnhandledPromiseRule

    code = (
        "await writer.ready.then(() => writer.write(data));\n"
        "const dictionaries = {\n"
        "  en: () =>\n"
        "    import('./en.json').then((m) => m.default),\n"
        "  sv: () =>\n"
        "    import('./sv.json').then((m) => m.default),\n"
        "};\n"
        "writer.closed.then(() => {\n"  # line 8: fire and forget
        "  cleanup();\n"
        "});\n"
    )
    findings = _scan(JsUnhandledPromiseRule(), code, path="src/route.ts")
    assert [f.location.line for f in findings] == [8]


def test_js_polling_loops_are_sequential_by_design() -> None:
    from doc_ai_slopcheck.rules.generic.js_await_in_loop import JsAwaitInLoopRule

    code = (
        "for await (const _ of setPromiseInterval(1000)) {\n"
        "  const r = await client.getSession(args);\n"
        "}\n"
        "while (!done) {\n"
        "  await new Promise((resolve) => setTimeout(resolve, 1000));\n"
        "}\n"
        "for (const id of ids) {\n"
        "  const item = await load(id);\n"  # line 8: serialised work
        "}\n"
    )
    findings = _scan(JsAwaitInLoopRule(), code, path="src/utils.ts")
    assert [f.location.line for f in findings] == [8]


def test_static_inner_html_is_not_flagged() -> None:
    from doc_ai_slopcheck.rules.generic.js_dangerously_set_html import (
        JsDangerouslySetHtmlRule,
    )

    code = (
        "<Script dangerouslySetInnerHTML={{\n  __html: `\n"
        "  (function(w){ w.x = 1; })(window);\n`,\n}} />\n"
        "<p dangerouslySetInnerHTML={{ __html: dictionary.footer }} />\n"  # line 6
        "<div dangerouslySetInnerHTML={{ __html: `<b>${name}</b>` }} />\n"  # line 7
    )
    findings = _scan(JsDangerouslySetHtmlRule(), code, path="src/Tag.tsx")
    assert [f.location.line for f in findings] == [6, 7]


def test_loose_equality_inside_string_is_ignored() -> None:
    from doc_ai_slopcheck.rules.generic.js_loose_equality import JsLooseEqualityRule

    code = 'const s = "data:text/html;base64,PHNjcmlwdD4==";\nif (a == b) {}\n'
    findings = _scan(JsLooseEqualityRule(), code, path="src/x.ts")
    assert [f.location.line for f in findings] == [2]
