from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig, ObfuscatedCodeConfig
from doc_ai_slopcheck.rules.generic.obfuscated_code import ObfuscatedCodeRule


def _scan(content: str, path: str = "src/util.py") -> list:
    rule = ObfuscatedCodeRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_eval_call() -> None:
    findings = _scan("result = eval(user_input)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "obfuscated_code"


def test_detects_function_constructor_js() -> None:
    findings = _scan("const f = new Function('a', 'return a');\n", path="src/app.js")
    assert len(findings) == 1


def test_detects_eval_of_atob_js() -> None:
    findings = _scan("eval(atob(payload));\n", path="src/app.ts")
    assert len(findings) == 1
    assert "base64-decoded" in findings[0].message


def test_detects_exec_of_base64_decode_python() -> None:
    findings = _scan("exec(base64.b64decode(encoded))\n")
    assert len(findings) == 1
    assert "base64-decoded" in findings[0].message


def test_plain_base64_decode_is_not_obfuscation() -> None:
    """Decoding keys or auth headers is routine; only executing decoded data is suspicious."""
    assert _scan("key = base64.b64decode(settings.kek)\n") == []
    assert _scan("const decoded = atob(data);\n", path="src/app.ts") == []


def test_bytes_literal_hex_is_binary_data() -> None:
    assert _scan('_OLE_MAGIC = b"\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1"\n') == []


def test_detects_dense_hex_escapes() -> None:
    # More than 6 hex escapes in one line (threshold raised from 3 to 6)
    findings = _scan('x = "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48"\n')
    assert len(findings) == 1


def test_allows_moderate_hex_escapes() -> None:
    """Up to 6 hex escapes is normal string encoding — should not flag."""
    findings = _scan('x = "\\x41\\x42\\x43"\n')
    assert len(findings) == 0


def test_skips_test_file() -> None:
    findings = _scan("eval(code)\n", path="tests/test_util.py")
    assert len(findings) == 0



def test_skips_unsupported_extension() -> None:
    rule = ObfuscatedCodeRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="template.html",
        content="eval(code)\n",
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.obfuscated_code = ObfuscatedCodeConfig(enabled=False)
    rule = ObfuscatedCodeRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.py",
        content="eval(x)\n",
        config=config,
    )
    assert len(findings) == 0


def test_skips_minified_files() -> None:
    """Files with .min. in the name should be skipped entirely."""
    # Test that obfuscation scanner skips minified vendor files (atob call).
    findings = _scan("const decoded = atob(data);\n", path="vendor/prettify.min.js")
    assert len(findings) == 0


def test_skips_files_with_long_average_lines() -> None:
    """Bundled/minified files detected by long average line length."""
    long_line = "a" * 300 + "\n"
    content = long_line * 10 + "const decoded = atob(data);\n"
    findings = _scan(content, path="dist/bundle.js")
    assert len(findings) == 0


def test_clean_code_no_findings() -> None:
    findings = _scan("x = int(user_input)\n")
    assert len(findings) == 0


def test_regex_exec_method_is_not_eval() -> None:
    code = "const m = /^##\\s+(.+)$/.exec(line);\nconst r = re.exec(s);\n"
    assert _scan(code, path="src/parse.ts") == []
