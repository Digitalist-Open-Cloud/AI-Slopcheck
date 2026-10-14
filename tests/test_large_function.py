from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig, LargeFunctionConfig
from doc_ai_slopcheck.rules.maintainability.large_function import LargeFunctionRule


def _make_config(max_lines: int = 60) -> AppConfig:
    config = AppConfig()
    config.rules.large_function = LargeFunctionConfig(
        enabled=True, max_lines=max_lines
    )
    return config


def _scan(content: str, path: str = "src/service.py") -> list:
    rule = LargeFunctionRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(),
    )


def _make_py_func(n_lines: int) -> str:
    body = "\n".join(f"    x = {i}" for i in range(n_lines))
    return f"def big_func():\n{body}\n"


def _make_js_func(n_lines: int) -> str:
    body = "\n".join(f"    const x{i} = {i};" for i in range(n_lines))
    return f"function bigFunc() {{\n{body}\n}}\n"


def test_detects_large_python_function() -> None:
    code = _make_py_func(70)
    findings = _scan(code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "large_function"


def test_allows_small_python_function() -> None:
    code = _make_py_func(10)
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_large_js_function() -> None:
    code = _make_js_func(70)
    findings = _scan(code, path="src/service.ts")
    assert len(findings) >= 1


def test_allows_small_js_function() -> None:
    code = _make_js_func(10)
    findings = _scan(code, path="src/service.ts")
    assert len(findings) == 0


def test_custom_max_lines() -> None:
    config = AppConfig()
    config.rules.large_function = LargeFunctionConfig(enabled=True, max_lines=20)
    rule = LargeFunctionRule()
    code = _make_py_func(25)
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/service.py",
        content=code,
        config=config,
    )
    assert len(findings) >= 1


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.large_function = LargeFunctionConfig(enabled=False)
    rule = LargeFunctionRule()
    code = _make_py_func(100)
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/service.py",
        content=code,
        config=config,
    )
    assert len(findings) == 0


def test_detects_large_async_python_function() -> None:
    code = _make_py_func(80).replace("def big_func", "async def big_func")
    findings = _scan(code)
    assert len(findings) == 1
    assert "big_func" in findings[0].message


def test_python_length_stops_at_function_end() -> None:
    """Module-level code after a function must not count toward its length."""
    code = "def small():\n    return 1\n\n" + "\n".join(f"X{i} = {i}" for i in range(100)) + "\n"
    assert _scan(code) == []


def test_python_syntax_error_returns_nothing() -> None:
    assert _scan("def broken(:\n" + "    x = 1\n" * 100) == []


def test_js_one_liner_function_is_one_line() -> None:
    """A function opened and closed on one line must not swallow the code below it."""
    filler = "\n".join(f"x{i}();" for i in range(80))
    code = (
        "function sceneAt(t) { return t; }\n"
        "const swing = (h) => { h.y = 1; };\n"
        f"{filler}\n}}\n"
    )
    assert _scan(code, path="src/scene.js") == []


def test_js_parenthesised_assignment_is_not_a_function() -> None:
    filler = "\n".join(f"x{i}();" for i in range(80))
    code = f"const lead = (isNew ? 1 : 0) + 2;\n{filler}\nif (a) {{\n  b();\n}}\n"
    assert _scan(code, path="src/scene.js") == []
