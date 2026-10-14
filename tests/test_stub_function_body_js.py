from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.rules.generic.stub_function_body_js import StubFunctionBodyJsRule


def _scan(content: str, path: str = "src/service.ts") -> list:
    rule = StubFunctionBodyJsRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_function_return_null():
    code = "function getData() {\n  // TODO: fetch from the API\n  return null;\n}\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert "getData" in findings[0].message


def test_detects_arrow_return_null():
    code = "const getData = () => null;\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_arrow_return_empty_array():
    code = "const getItems = () => [];\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_empty_function_body():
    code = "function handler() { }\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_return_undefined():
    code = "function process() {\n  // not implemented yet\n  return undefined;\n}\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_ignores_real_implementation():
    code = "function getData() {\n  const result = fetch(url);\n  return result;\n}\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_ignores_non_js_files():
    code = "function getData() {\n  return null;\n}\n"
    findings = _scan(code, path="src/main.py")
    assert len(findings) == 0


def test_detects_async_arrow():
    code = "const fetchData = async () => null;\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_export_function():
    code = "export function getUser() {\n  // @todo\n  return null;\n}\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_lone_trivial_return_without_todo_is_not_a_stub():
    """Next.js generateStaticParams() { return [] } and similar are deliberate."""
    code = "export async function generateStaticParams() {\n  return [];\n}\n"
    assert _scan(code, path="src/app/page.tsx") == []
