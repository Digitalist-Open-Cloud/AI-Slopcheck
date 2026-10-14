from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.rules.ai_slop.plan_reference_comment import PlanReferenceCommentRule


def _scan(content: str, path: str = "src/app.py", config: AppConfig | None = None) -> list:
    return PlanReferenceCommentRule().scan_file(
        repo_root=Path("."), relative_path=path, content=content, config=config or AppConfig()
    )


def test_flags_plan_ids_in_comments_and_docstrings_once_per_file() -> None:
    code = (
        '"""Usage report (P13, Task 5)."""\n'
        "def f():\n"
        "    # K3: class comes from the assistant record\n"
        "    return 1\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].location.line == 1
    assert "3 plan/task references" in findings[0].message
    assert "P13, Task 5, K3" in findings[0].message


def test_ignores_code_strings_directives_urls_versions() -> None:
    code = (
        'BUCKET = "P13"  # noqa: B008, E501\n'
        "x = 1  # type: ignore[arg-type]\n"
        "# see https://example.com/blob/main/x.py#L37\n"
        "# Pydantic V2 stores this on S3, p95 latency under P99\n"
    )
    assert _scan(code) == []


def test_js_comments_but_not_urls_in_code() -> None:
    code = (
        'const url = "https://api.example.com/v1";\n'
        "// Fas 3: wire up the handler\n"
        "/* R7 fallback */\n"
    )
    findings = _scan(code, path="src/app.ts")
    assert len(findings) == 1
    assert "Fas 3, R7" in findings[0].message


def test_configurable_patterns_and_disable() -> None:
    config = AppConfig()
    config.rules.plan_reference_comment.patterns = [r"\bD-\d+\b"]
    assert len(_scan("# decided in D-71\n", config=config)) == 1
    config.rules.plan_reference_comment.enabled = False
    assert _scan("# decided in D-71\n", config=config) == []


def test_unparseable_python_still_scans_comments() -> None:
    assert len(_scan("# Task 4: wip\ndef broken(:\n")) == 1
