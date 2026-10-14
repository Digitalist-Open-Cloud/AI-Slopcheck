from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig, ContradictoryNullCheckConfig
from doc_ai_slopcheck.rules.generic.contradictory_null_check import ContradictoryNullCheckRule


def _scan(content: str, path: str = "module.py") -> list:
    rule = ContradictoryNullCheckRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


# ── Positive cases (should flag) ──────────────────────────────────────────────

def test_is_none_then_attr_access() -> None:
    code = (
        "if x is None:\n"
        "    x.do_something()\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "x" in findings[0].message
    assert findings[0].location.line == 2


def test_is_none_then_subscript() -> None:
    code = (
        "if obj is None:\n"
        "    val = obj[\"key\"]\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "obj" in findings[0].message


def test_not_x_then_attr_access() -> None:
    code = (
        "if not user:\n"
        "    print(user.name)\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "user" in findings[0].message


def test_not_x_then_filling_empty_container_ok() -> None:
    """`if not items: items.append(1)` is how an empty list gets filled."""
    code = (
        "if not items:\n"
        "    items.append(1)\n"
        "if not cache:\n"
        "    cache[key] = load()\n"
    )
    assert _scan(code) == []


def test_is_none_then_append_still_flagged() -> None:
    code = (
        "if items is None:\n"
        "    items.append(1)\n"
    )
    assert len(_scan(code)) == 1


def test_access_in_trailing_comment_ignored() -> None:
    code = (
        "if not choices:\n"
        "    continue  # never index choices[0] blindly\n"
    )
    assert _scan(code) == []


def test_len_zero_then_iteration() -> None:
    code = (
        "if len(data) == 0:\n"
        "    for item in data:\n"
        "        process(item)\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "data" in findings[0].message
    assert findings[0].location.line == 2


def test_not_x_then_nested_attr_access() -> None:
    code = (
        "if not conn:\n"
        "    result = conn.execute(query)\n"
    )
    findings = _scan(code)
    assert len(findings) == 1


# ── Negative cases (should not flag) ─────────────────────────────────────────

def test_safe_early_return_pattern() -> None:
    """if x is None: return — nothing dereferenced inside block."""
    code = (
        "if x is None:\n"
        "    return None\n"
        "x.do_something()\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_safe_not_check_with_raise() -> None:
    code = (
        "if not items:\n"
        "    raise ValueError(\"empty\")\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_different_variable_not_flagged() -> None:
    """The dereferenced variable is different from the guarded one."""
    code = (
        "if x is None:\n"
        "    y.do_something()\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_non_python_file() -> None:
    code = (
        "if x is None:\n"
        "    x.method()\n"
    )
    findings = _scan(code, path="module.go")
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.contradictory_null_check = ContradictoryNullCheckConfig(enabled=False)
    rule = ContradictoryNullCheckRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="module.py",
        content="if x is None:\n    x.method()\n",
        config=config,
    )
    assert len(findings) == 0


def test_severity_and_confidence() -> None:
    code = (
        "if x is None:\n"
        "    x.method()\n"
    )
    findings = _scan(code)
    assert findings[0].severity.value == "error"
    assert findings[0].confidence.value == "medium"
