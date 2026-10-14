from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from doc_ai_slopcheck.cli import app
from doc_ai_slopcheck.models import (
    Confidence,
    Finding,
    Location,
    ScanResult,
    ScanStats,
    Severity,
)
from doc_ai_slopcheck.output.html_report import render_html


def _finding(rule_id: str, severity: Severity, message: str = "msg") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} title",
        message=message,
        severity=severity,
        confidence=Confidence.HIGH,
        location=Location(path="src/app.py", line=3),
        fingerprint=rule_id + message,
        evidence="x = 1",
    )


def test_html_groups_orders_and_escapes() -> None:
    result = ScanResult(
        repo_root="/repo/demo",
        stats=ScanStats(scanned_files=4, findings=3),
        findings=[
            _finding("noisy_note", Severity.NOTE),
            _finding("noisy_note", Severity.NOTE, "second"),
            _finding("bad_error", Severity.ERROR, "<script>alert(1)</script>"),
        ],
    )

    html = render_html(result)

    assert "3 findings across 2 rules" in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    # Errors come before notes regardless of count.
    assert html.index('id="bad_error"') < html.index('id="noisy_note"')


def test_html_no_findings() -> None:
    result = ScanResult(repo_root="/repo/demo", stats=ScanStats())
    assert "No findings" in render_html(result)


def test_html_command(tmp_path: Path) -> None:
    findings_file = tmp_path / "findings.json"
    result = ScanResult(
        repo_root="/repo/demo",
        stats=ScanStats(findings=1),
        findings=[_finding("bad_error", Severity.ERROR)],
    )
    findings_file.write_text(result.model_dump_json(), encoding="utf-8")

    out = CliRunner().invoke(app, ["html", str(findings_file)])

    assert out.exit_code == 0
    assert out.stdout.startswith("<!doctype html>")


def test_hotspots_rank_files_by_weighted_severity() -> None:
    def at(path: str, rule_id: str, severity: Severity) -> Finding:
        f = _finding(rule_id, severity, message=path + rule_id)
        return f.model_copy(update={"location": Location(path=path, line=1)})

    notes = [at("src/noisy.py", f"note_{i}", Severity.NOTE) for i in range(5)]  # score 5
    result = ScanResult(
        repo_root="/repo/demo",
        stats=ScanStats(findings=7),
        findings=[*notes, at("src/bad.py", "bad_error", Severity.ERROR),  # score 10
                  at("src/meh.py", "meh", Severity.WARNING)],  # score 3
    )

    html = render_html(result)
    hot = html[html.index("Where to start") : html.index(">Index<")]
    assert hot.index("src/bad.py") < hot.index("src/noisy.py") < hot.index("src/meh.py")
    assert '<a href="#bad_error">bad_error</a>' in hot


def test_hotspots_count_each_rule_once_and_skip_test_code() -> None:
    def at(path: str, rule_id: str, n: int, tags: list[str] | None = None) -> Finding:
        f = _finding(rule_id, Severity.NOTE, message=f"{path}{rule_id}{n}")
        return f.model_copy(update={"location": Location(path=path, line=n), "tags": tags or []})

    findings = [
        *(at("src/busy.js", "many_positional_args", n) for n in range(40)),  # one rule: 1
        at("src/broad.py", "large_function", 1),  # three rules: 3
        at("src/broad.py", "duplicate_code", 2),
        at("src/broad.py", "plan_reference_comment", 3),
        *(at("app/tests/test_x.py", f"rule_{n}", n, ["test-code"]) for n in range(9)),
    ]
    result = ScanResult(repo_root="/r", stats=ScanStats(findings=len(findings)), findings=findings)

    html = render_html(result)
    hot = html[html.index("Where to start") : html.index(">Index<")]
    assert hot.index("src/broad.py") < hot.index("src/busy.js")
    assert "test_x.py" not in hot
