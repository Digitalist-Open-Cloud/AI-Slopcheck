from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import DuplicateCodeConfig
from doc_ai_slopcheck.engine.duplication import find_duplicates

BLOCK = "\n".join(
    f"    result_{i} = compute_something(alpha_{i}, beta_{i}, gamma_{i})" for i in range(12)
)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scan(root: Path, *paths: Path, **cfg: object):
    return find_duplicates(root, sorted(paths), DuplicateCodeConfig(**cfg))


def test_cross_file_copy_reported_once_on_later_path(tmp_path: Path) -> None:
    a = _write(tmp_path, "a/handler.py", f"def a():\n{BLOCK}\n")
    # Different indentation and an interleaved comment must not hide the copy.
    copy = BLOCK.replace("    ", "\t").replace("result_5", "# note\n\tresult_5")
    b = _write(tmp_path, "b/handler.py", f"def b():\n{copy}\n")

    findings, suppressed = _scan(tmp_path, a, b)

    assert suppressed == 0
    assert len(findings) == 1
    assert findings[0].location.path == "b/handler.py"
    assert "a/handler.py" in findings[0].message


def test_within_file_copy(tmp_path: Path) -> None:
    f = _write(tmp_path, "x.py", f"def a():\n{BLOCK}\n\ndef b():\n{BLOCK}\n")
    findings, _ = _scan(tmp_path, f)
    assert len(findings) == 1
    assert "elsewhere in this file" in findings[0].message
    assert findings[0].message.startswith("24 lines (lines 2-13, 16-27)")


def test_three_copies_give_two_findings(tmp_path: Path) -> None:
    files = [_write(tmp_path, f"s{i}/x.py", f"def f():\n{BLOCK}\n") for i in range(3)]
    findings, _ = _scan(tmp_path, *files)
    assert sorted(f.location.path for f in findings) == ["s1/x.py", "s2/x.py"]
    assert all("s0/x.py" in f.message for f in findings)


def test_short_or_import_only_blocks_ignored(tmp_path: Path) -> None:
    imports = "\n".join(f"from pkg.mod{i} import thing_{i}_with_a_long_name" for i in range(15))
    a = _write(tmp_path, "a.py", imports)
    b = _write(tmp_path, "b.py", imports)
    short = "\n".join(f"x = {i}" for i in range(15))
    c = _write(tmp_path, "c.py", short)
    d = _write(tmp_path, "d.py", short)
    assert _scan(tmp_path, a, b, c, d) == ([], 0)


def test_suppression_and_disable(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.py", f"def a():\n{BLOCK}\n")
    b = _write(
        tmp_path, "b.py", f"def b():\n    # slopcheck: ignore-next[duplicate_code]\n{BLOCK}\n"
    )
    assert _scan(tmp_path, a, b) == ([], 1)
    assert _scan(tmp_path, a, b, enabled=False) == ([], 0)
