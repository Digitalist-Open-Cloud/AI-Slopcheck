"""Real-world lines that once produced findings and must stay clean.

Each file holds code copied from a mature codebase where a rule fired on
nothing. Add a file (or a line) whenever a false positive is fixed.
"""

from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.scanner import scan_paths

FIXTURES = Path(__file__).parent / "fixtures" / "false_positives"


def test_known_false_positives_stay_clean() -> None:
    result = scan_paths(repo_root=FIXTURES, targets=None, config=AppConfig())
    assert result.stats.scanned_files >= 5
    found = {
        (f.location.path, f.location.line, f.rule_id, f.severity.value) for f in result.findings
    }
    # Names and fragments spliced into SQL, and HTML built from a number, are
    # worth a look but never an error.
    assert found == {
        ("sql_names.php", 3, "sql_string_concat", "warning"),
        ("sql_names.php", 5, "sql_string_concat", "warning"),
        ("sql_names.php", 6, "sql_string_concat", "warning"),
        ("sql_names.php", 6, "select_star_sql", "note"),
        ("sql_names.php", 7, "sql_string_concat", "warning"),
        ("dom.js", 1, "inner_html_assignment", "warning"),
    }
