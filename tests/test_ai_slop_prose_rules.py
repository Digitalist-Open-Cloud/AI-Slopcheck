"""Rules inspired by ponytail (over-building) and caveman (wordy prose)."""

from __future__ import annotations

from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.rules.ai_slop.ai_conversational_bleed import AiConversationalBleedRule
from doc_ai_slopcheck.rules.ai_slop.comment_essay import CommentEssayRule
from doc_ai_slopcheck.rules.ai_slop.history_comment import HistoryCommentRule
from doc_ai_slopcheck.rules.idioms.native_alternative import NativeAlternativeRule
from doc_ai_slopcheck.rules.maintainability.pass_through_wrapper import PassThroughWrapperRule


def _scan(rule, content: str, path: str, config: AppConfig | None = None) -> list:
    return rule.scan_file(
        repo_root=Path("."), relative_path=path, content=content, config=config or AppConfig()
    )


def test_comment_essay_python_docstring_and_file_header() -> None:
    essay = "\n".join(f"    Line {i} of design notes about why this exists." for i in range(16))
    code = f'def route():\n    """Route.\n\n{essay}\n    """\n    return 1\n'
    findings = _scan(CommentEssayRule(), code, "src/metrics.py")
    assert len(findings) == 1 and "`route`" in findings[0].message

    header = "\n".join(f"# history line {i}" for i in range(32))
    findings = _scan(CommentEssayRule(), header + "\nx = 1\n", "src/notes.py")
    assert any("file header" in f.message for f in findings)


def test_comment_essay_ignores_api_docblocks_and_commented_out_code() -> None:
    params = "\n".join(
        f" * @param string $a{i}\n *   Description of argument {i}." for i in range(8)
    )
    php = (
        f"<?php\n/**\n * Constructs the plugin.\n{params}\n */\n"
        "public function __construct() {\n  $x = 1;\n}\n"
    )
    assert _scan(CommentEssayRule(), php, "src/Plugin.php") == []
    commented = "/**\n * TODO: fix\nfunction old() {\n" + "  // note\n" * 20 + "}\n */\n"
    assert _scan(CommentEssayRule(), commented, "src/old.ts") == []


def test_history_comment_needs_code_history_not_runtime_order() -> None:
    code = (
        "# Overwrites all previously set columns.\n"  # runtime, not history
        "# The session is no longer valid after logout.\n"  # state
        "# We used to call the API twice here.\n"  # history: line 3
        "# Fram till D-113 skickades sub i klartext.\n"  # history
    )
    findings = _scan(HistoryCommentRule(), code, "src/auth.py")
    assert len(findings) == 1
    assert findings[0].location.line == 3 and "2 comment lines" in findings[0].message


def test_native_alternative() -> None:
    js = (
        "import moment from 'moment';\n"
        "import { v4 } from 'uuid';\n"
        "import debounce from 'lodash/debounce';\n"  # no native equivalent: not flagged
        "const copy = JSON.parse(JSON.stringify(obj));\n"
    )
    assert [f.location.line for f in _scan(NativeAlternativeRule(), js, "src/a.ts")] == [1, 2, 4]
    py = "import pytz\nfrom mock import patch\nimport json\n"
    assert [f.location.line for f in _scan(NativeAlternativeRule(), py, "src/a.py")] == [1, 2]


def test_emoji_in_comments_and_logs_not_ui_text() -> None:
    code = (
        '"""⚠️ Fail-closed is inverted here."""\n'
        'logger.info("✅ done")\n'
        'TITLE = "🎉 Welcome"\n'  # UI text: allowed
    )
    findings = _scan(AiConversationalBleedRule(), code, "src/x.py")
    assert sorted(f.location.line for f in findings if "emoji" in f.tags) == [1, 2]


def test_pass_through_wrapper_is_opt_in_and_skips_factories() -> None:
    code = (
        "def constant_time_eq(a, b):\n    return hmac.compare_digest(a, b)\n"
        "def get_repo(s):\n    return RoleRepo(s)\n"  # factory
        "def get_pool(self, sid):\n    return self._pools.get(sid)\n"  # encapsulation
        "def convert(a, b):\n    return other(b, a)\n"  # reorders: real work
    )
    assert _scan(PassThroughWrapperRule(), code, "src/a.py") == []
    config = AppConfig()
    config.rules.pass_through_wrapper.enabled = True
    findings = _scan(PassThroughWrapperRule(), code, "src/a.py", config)
    assert [f.location.line for f in findings] == [1]
