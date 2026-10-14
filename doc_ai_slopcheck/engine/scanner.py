from __future__ import annotations

import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.engine.context_filter import non_code_lines
from doc_ai_slopcheck.engine.duplication import find_duplicates
from doc_ai_slopcheck.engine.repo_files import (
    DEFAULT_CODE_EXTENSIONS,
    discover_files,
    is_generated,
    is_ignored,
)
from doc_ai_slopcheck.engine.suppression import is_suppressed, parse_suppressions
from doc_ai_slopcheck.models import Finding, ScanResult, ScanStats, Severity
from doc_ai_slopcheck.rules.base import Rule
from doc_ai_slopcheck.rules.registry import build_rules

_DOWNGRADE = {Severity.ERROR: Severity.WARNING, Severity.WARNING: Severity.NOTE}


def _downgrade_test_code(
    findings: list[Finding], test_paths: list[str], keep: set[str]
) -> list[Finding]:
    return [
        f.model_copy(
            update={
                "severity": _DOWNGRADE.get(f.severity, f.severity),
                "tags": [*f.tags, "test-code"],
            }
        )
        if f.rule_id not in keep and is_ignored(f.location.path, test_paths)
        else f
        for f in findings
    ]


def _build_rules_by_ext(rules: list[Rule]) -> dict[str, list[Rule]]:
    """Pre-filter: map file extensions to applicable rules."""
    by_ext: dict[str, list[Rule]] = defaultdict(list)
    for rule in rules:
        if rule.supported_extensions is None:
            for ext in DEFAULT_CODE_EXTENSIONS:
                by_ext[ext].append(rule)
        else:
            for ext in rule.supported_extensions:
                by_ext[ext].append(rule)
    return dict(by_ext)


def _scan_single_file(
    path: Path,
    repo_root: Path,
    applicable_rules: list[Rule],
    config: AppConfig,
) -> tuple[list[Finding], int, int]:
    """Scan a single file with the given rules. Thread-safe."""
    relative_path = path.relative_to(repo_root).as_posix()
    content = path.read_text(encoding="utf-8", errors="ignore")
    if config.skip_generated and is_generated(content):
        return [], 0, 0
    suppressions = parse_suppressions(content)

    findings: list[Finding] = []
    rule_errors = 0
    suppressed_count = 0
    comment_lines: frozenset[int] | None = None  # computed on first need

    for rule in applicable_rules:
        try:
            file_findings = rule.scan_file(
                repo_root=repo_root,
                relative_path=relative_path,
                content=content,
                config=config,
            )
            for finding in file_findings:
                if rule.code_only:
                    if comment_lines is None:
                        comment_lines = non_code_lines(content, path.suffix.lower())
                    if finding.location.line in comment_lines:
                        continue
                if is_suppressed(
                    suppressions, finding.location.line, finding.rule_id
                ):
                    suppressed_count += 1
                else:
                    findings.append(finding)
        except Exception as exc:
            rule_errors += 1
            print(
                f"slopcheck: rule {rule.rule_id} failed on "
                f"{relative_path}: {exc}",
                file=sys.stderr,
            )

    return findings, rule_errors, suppressed_count


def scan_paths(
    *,
    repo_root: Path,
    targets: list[Path] | None,
    config: AppConfig,
    jobs: int | None = None,
) -> ScanResult:
    files = discover_files(
        repo_root=repo_root, targets=targets, ignored_patterns=config.ignored_paths
    )
    rules = build_rules()
    rules_by_ext = _build_rules_by_ext(rules)

    all_findings: list[Finding] = []
    total_errors = 0
    total_suppressed = 0

    max_workers = jobs if jobs and jobs > 0 else min(os.cpu_count() or 1, 8)

    # Build work items: (file, applicable_rules)
    work: list[tuple[Path, list[Rule]]] = []
    for path in files:
        ext = path.suffix.lower()
        applicable = rules_by_ext.get(ext, [])
        if applicable:
            work.append((path, applicable))

    if max_workers <= 1 or len(work) < 50:
        # Sequential for small batches or --jobs 1
        for path, applicable in work:
            findings, errors, suppressed = _scan_single_file(
                path, repo_root, applicable, config
            )
            all_findings.extend(findings)
            total_errors += errors
            total_suppressed += suppressed
    else:
        # Threaded for larger batches
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [
                pool.submit(
                    _scan_single_file, path, repo_root, applicable, config
                )
                for path, applicable in work
            ]
            for future in futures:
                findings, errors, suppressed = future.result()
                all_findings.extend(findings)
                total_errors += errors
                total_suppressed += suppressed

    dup_findings, dup_suppressed = find_duplicates(
        repo_root, files, config.rules.duplicate_code, skip_generated=config.skip_generated
    )
    all_findings.extend(dup_findings)
    total_suppressed += dup_suppressed
    keep = {rule.rule_id for rule in rules if not rule.downgrade_in_tests}
    all_findings = _downgrade_test_code(all_findings, config.test_paths, keep)

    all_findings.sort(
        key=lambda item: (
            item.location.path,
            item.location.line,
            item.rule_id,
            item.message,
        )
    )

    return ScanResult(
        repo_root=repo_root.as_posix(),
        stats=ScanStats(
            scanned_files=len(files),
            findings=len(all_findings),
            rule_errors=total_errors,
            suppressed=total_suppressed,
        ),
        findings=all_findings,
    )
