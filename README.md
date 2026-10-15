# doc-ai-slopcheck

[![PyPI](https://img.shields.io/pypi/v/doc-ai-slopcheck?color=blue)](https://pypi.org/project/doc-ai-slopcheck/)
[![Python](https://img.shields.io/pypi/pyversions/doc-ai-slopcheck)](https://pypi.org/project/doc-ai-slopcheck/)
[![Tests](https://github.com/Digitalist-Open-Cloud/AI-Slopcheck/actions/workflows/tests.yml/badge.svg)](https://github.com/Digitalist-Open-Cloud/AI-Slopcheck/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-81-blue)]()

**Deterministic scanner for AI-style code failures. 81 rules. No LLM. No backend.**

Digitalist Open Cloud fork of [ai-slopcheck](https://github.com/Euraika-Labs/ai_slopcheck) by Euraika, which is no longer public.

> Catches the mistakes AI coding assistants leave behind — stub functions, silent error handling, copy-pasted code, plan/ticket IDs in comments, hallucinated placeholders, hardcoded secrets, and more across Python, JS/TS, PHP (incl. Drupal), Go, C/C++, SQL, and Markdown.

---

## Install

From [PyPI](https://pypi.org/project/doc-ai-slopcheck/) (Python 3.12+):

```shell
pip install doc-ai-slopcheck
# or as an isolated command-line tool
pipx install doc-ai-slopcheck
```

## Quick Start

```shell
# Scan a project (findings go to findings.json by default)
doc-ai-slopcheck scan . --output findings.json --fail-on warning

# Read the results
doc-ai-slopcheck summary findings.json            # Markdown summary
doc-ai-slopcheck html findings.json > report.html  # shareable HTML report

# GitHub Security tab (SARIF)
doc-ai-slopcheck sarif findings.json > results.sarif

# Only scan changed files (CI)
doc-ai-slopcheck scan . --changed-files git --fail-on warning
```

Scanning a directory other than the current one works as expected: when you
pass exactly one directory and no `--repo-root`, that directory becomes the
repository root (paths and `.slopcheck.yaml` are resolved from there). Paths
outside the repository root are rejected with an error instead of being
silently skipped.

## What It Catches

Rules live in seven groups (`doc-ai-slopcheck rules` lists them all, with on/off):

| Group | Rules | Examples |
| ----- | :---: | -------- |
| **ai_slop** | 21 | Stub functions (Python/JS/Go/PHP), tests that cannot fail, chat bleed and emoji, identity refusals, plan/task IDs and history narrated in comments, comment essays, placeholders, hallucinated values, debug code left in |
| **security** | 11 | Hardcoded secrets, SQL built from strings, XSS (`dangerouslySetInnerHTML`, dynamic `innerHTML`), raw `$_GET`/`$_POST` into eval/shell/SQL/echo, obfuscation, weak hashing, ReDoS |
| **error_handling** | 11 | Empty catch/except, ignored Go errors, unhandled promises, unguarded `JSON.parse`, contradictory null checks, unreachable code |
| **concurrency** | 6 | Locks without release, thread-unsafe globals, missing `defer`, timers without cleanup, use-after-free |
| **maintainability** | 18 | Large functions (>150 lines), copy-pasted code across files, deep nesting, too many positional args, oversized classes, opt-in pass-through wrappers |
| **idioms** | 10 | Dependencies or hacks where a built-in exists (`moment`, `uuid`, `JSON.parse(JSON.stringify())`, `pytz`, `six`), mutable defaults, `==` and React antipatterns, `any` / `as unknown as` / `@ts-ignore`, `SELECT *` |
| **project** | 4 | Import boundaries, API contract breaks, undeclared imports, unused suppressions |

## Features

- **81 deterministic rules** — no LLM, no network, no randomness
- **7 languages** — Python, JS/TS, PHP (incl. Drupal .module/.inc/.install/.theme), Go, C/C++, SQL, Markdown
- **Cross-file duplication** — finds copy-pasted blocks within and across files, one finding per file pair
- **Prose slop** — comment essays, history narrated in comments, plan/ticket IDs, emoji in comments and logs
- **Code-aware** — rules about code skip comments and docstrings; rules about comments (TODOs, plan IDs, chat bleed) read them
- **Test code weighs less** — findings in tests, mocks and fixtures drop one severity level
- **HTML report** — standalone, shareable page that opens with a "Where to start" ranking of the files with the most kinds of problem
- **Inline suppression** — `# slopcheck: ignore[rule_id]`, or `# slopcheck: ignore-next[duplicate_code]` above a copied block
- **SARIF output** — integrates with GitHub Security tab
- **Diff-only mode** — scan only changed files (`--changed-files git`)
- **Baselines** — suppress existing findings, fail only on new ones
- **API snapshots** — detect removed API routes
- **Threaded** — multi-core scanning (`--jobs N`)
- **Confidence filtering** — `--min-confidence medium` for high-signal-only mode

## Severity

Findings are `error`, `warning` or `note`. `--fail-on` (default `error`) sets
the level that makes `scan` exit with status 1.

Findings in test and mock code (`tests/`, `mocks/`, `fixtures/`, `test_*.py`,
`*.test.ts`, `*Test.php`, …) are lowered one level — error to warning, warning
to note — and tagged `test-code`. Set `test_paths: []` in the config to treat
test code like production code.

SQL built from strings is an `error` when a value is spliced in, and a
`warning` when only a table or column name is (`FROM $table … WHERE id = ?`),
since names can't be bound as parameters.

## PHP and Drupal

`.php` files and Drupal's `.module`, `.inc`, `.install`, `.theme`, `.profile`
and `.engine` files are scanned. Only the project's own code is scanned by
default: `vendor/`, Drupal core (`web/core`, `docroot/core`, `html/core`),
contrib modules/themes/profiles, `libraries/`, `sites/*/files`, scaffold copies
(`default.settings.php`, `.ht.router.php`, `web/index.php`, …) and generated
files (`.phpstorm.meta.php`, `sites/simpletest`) are ignored.

PHP comments, docblocks, `#[Attributes]`, heredocs and inline HTML outside
`<?php ?>` are told apart, so rules don't fire on documentation or templates.

## GitHub Actions

```yaml
name: slopcheck
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # required by upload-sarif
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with: { python-version: '3.12' }
      - run: pip install doc-ai-slopcheck
      - run: doc-ai-slopcheck scan . --output findings.json --fail-on warning
      - if: always()
        run: |
          doc-ai-slopcheck github-annotations findings.json
          doc-ai-slopcheck sarif findings.json > results.sarif
          doc-ai-slopcheck html findings.json > slopcheck-report.html
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with: { sarif_file: results.sarif }
      - if: always()
        uses: actions/upload-artifact@v7
        with: { name: slopcheck-report, path: slopcheck-report.html }
```

## Baselines (Incremental Adoption)

```shell
# First run: baseline existing findings
doc-ai-slopcheck scan . --output findings.json --fail-on none
doc-ai-slopcheck create-baseline findings.json

# CI: only fail on NEW findings
doc-ai-slopcheck scan . --baseline .slopcheck/baseline.json --fail-on warning
```

## CLI Reference

| Command | Purpose |
| --------- | --------- |
| `doc-ai-slopcheck scan [paths]` | Scan files, write findings JSON |
| `doc-ai-slopcheck rules` | List rule IDs, on/off (with the project config) and what each checks |
| `doc-ai-slopcheck summary <file>` | Markdown summary |
| `doc-ai-slopcheck github-annotations <file>` | GitHub workflow annotations |
| `doc-ai-slopcheck sarif <file>` | SARIF v2.1.0 output |
| `doc-ai-slopcheck html <file> > report.html` | Standalone HTML report |
| `doc-ai-slopcheck create-baseline <file>` | Create fingerprint baseline |
| `doc-ai-slopcheck api-snapshot` | Snapshot API routes for contract checks |

### Key `scan` Options

| Option | Default | Description |
| -------- | --------- | ------------- |
| `--output` | `findings.json` | Findings JSON file; `-` for stdout |
| `--repo-root` | scanned dir, else `.` | Root for relative paths and config lookup |
| `--config` | `.slopcheck/config.yaml`, `.slopcheck.yaml` or `.slopcheck.yml` | Config file |
| `--fail-on` | `error` | Exit 1 at severity: `none` / `note` / `warning` / `error` |
| `--min-confidence` | `low` | Filter: `low` / `medium` / `high` |
| `--baseline` | — | Suppress fingerprints from baseline file |
| `--changed-files` | — | `git` or `@file.txt` for diff-only mode |
| `--jobs` | auto | Thread count (0=auto, 1=sequential) |
| `--api-baseline` | — | API snapshot for contract comparison |

## Configuration

Create `.slopcheck/config.yaml` (or `.slopcheck.yaml`) in the repository root:

```yaml
# Replaces the default list, so keep the defaults you still want
# (vendor, node_modules, Drupal core/contrib, ...).
ignored_paths:
  - "vendor/**"
  - "**/node_modules/**"
  - "services/legacy-api/**"

# Generated files (header says @generated, DO NOT EDIT or auto-generated) and
# bundled third-party files (first line is a /*! license banner) are skipped;
# set false to scan them.
skip_generated: true

# Paths treated as test code (findings drop one severity level); [] disables.
test_paths: ["*/tests/*", "*/mocks/*", "*Test.php", "test_*.py"]

rules:
  # Disable a rule
  js_loose_equality:
    enabled: false

  # Tune thresholds
  large_function:
    max_lines: 150
  duplicate_code:
    min_lines: 10        # normalised lines (blank and comment lines excluded)

  # Enable an opt-in rule with custom threshold
  deep_nesting:
    enabled: true
    max_depth: 5

  # Plan/ticket IDs in comments: add your own ID formats, e.g. decision records
  plan_reference_comment:
    patterns:
      - '\b(?:Task|Phase|Milestone|Sprint)\s+#?\d+\b'
      - '\bD-\d+\b'

  # One class per file is enforced for JS/TS; opt in for Python
  multiple_classes_per_file:
    python: true

  hallucinated_placeholder:
    allowed_domains: ["example.com", "localhost"]
```

## Project Layout

```shell
doc_ai_slopcheck/
├── cli.py                 — CLI commands
├── config.py              — Pydantic config models
├── models.py              — Finding, ScanResult (stable contract)
├── engine/
│   ├── scanner.py         — Threaded orchestrator, comment and test-code filters
│   ├── duplication.py     — Cross-file copy-paste detector
│   ├── context_filter.py  — Comment/docstring/string detection (Python, C-style, PHP)
│   ├── repo_files.py      — File discovery and ignore patterns
│   ├── suppression.py     — Inline ignore parser
│   └── api_routes.py      — Route extraction for API snapshots
├── rules/                 — one folder per group; base.py, registry.py
│   ├── ai_slop/
│   ├── security/
│   ├── error_handling/
│   ├── concurrency/
│   ├── maintainability/
│   ├── idioms/
│   └── project/
├── output/
│   ├── html_report.py     — Standalone HTML report with hotspot ranking
│   ├── sarif.py           — SARIF v2.1.0
│   ├── annotations.py     — GitHub annotations
│   └── markdown_summary.py
└── state/
    └── store.py           — Baseline persistence
```

## Development

Requires Python 3.12+ and [Poetry](https://python-poetry.org/) 2.x.

```shell
poetry install
poetry run pytest
poetry run ruff check .
poetry build
```

Tests and ruff run on GitHub Actions for every push and pull request, on
Python 3.12 and 3.13 (`.github/workflows/tests.yml`).

## License

[MIT](LICENSE) — Euraika 2026. Fork maintained by Digitalist Open Cloud.
