# doc-ai-slopcheck

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-75-blue)]()

**Deterministic scanner for AI-style code failures. 75 rules. No LLM. No backend.**

Digitalist fork of [ai-slopcheck](https://github.com/Euraika-Labs/ai_slopcheck) by Euraika, which is no longer published.

> Catches the mistakes AI coding assistants leave behind — stub functions, silent error handling, hallucinated placeholders, hardcoded secrets, and 70 more patterns across Python, JS/TS, PHP, Go, C/C++, SQL, and Markdown.

---

## Install

```bash
pip install git+https://github.com/Digitalist-Open-Cloud/AI-Slopcheck.git
```

## Quick Start

```bash
# Scan a project
doc-ai-slopcheck scan . --output findings.json --fail-on warning

# View results
doc-ai-slopcheck summary findings.json

# GitHub Security tab (SARIF)
doc-ai-slopcheck sarif findings.json

# Only scan changed files (CI)
doc-ai-slopcheck scan . --changed-files git --fail-on warning
```

## What It Catches

| Category | Rules | Examples |
|----------|:-----:|---------|
| **AI Detection** | 16 | Stub functions, instruction comments, plan/task IDs in comments, conversational bleed, identity refusals |
| **Security** | 7 | Hardcoded secrets, SQL injection, XSS, weak hashing, obfuscated code |
| **JavaScript / Node** | 11 | await-in-loop, unguarded JSON.parse, loose equality, React antipatterns |
| **Go** | 3 | Ignored errors, missing defer, wrong error wrapping |
| **PHP / Drupal** | 2 + shared | Stub functions, raw `$_GET`/`$_POST` into eval/shell/SQL/echo; plus PHP support in debug (incl. devel `dpm`), SQL, obfuscation, empty catch, large functions, duplication |
| **Python** | 1 | Mutable default arguments |
| **Cross-Language** | 17 | Debug code, unreachable code, deep inheritance, dangerous shell in markdown |
| **Data-Flow** | 4 | Contradictory null checks, lock safety, IDOR risk, thread-unsafe globals |
| **Quality** | 9 | Large functions (>150 lines), copy-pasted code across files, plus opt-in deep nesting |
| **API Contract** | 1 | Removed routes, deprecated endpoints |
| **Repo-Specific** | 1 | Import boundary violations |
| **Meta** | 1 | Unused suppression directives |

## Features

- **75 deterministic rules** — no LLM, no network, no randomness
- **7 languages** — Python, JS/TS, PHP (incl. Drupal .module/.inc/.install/.theme), Go, C/C++, SQL, Markdown
- **Inline suppression** — `# slopcheck: ignore[rule_id]`, or `# slopcheck: ignore-next[duplicate_code]` above a copied block
- **SARIF output** — integrates with GitHub Security tab
- **HTML report** — standalone, shareable page (`doc-ai-slopcheck html findings.json > report.html`)
- **Diff-only mode** — scan only changed files (`--changed-files git`)
- **Baselines** — suppress existing findings, fail only on new ones
- **API snapshots** — detect removed API routes
- **Tree-sitter** — optional AST context for better precision
- **Threaded** — multi-core scanning (`--jobs N`)
- **Confidence filtering** — `--min-confidence medium` for high-signal-only mode

## GitHub Actions

```yaml
name: slopcheck
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install git+https://github.com/Digitalist-Open-Cloud/AI-Slopcheck.git
      - run: doc-ai-slopcheck scan . --output findings.json --fail-on warning
      - run: doc-ai-slopcheck github-annotations findings.json
      - run: doc-ai-slopcheck sarif findings.json > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
```

## Baselines (Incremental Adoption)

```bash
# First run: baseline existing findings
doc-ai-slopcheck scan . --output findings.json --fail-on none
doc-ai-slopcheck create-baseline findings.json

# CI: only fail on NEW findings
doc-ai-slopcheck scan . --baseline .slopcheck/baseline.json --fail-on warning
```

## CLI Reference

| Command | Purpose |
|---------|---------|
| `doc-ai-slopcheck scan [paths]` | Scan files, write findings JSON |
| `doc-ai-slopcheck summary <file>` | Markdown summary |
| `doc-ai-slopcheck github-annotations <file>` | GitHub workflow annotations |
| `doc-ai-slopcheck sarif <file>` | SARIF v2.1.0 output |
| `doc-ai-slopcheck html <file> > report.html` | Standalone HTML report |
| `doc-ai-slopcheck create-baseline <file>` | Create fingerprint baseline |
| `doc-ai-slopcheck api-snapshot` | Snapshot API routes for contract checks |

### Key `scan` Options

| Option | Default | Description |
|--------|---------|-------------|
| `--fail-on` | `error` | Exit 1 at severity: `none` / `note` / `warning` / `error` |
| `--min-confidence` | `low` | Filter: `low` / `medium` / `high` |
| `--baseline` | — | Suppress fingerprints from baseline file |
| `--changed-files` | — | `git` or `@file.txt` for diff-only mode |
| `--jobs` | auto | Thread count (0=auto, 1=sequential) |
| `--api-baseline` | — | API snapshot for contract comparison |

## Configuration

Create `.slopcheck/config.yaml` (or `.slopcheck.yaml`):

```yaml
rules:
  # Disable a rule
  js_loose_equality:
    enabled: false
  
  # Enable an opt-in rule with custom threshold
  deep_nesting:
    enabled: true
    max_depth: 5
  
  # Configure detection
  hallucinated_placeholder:
    allowed_domains: ["example.com", "localhost"]
```

## Tree-sitter (Optional)

For better precision (~5% improvement on string/comment context detection):

```bash
pip install "doc-ai-slopcheck[ast] @ git+https://github.com/Digitalist-Open-Cloud/AI-Slopcheck.git"
# Or manually:
pip install tree-sitter-python tree-sitter-javascript tree-sitter-go tree-sitter-typescript
```

## Project Layout

```
doc_ai_slopcheck/
├── cli.py                 — 6 CLI commands
├── config.py              — 50+ Pydantic config models
├── models.py              — Finding, ScanResult (stable contract)
├── engine/
│   ├── scanner.py         — Threaded orchestrator
│   ├── duplication.py     — Cross-file copy-paste detector
│   ├── suppression.py     — Inline ignore parser
│   └── context_filter.py  — String/comment detector
├── parsers/
│   └── treesitter.py      — Optional AST adapter
├── rules/
│   ├── generic/           — 71 cross-repo rules
│   └── repo/              — 1 architecture rule
├── output/
│   ├── sarif.py           — SARIF v2.1.0
│   ├── annotations.py     — GitHub annotations
│   └── markdown_summary.py
└── state/
    └── store.py           — Baseline persistence
```

## Development

Requires Python 3.12+ and [Poetry](https://python-poetry.org/) 2.x.

```bash
poetry install            # add --all-extras for tree-sitter and requests
poetry run pytest
poetry run ruff check .
poetry build
```

## License

[MIT](LICENSE) — Euraika 2026. Fork maintained by Digitalist.
