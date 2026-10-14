from __future__ import annotations

from collections import Counter, defaultdict
from html import escape
from pathlib import PurePath

from doc_ai_slopcheck.models import Finding, ScanResult, Severity

_ORDER = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.NOTE: 2}
_WEIGHT = {Severity.ERROR: 10, Severity.WARNING: 3, Severity.NOTE: 1}
_HOTSPOTS = 10

_CSS = """
:root {
  --paper: #f5f2ec; --ink: #161616; --muted: #6b665e; --rule: #d9d3c8;
  --error: #a8321e; --warning: #a8751a; --note: #4f5f68;
  --serif: "Iowan Old Style", "Charter", "Palatino Linotype", Georgia, serif;
  --sans: "Helvetica Neue", Helvetica, Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink);
  font: 15px/1.55 var(--sans); -webkit-font-smoothing: antialiased; }
main { max-width: 960px; margin: 0 auto; padding: 48px 24px 96px; }
.masthead { display: flex; justify-content: space-between; align-items: baseline;
  flex-wrap: wrap; gap: 8px; border-bottom: 2px solid var(--ink); padding-bottom: 10px; }
.wordmark { font: 700 13px var(--sans); letter-spacing: .32em; text-transform: uppercase; }
.dateline, .kicker, th, .label { font-size: 11px; letter-spacing: .14em;
  text-transform: uppercase; color: var(--muted); }
h1 { font: 400 clamp(34px, 6vw, 56px)/1.08 var(--serif); letter-spacing: -.01em;
  margin: 48px 0 16px; max-width: 18ch; }
.standfirst { font: italic 19px/1.5 var(--serif); color: var(--muted); max-width: 60ch;
  margin: 0 0 40px; word-break: break-word; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  border-top: 1px solid var(--ink); border-bottom: 1px solid var(--rule); margin-bottom: 64px; }
.stat { padding: 18px 20px 20px 0; }
.stat + .stat { border-left: 1px solid var(--rule); padding-left: 20px; }
.stat b { display: block; font: 400 44px/1 var(--serif); margin-top: 8px; }
h2.section { font: 700 12px var(--sans); letter-spacing: .24em; text-transform: uppercase;
  border-top: 2px solid var(--ink); padding-top: 10px; margin: 64px 0 8px; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-weight: 400; padding: 10px 0; border-bottom: 1px solid var(--ink); }
td { padding: 10px 0; border-bottom: 1px solid var(--rule); vertical-align: baseline; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
th:not(:last-child), td:not(:last-child) { padding-right: 20px; }
td a { color: inherit; text-decoration: none; font-family: var(--serif); font-size: 17px;
  overflow-wrap: anywhere; }
td a:hover { text-decoration: underline; text-underline-offset: 3px; }
.sev { font-size: 11px; letter-spacing: .14em; text-transform: uppercase; }
.sev-error { color: var(--error); } .sev-warning { color: var(--warning); }
.sev-note { color: var(--note); }
details.rule { border-bottom: 1px solid var(--rule); }
details.rule > summary { list-style: none; cursor: pointer; padding: 28px 0 24px;
  display: grid; grid-template-columns: 1fr auto; gap: 4px 24px; align-items: baseline; }
details.rule > summary::-webkit-details-marker { display: none; }
summary h3 { grid-column: 1; font: 400 28px/1.2 var(--serif); margin: 2px 0 0; }
summary .count { grid-column: 2; grid-row: 1 / span 2; font: 400 34px var(--serif); }
summary .count::after { content: " +"; color: var(--muted); font-size: 22px; }
details[open] > summary .count::after { content: " \\2212"; }
.rule-id { font: 12px var(--mono); color: var(--muted); }
ol.findings { list-style: none; margin: 0 0 32px; padding: 0; }
ol.findings li { display: grid; grid-template-columns: 220px 1fr; gap: 4px 28px;
  padding: 16px 0; border-top: 1px solid var(--rule); }
.where { font: 12px/1.5 var(--mono); word-break: break-all; }
.where span { display: block; color: var(--muted); }
.message { margin: 0; max-width: 62ch; }
pre { font: 12.5px/1.5 var(--mono); background: #ebe6dc; padding: 10px 12px; margin: 10px 0 0;
  white-space: pre-wrap; word-break: break-word; border-left: 2px solid var(--ink); }
.suggestion { font: italic 15px/1.5 var(--serif); color: var(--muted); margin: 10px 0 0; }
.empty { font: italic 22px var(--serif); color: var(--muted); }
.note { font: italic 15px/1.5 var(--serif); color: var(--muted); margin: 0 0 8px; }
.hotspots td { padding: 16px 0; }
td.rank { font: 400 28px/1 var(--serif); color: var(--muted); width: 56px; }
.hot-file { display: block; font: 400 21px/1.25 var(--serif); overflow-wrap: anywhere; }
.hot-path { display: block; font: 12px/1.5 var(--mono); color: var(--muted);
  overflow-wrap: anywhere; }
.hot-rules { display: block; font-size: 12px; margin-top: 6px; }
.hot-rules a { color: var(--ink); text-underline-offset: 3px; }
.score { display: block; font: 400 30px/1 var(--serif); }
.tally { display: block; margin-top: 6px; white-space: nowrap; }
.tally span + span::before { content: " · "; color: var(--muted); }
footer { margin-top: 80px; padding-top: 12px; border-top: 1px solid var(--ink);
  font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); }
@media (max-width: 640px) {
  ol.findings li { grid-template-columns: 1fr; }
  .stat + .stat { border-left: 0; padding-left: 0; }
  .tally span { display: block; }
  .tally span + span::before { content: none; }
  td.rank { width: 36px; font-size: 22px; }
}
@media print { body { background: #fff; } details.rule > summary .count::after { content: ""; } }
"""


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def _finding(f: Finding) -> str:
    loc = f.location
    parts = [f'<p class="message">{escape(f.message)}</p>']
    if f.evidence:
        parts.append(f"<pre>{escape(f.evidence)}</pre>")
    if f.suggestion:
        parts.append(f'<p class="suggestion">{escape(f.suggestion)}</p>')
    return (
        f'<li><div class="where">{escape(PurePath(loc.path).name)}:{loc.line}'
        f"<span>{escape(loc.path)}</span></div><div>{''.join(parts)}</div></li>"
    )


def _score(group: list[Finding]) -> int:
    """Each rule counts once per file at its worst severity, so a file with many
    kinds of problem outranks one rule firing many times."""
    worst: dict[str, int] = {}
    for f in group:
        worst[f.rule_id] = max(worst.get(f.rule_id, 0), _WEIGHT[f.severity])
    return sum(worst.values())


def _hotspots(findings: list[Finding]) -> str:
    """Production files ranked by breadth of problems: where a team should start."""
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if "test-code" not in f.tags:
            by_file[f.location.path].append(f)
    if not by_file:
        return ""
    ranked = sorted(by_file.items(), key=lambda kv: (-_score(kv[1]), kv[0]))[:_HOTSPOTS]
    rows = []
    for rank, (path, group) in enumerate(ranked, start=1):
        rule_ids = [r for r, _ in Counter(f.rule_id for f in group).most_common()]
        counts = Counter(f.severity for f in group)
        tally = "".join(
            f'<span class="sev sev-{s.value}">{_plural(counts[s], s.value)}</span>'
            for s in (Severity.ERROR, Severity.WARNING, Severity.NOTE)
            if counts[s]
        )
        rules = ", ".join(f'<a href="#{escape(r)}">{escape(r)}</a>' for r in rule_ids)
        rows.append(
            f'<tr><td class="rank">{rank:02d}</td><td><span class="hot-file">'
            f"{escape(PurePath(path).name)}</span><span class=\"hot-path\">{escape(path)}</span>"
            f'<span class="hot-rules">{rules}</span></td>'
            f'<td class="num"><b class="score">{_score(group)}</b>'
            f'<span class="tally">{tally}</span></td></tr>'
        )
    return (
        '<h2 class="section">Where to start</h2>'
        '<p class="note">Production files ranked by how many kinds of problem they have. '
        "Each rule counts once per file, weighted error 10, warning 3, note 1. "
        "Test and mock code is left out.</p>"
        '<table class="hotspots"><thead><tr><th>No.</th><th>File</th>'
        f'<th class="num">Score</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'
    )


def render_html(scan_result: ScanResult) -> str:
    findings = scan_result.findings
    stats = scan_result.stats
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)

    def rank(rule_id: str) -> tuple[int, int, str]:
        group = by_rule[rule_id]
        return (min(_ORDER[f.severity] for f in group), -len(group), rule_id)

    rules = sorted(by_rule, key=rank)
    severity_counts = Counter(f.severity for f in findings)
    repo_name = PurePath(scan_result.repo_root).name or scan_result.repo_root
    generated = scan_result.generated_at
    date = f"{generated.day} {generated:%B %Y}"

    stat_cells = "".join(
        f'<div class="stat"><span class="label">{label}</span><b>{value:,}</b></div>'
        for label, value in [
            ("Errors", severity_counts[Severity.ERROR]),
            ("Warnings", severity_counts[Severity.WARNING]),
            ("Notes", severity_counts[Severity.NOTE]),
            ("Files scanned", stats.scanned_files),
        ]
    )

    if findings:
        index_rows = []
        sections = []
        for rule_id in rules:
            group = sorted(by_rule[rule_id], key=lambda f: (f.location.path, f.location.line))
            sev = min((f.severity for f in group), key=_ORDER.__getitem__).value
            title = escape(group[0].title)
            index_rows.append(
                f'<tr><td><a href="#{escape(rule_id)}">{title}</a></td>'
                f'<td><span class="sev sev-{sev}">{sev}</span></td>'
                f'<td class="num">{len(group):,}</td></tr>'
            )
            is_open = " open" if sev == "error" else ""
            sections.append(
                f'<details class="rule" id="{escape(rule_id)}"{is_open}><summary>'
                f'<span class="sev sev-{sev}">{sev}</span>'
                f'<span class="count">{len(group):,}</span>'
                f'<h3>{title}</h3><span class="rule-id">{escape(rule_id)}</span></summary>'
                f'<ol class="findings">{"".join(_finding(f) for f in group)}</ol></details>'
            )
        body = (
            f"{_hotspots(findings)}"
            '<h2 class="section">Index</h2><table><thead><tr><th>Rule</th><th>Severity</th>'
            f'<th class="num">Findings</th></tr></thead><tbody>{"".join(index_rows)}</tbody>'
            f'</table><h2 class="section">Findings</h2>{"".join(sections)}'
        )
        headline = f"{_plural(len(findings), 'finding')} across {_plural(len(rules), 'rule')}"
    else:
        body = '<p class="empty">Nothing to report. The code reads clean.</p>'
        headline = "No findings"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Slopcheck · {escape(repo_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header class="masthead"><span class="wordmark">Slopcheck</span>
<span class="dateline">Report · {escape(repo_name)} · {date}</span></header>
<h1>{headline}</h1>
<p class="standfirst">A deterministic reading of {escape(scan_result.repo_root)}:
{_plural(stats.scanned_files, 'file')} scanned, {stats.suppressed:,} suppressed,
{_plural(stats.rule_errors, 'rule error')}.</p>
<section class="stats">{stat_cells}</section>
{body}
<footer>Generated by doc-ai-slopcheck · {escape(scan_result.generated_at.isoformat())}</footer>
</main>
</body>
</html>
"""
