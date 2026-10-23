"""Rendering a run's result: a self-contained HTML report and a short terminal summary."""

from __future__ import annotations

import html
import os
from datetime import datetime
from pathlib import Path

STOP_REASONS = {
    "max_cases": "Requested number of inputs reached",
    "time_limit": "Time limit reached",
    "input_space_exhausted": "No new distinct inputs could be generated (input space exhausted)",
    "coverage_plateau": "Coverage stopped growing (top-up disabled)",
    "counterexample_found": "Stopped at the first counterexample",
    None: "Run did not finish",
}

OUTCOMES = [
    ("same_output", "Same output", "both returned equal results", True),
    ("both_error", "Both failed", "both raised an error or timed out", True),
    ("different_output", "Different output", "both returned, with different results", False),
    ("b_error_only", "Only the candidate failed", "the reference returned, the candidate failed", False),
    ("a_error_only", "Only the reference failed", "the reference rejected the input; not scored", None),
]

CSS = """
:root{--bg:#f7f7f5;--panel:#ffffff;--text:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;
--good:#1f7a4d;--good-bg:#e5f4ec;--bad:#b42318;--bad-bg:#fdecea;--warn:#8a5a00;--warn-bg:#fdf3dc;
--accent:#2f5bd3;--hit:#e8f5ec;--miss:#fbe7e7;--partial:#fff4d6;--code-bg:#fbfbfa;
--good-soft:#7cc79e;--bad-soft:#ef9a90}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#141416;--panel:#1d1d20;
--text:#ececf0;--muted:#a0a0a8;--line:#2e2e33;--good:#5ccf95;--good-bg:#173326;--bad:#ff7b6e;
--bad-bg:#3a1a17;--warn:#f0c060;--warn-bg:#3a2e12;--accent:#8aa8ff;--hit:#16301f;--miss:#3a1d1d;
--partial:#3a3014;--code-bg:#18181b;--good-soft:#2f7a52;--bad-soft:#9a443b}}
:root[data-theme="dark"]{--bg:#141416;--panel:#1d1d20;
--text:#ececf0;--muted:#a0a0a8;--line:#2e2e33;--good:#5ccf95;--good-bg:#173326;--bad:#ff7b6e;
--bad-bg:#3a1a17;--warn:#f0c060;--warn-bg:#3a2e12;--accent:#8aa8ff;--hit:#16301f;--miss:#3a1d1d;
--partial:#3a3014;--code-bg:#18181b;--good-soft:#2f7a52;--bad-soft:#9a443b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:14px 14px 28px}
header{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:10px}
h1{font-size:17px;margin:0}h2{font-size:11px;margin:14px 0 5px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.sub{color:var(--muted);font-size:12px}.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.top{display:grid;grid-template-columns:1.1fr 1fr;gap:10px;align-items:start}
.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media (max-width:620px){.top,.two{grid-template-columns:1fr}}
.verdict{padding:10px 14px;border-radius:8px;border:1px solid var(--line);background:var(--panel)}
.verdict.good{background:var(--good-bg);border-color:transparent}.verdict.bad{background:var(--bad-bg);border-color:transparent}
.verdict .big{font-size:20px;font-weight:650;line-height:1.2}.verdict.good .big{color:var(--good)}.verdict.bad .big{color:var(--bad)}
.verdict .big small{font-size:13px;font-weight:500}
.bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden;margin-top:6px}
.bar>span{display:block;height:100%;background:var(--accent)}
.stats{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:6px 10px;
display:grid;grid-template-columns:auto 1fr;gap:1px 10px;font-size:12px;align-content:center}
.stats dt{color:var(--muted)}.stats dd{margin:0}
.warn{background:var(--warn-bg);color:var(--warn);border-radius:6px;padding:5px 10px;margin:6px 0 0;font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:3px 8px;border-bottom:1px solid var(--line);vertical-align:top;font-size:12px}
th{color:var(--muted);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.03em}
tr:last-child td{border-bottom:none}td.num{text-align:right;font-variant-numeric:tabular-nums}
td pre{margin:0;white-space:pre-wrap;word-break:break-all;font-size:11.5px}
.tag{display:inline-block;font-size:10.5px;padding:0 6px;border-radius:8px;background:var(--line);white-space:nowrap}
.tag.bad{background:var(--bad-bg);color:var(--bad)}.tag.good{background:var(--good-bg);color:var(--good)}
details summary{cursor:pointer;color:var(--accent);font-size:12px;margin:4px 0}
.code-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media (max-width:620px){.code-grid{grid-template-columns:1fr}}
.code{background:var(--code-bg);border:1px solid var(--line);border-radius:8px;overflow:auto}
.code .head{padding:5px 10px;border-bottom:1px solid var(--line);font-size:12px;background:var(--panel)}
.code table{border:none;border-radius:0;background:transparent}
.code td{padding:0 8px;border:none;font-size:11.5px;line-height:1.35;white-space:pre;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.code td.ln{color:var(--muted);text-align:right;user-select:none;width:1%}
tr.hit td.src{background:var(--hit)}tr.miss td.src{background:var(--miss)}tr.partial td.src{background:var(--partial)}
.legend{float:right;margin-top:-20px}.legend span{display:inline-block;margin-left:10px;font-size:11px;color:var(--muted)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.cfg td:first-child{color:var(--muted);white-space:nowrap;width:1%}
.outcomes{display:flex;gap:12px;align-items:center;background:var(--panel);border:1px solid var(--line);
border-radius:8px;padding:8px 10px}
.pie{width:104px;height:104px;flex:none}.pie path,.pie circle{stroke-linecap:butt}
.pie-n{font-size:17px;font-weight:650;fill:var(--text)}.pie-l{font-size:9px;fill:var(--muted)}
.legend-t{border:none;background:transparent}.legend-t td{padding:1px 4px;border:none;white-space:nowrap}
.legend-t th{padding:5px 4px 1px;border:none;text-transform:none;letter-spacing:0}
.legend-t tr:first-child th{padding-top:0}
.sw{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}
.cfg td{word-break:break-all}
"""


def _e(s) -> str:
    return html.escape(str(s))


def _pct(a, b) -> str:
    return f"{100 * a / b:.0f}%" if b else "n/a"


def warnings(res: dict) -> list:
    out = []
    cov = res.get("coverage", {})
    for name, who in (("A", "the reference"), ("B", "the candidate")):
        c = cov.get(name)
        if c and c["lines"][1] and c["lines"][0] < c["lines"][1]:
            out.append(f"{len(c['missing_lines'])} line(s) of {who} were never executed "
                       f"(lines {', '.join(map(str, c['missing_lines'][:12]))}"
                       f"{', ...' if len(c['missing_lines']) > 12 else ''}); behaviour there was not compared.")
    o = res["outcomes"]
    if o["a_error_only"]:
        out.append(f"{o['a_error_only']} input(s) were not scored because the reference rejected them while the "
                   "candidate returned a result.")
    att = sum(res["attempts_by_phase"].values())
    if att and res["generator_failures"] > 0.1 * att:
        out.append(f"The input generator failed on {res['generator_failures']} of {att} attempts.")
    if res["stop_reason"] == "input_space_exhausted":
        out.append(f"Only {res['distinct_inputs']} distinct inputs could be generated; the generator's input "
                   "space may be small, so check that it covers the intended inputs.")
    return out


def _code_pane(title: str, path: str, cov: dict) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    executed = set(cov.get("executed_lines", []))
    missing = set(cov.get("missing_lines", []))
    partial = {b[0] for b in cov.get("missing_branches", [])}
    rows = []
    for i, line in enumerate(lines, 1):
        cls = "miss" if i in missing else "partial" if i in partial else "hit" if i in executed else ""
        rows.append(f'<tr class="{cls}"><td class="ln">{i}</td><td class="src">{_e(line) or " "}</td></tr>')
    l, b = cov.get("lines", [0, 0]), cov.get("branches", [0, 0])
    head = (f"<b>{_e(title)}</b> <span class='sub mono'>{_e(os.path.basename(path))}</span>"
            f" <span class='sub'>· lines {l[0]}/{l[1]} · branches {b[0]}/{b[1]}</span>")
    return f'<div class="code"><div class="head">{head}</div><table>{"".join(rows)}</table></div>'


# colours of the outcome slices (theme variables, so the chart follows light and dark mode)
OUTCOME_COLOURS = {"same_output": "var(--good)", "both_error": "var(--good-soft)", "different_output": "var(--bad)",
                   "b_error_only": "var(--bad-soft)", "a_error_only": "var(--muted)"}


def _outcome_pie(o: dict) -> str:
    """The five outcomes as a donut chart (inline SVG) with a legend that keeps every outcome, its meaning, and
    its count, including outcomes with no input."""
    import math
    total = sum(o[k] for k, *_ in OUTCOMES)
    r, cx, cy, w = 42, 55, 55, 20
    arcs, start = [], -math.pi / 2
    for key, label, _, _ in OUTCOMES:
        n = o[key]
        if not total or not n:
            continue
        frac = n / total
        if frac >= 0.9999:   # a single outcome: a full ring
            arcs.append(f"<circle cx='{cx}' cy='{cy}' r='{r}' fill='none' stroke='{OUTCOME_COLOURS[key]}' "
                        f"stroke-width='{w}'><title>{_e(label)}: {n}</title></circle>")
            break
        end = start + 2 * math.pi * frac
        x1, y1 = cx + r * math.cos(start), cy + r * math.sin(start)
        x2, y2 = cx + r * math.cos(end), cy + r * math.sin(end)
        arcs.append(f"<path d='M {x1:.2f} {y1:.2f} A {r} {r} 0 {1 if frac > 0.5 else 0} 1 {x2:.2f} {y2:.2f}' "
                    f"fill='none' stroke='{OUTCOME_COLOURS[key]}' stroke-width='{w}'>"
                    f"<title>{_e(label)}: {n} ({100 * frac:.1f}%)</title></path>")
        start = end
    if not total:
        arcs.append(f"<circle cx='{cx}' cy='{cy}' r='{r}' fill='none' stroke='var(--line)' stroke-width='{w}'/>")
    svg = (f"<svg class='pie' viewBox='0 0 110 110' role='img' aria-label='Outcomes of the {total} inputs'>"
           + "".join(arcs)
           + f"<text x='{cx}' y='{cy - 2}' text-anchor='middle' class='pie-n'>{total}</text>"
           f"<text x='{cx}' y='{cy + 11}' text-anchor='middle' class='pie-l'>inputs</text></svg>")
    legend = []
    for group, title, cls in ((True, "Agree", "good"), (False, "Disagree", "bad"), (None, "Not scored", "")):
        legend.append(f"<tr><th colspan='3'><span class='tag {cls}'>{title}</span></th></tr>")
        for key, label, meaning, good in OUTCOMES:
            if good is not group:
                continue
            pct = f"{100 * o[key] / total:.1f}%" if total else "n/a"
            legend.append(f"<tr title='{_e(meaning)}'><td><i class='sw' style='background:{OUTCOME_COLOURS[key]}'></i>"
                          f"{label}</td><td class='num'>{o[key]}</td><td class='num sub'>{pct}</td></tr>")
    return (f"<div class='outcomes'>{svg}<table class='legend-t'>{''.join(legend)}</table></div>")


def render_html(res: dict, meta: dict) -> str:
    title = f"{os.path.basename(meta['a_path'])} vs {os.path.basename(meta['b_path'])}"
    run_kind = "early stop" if res.get("mode") == "equivalence" else "full budget"
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Difuzzi Report</title><style>{CSS}</style></head><body><main>",
             f"<header><h1>Difuzzi report</h1><span class='sub'>{_e(title)} · {_e(res.get('level', ''))} level · "
             f"{run_kind} · {datetime.now().strftime('%Y-%m-%d %H:%M')}</span></header>"]

    if res.get("status") != "done":
        parts.append(f"<div class='verdict bad'><div class='big'>Run failed</div>"
                     f"<div>{_e(res.get('error', 'the fuzzing process did not finish'))}</div></div></main></body></html>")
        return "".join(parts)

    n, scored, o = res["distinct_inputs"], res["scored"], res["outcomes"]
    # ---- the score (or, with early stop, the verdict) and the run statistics side by side
    if res["mode"] == "equivalence":
        if res["verdict"] == "not_equivalent":
            verdict = ("<div class='verdict bad'><div class='big'>Not equivalent</div>"
                       f"<div>A counterexample was found after {n} distinct inputs (early stop: the similarity "
                       "score was not computed).</div></div>")
        else:
            verdict = ("<div class='verdict good'><div class='big'>No counterexample found</div>"
                       f"<div>The reference and the candidate agreed on all {scored} scored inputs ({n} distinct "
                       "inputs tested). This is evidence of equivalence, not a proof; see the coverage below.</div></div>")
    else:
        agree = res["agreement"]
        cls = "good" if agree == 1 else "bad" if agree is not None and agree < 1 else ""
        score = "n/a" if agree is None else f"{agree:.3f}"
        pct = "" if agree is None else f" <small>({100 * agree:.1f}% agreement)</small>"
        verdict = (f"<div class='verdict {cls}'><div class='big'>Similarity score {score}{pct}</div>"
                   f"<div>The reference and the candidate behaved the same on {o['same_output'] + o['both_error']} "
                   f"of {scored} scored inputs ({n} distinct inputs tested).</div>"
                   f"<div class='bar'><span style='width:{0 if agree is None else 100 * agree:.1f}%'></span></div></div>")
    d = res["distinct_by_phase"]
    cov = res.get("coverage", {})
    stats = [("Distinct inputs", f"{n} ({d['examples']} example, {n - d['examples']} generated)"),
             ("Stopped", STOP_REASONS.get(res["stop_reason"], res["stop_reason"])),
             ("Time", f"{res['elapsed']:.1f} s ({res['duplicates_skipped']} duplicates skipped)")]
    for name, who in (("A", "reference"), ("B", "candidate")):
        c = cov.get(name, {"lines": [0, 0], "branches": [0, 0]})
        stats.append((f"Coverage, {who}", f"lines {c['lines'][0]}/{c['lines'][1]} ({_pct(*c['lines'])}), "
                      f"branches {c['branches'][0]}/{c['branches'][1]}"))
    parts.append("<div class='top'>" + verdict + "<dl class='stats'>"
                 + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in stats) + "</dl></div>")
    for w in warnings(res):
        parts.append(f"<div class='warn'>{_e(w)}</div>")

    # ---- outcomes (pie chart) and run configuration side by side
    outcomes = [_outcome_pie(o)]
    cfg = res["config"]
    rows = [("Reference", meta["a_path"]), ("Candidate", meta["b_path"]),   # file names; the full path on hover
            ("Entry points", f"{meta.get('entry_a')} / {meta.get('entry_b')}" if res["level"] == "function" else "whole program"),
            ("Example inputs", len(meta.get("examples", []))), ("Input generator", meta.get("binding_source", "")),
            ("Max distinct inputs", cfg["max_cases"]), ("Time limit", f"{cfg['time_budget']} s"),
            ("Per-call timeout", f"{cfg['call_timeout']} s"), ("Random top-up", "on" if cfg["topup"] else "off"),
            ("Seed", cfg["seed"])]
    def cell(k, v):
        if k in ("Reference", "Candidate"):
            return f"<span title='{_e(v)}'>{_e(os.path.basename(str(v)))}</span>"
        return _e(v)
    config = ("<table class='cfg'>" + "".join(f"<tr><td>{_e(k)}</td><td class='mono'>{cell(k, v)}</td></tr>"
                                              for k, v in rows) + "</table>")
    parts.append("<div class='two'><div><h2>Outcomes</h2>" + "".join(outcomes) + "</div>"
                 "<div><h2>Run configuration</h2>" + config + "</div></div>")

    # ---- counterexamples: the first few, the rest one click away
    cx = res["counterexamples"]
    parts.append(f"<h2>Counterexamples{f' (first {len(cx)})' if cx else ''}</h2>")
    if cx:
        def table(rows):
            return ("<table><tr><th>Input</th><th>Reference</th><th>Candidate</th></tr>" + "".join(
                f"<tr><td><pre>{_e(c['input'])}</pre></td><td><pre>{_e(c['a'])}</pre></td>"
                f"<td><pre>{_e(c['b'])}</pre></td></tr>" for c in rows) + "</table>")
        parts.append(table(cx[:5]))
        if len(cx) > 5:
            parts.append(f"<details><summary>show {len(cx) - 5} more</summary>{table(cx[5:])}</details>")
    else:
        parts.append("<div class='sub'>None: the reference and the candidate agreed on every scored input.</div>")

    # ---- coverage on the source code
    parts.append("<h2>Coverage</h2><div class='legend'><span><i style='background:var(--hit)'></i>executed</span>"
                 "<span><i style='background:var(--partial)'></i>branch partly taken</span>"
                 "<span><i style='background:var(--miss)'></i>never executed</span></div><div class='code-grid'>"
                 + _code_pane("Reference", meta["a_path"], cov.get("A", {}))
                 + _code_pane("Candidate", meta["b_path"], cov.get("B", {})) + "</div>")
    parts.append("</main></body></html>")
    return "".join(parts)


def terminal_summary(res: dict) -> str:
    if res.get("status") != "done":
        return f"Run failed: {res.get('error', 'the fuzzing process did not finish')}"
    o, d = res["outcomes"], res["distinct_by_phase"]
    lines = []
    if res["mode"] == "equivalence":
        lines.append("Verdict:          " + ("NOT EQUIVALENT (counterexample found)" if res["verdict"] == "not_equivalent"
                                            else "no counterexample found"))
    else:
        a = res["agreement"]
        lines.append(f"Agreement:        {'n/a' if a is None else f'{100 * a:.2f}%'}  "
                     f"({o['same_output'] + o['both_error']}/{res['scored']} scored inputs)")
    lines.append(f"Distinct inputs:  {res['distinct_inputs']}  ({d['examples']} example input(s), "
                 f"{res['distinct_inputs'] - d['examples']} generated; {res['duplicates_skipped']} duplicates skipped)")
    lines.append(f"Stopped:          {STOP_REASONS.get(res['stop_reason'], res['stop_reason'])} after {res['elapsed']:.1f} s")
    for name, who in (("A", "reference: "), ("B", "candidate: ")):
        c = res.get("coverage", {}).get(name)
        if c:
            lines.append(f"Coverage {who}  lines {c['lines'][0]}/{c['lines'][1]}, branches {c['branches'][0]}/{c['branches'][1]}")
    if res["counterexamples"]:
        c = res["counterexamples"][0]
        lines.append(f"Counterexample:   input {c['input']}\n                  reference -> {c['a']}\n"
                     f"                  candidate -> {c['b']}")
    for w in warnings(res):
        lines.append(f"Warning:          {w}")
    return "\n".join(lines)


# ---- several candidates against one reference -----------------------------------------------------
def _row(name: str, res: dict) -> dict:
    """One candidate's line in the summary."""
    done = res.get("status") == "done"
    o = res.get("outcomes") or {}
    return {"candidate": name, "status": "done" if done else "failed",
            "verdict": res.get("verdict") if done and res.get("mode") == "equivalence" else None,
            "agreement": res.get("agreement") if done else None,
            "scored": res.get("scored") if done else None,
            "differences": (o.get("different_output", 0) + o.get("b_error_only", 0)) if done else None,
            "error": None if done else res.get("error", "the fuzzing process did not finish")}


def summary_rows(results: list) -> list:
    """Candidates ranked from most to least like A (failed runs last)."""
    rows = [_row(name, res) for name, res in results]
    return sorted(rows, key=lambda r: (r["status"] != "done", -(r["agreement"] if r["agreement"] is not None else -1),
                                       r["candidate"]))


def summary_terminal(results: list, mode: str) -> str:
    rows = summary_rows(results)
    w = max([len("Candidate")] + [len(r["candidate"]) for r in rows])
    head = f"{'Candidate':<{w}}  " + ("Verdict                 " if mode == "equivalence" else "Agreement   ") + "Differing inputs"
    lines = [head, "-" * len(head)]
    for r in rows:
        if r["status"] != "done":
            lines.append(f"{r['candidate']:<{w}}  run failed: {r['error']}")
            continue
        if mode == "equivalence":
            first = "NOT EQUIVALENT          " if r["verdict"] == "not_equivalent" else "no counterexample found "
        else:
            first = f"{100 * r['agreement']:8.2f}%   " if r["agreement"] is not None else "     n/a   "
        lines.append(f"{r['candidate']:<{w}}  {first}{r['differences']}/{r['scored']}")
    return "\n".join(lines)


def render_summary_html(a_path: str, results: list, links: dict, mode: str) -> str:
    """A ranked table of the candidates, each linked to its own report."""
    rows = summary_rows(results)
    cells = []
    for r in rows:
        href = links.get(r["candidate"])
        link = f"<a href='{_e(href)}'>{_e(r['candidate'])}</a>" if href else _e(r["candidate"])
        if r["status"] != "done":
            cells.append(f"<tr><td class='mono'>{link}</td><td colspan='2' class='sub'>run failed: {_e(r['error'])}</td></tr>")
            continue
        if mode == "equivalence":
            first = "<b>not equivalent</b>" if r["verdict"] == "not_equivalent" else "no counterexample found"
        else:
            first = "n/a" if r["agreement"] is None else f"{100 * r['agreement']:.2f}%"
        cells.append(f"<tr><td class='mono'>{link}</td><td>{first}</td>"
                     f"<td>{r['differences']} / {r['scored']}</td></tr>")
    title = "Verdict" if mode == "equivalence" else "Agreement with the reference"
    return ("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Candidate Summary</title><style>{CSS}</style></head><body><main>"
            f"<h1>{len(rows)} candidates against {_e(Path(a_path).name)}</h1>"
            f"<p class='sub'>Ranked from most to least like the reference. Each candidate was fuzzed with the "
            f"same input generator; follow a name for its full report.</p>"
            f"<table><tr><th>Candidate</th><th>{title}</th><th>Differing inputs</th></tr>{''.join(cells)}</table>"
            "</main></body></html>")
