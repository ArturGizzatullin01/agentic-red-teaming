"""src/memnotsafe/reporting/html_report.py — report.html: executive summary,
funnel таблица, находки с causal trace и evidence. Самодостаточный статический
файл — без CDN/сети, пригоден для демонстрации жюри офлайн."""

from __future__ import annotations

import html
import json
from pathlib import Path

from memnotsafe.core.models import CampaignResult
from memnotsafe.reporting.findings import Finding, build_findings
from memnotsafe.tracing.causal_graph import build_causal_chain, flatten_linear

_STAGE_ORDER = ["write", "persistence", "retrieval", "adoption", "tool", "external_effect"]
_STAGE_LABEL = {
    "write": "WRITE",
    "persistence": "PERSIST",
    "retrieval": "RETRIEVE",
    "adoption": "ADOPT",
    "tool": "TOOL",
    "external_effect": "CONSEQUENCE",
}


def _verdict_glyph(v: bool | None) -> str:
    if v is True:
        return '<span class="ok">✔</span>'
    if v is False:
        return '<span class="fail">✘</span>'
    return '<span class="unk">?</span>'


def _esc(x: object) -> str:
    return html.escape(str(x))


def _funnel_table(funnel: dict) -> str:
    rows = []
    for stage in _STAGE_ORDER:
        c = funnel.get(stage, {"pass": 0, "fail": 0, "unknown": 0, "total": 0})
        rows.append(
            f"<tr><td>{_STAGE_LABEL[stage]}</td><td>{c['pass']}</td><td>{c['fail']}</td>"
            f"<td>{c['unknown']}</td><td>{c['pass']}/{c['total']}</td></tr>"
        )
    return "\n".join(rows)


def _lifecycle_ladder(stages: dict[str, bool | None]) -> str:
    parts = [f'<span class="stage-chip">{_STAGE_LABEL[s]} {_verdict_glyph(stages.get(s))}</span>' for s in _STAGE_ORDER]
    return " → ".join(parts)


def _causal_trace_html(events: list[dict]) -> str:
    if not events:
        return '<p class="muted">Трасса недоступна (telemetry не поддерживается таргетом).</p>'
    nodes = build_causal_chain(events)
    flat = flatten_linear(nodes)
    items = []
    for e in flat:
        label = e.get("event", "?")
        detail = e.get("tool") or e.get("detail", {}).get("scope") or ""
        args = f" {json.dumps(e.get('arguments'), ensure_ascii=False)}" if e.get("arguments") else ""
        items.append(f'<li><code>{_esc(label)}</code> {_esc(detail)}{_esc(args)}</li>')
    return "<ol class='causal-chain'>" + "\n".join(items) + "</ol>"


def _finding_card(f: Finding, events: list[dict]) -> str:
    status_class = "success" if f.status == "SUCCESS" else "not-exploitable"
    evidence_json = _esc(json.dumps(f.evidence, ensure_ascii=False, indent=2))
    return f"""
<article class="finding {status_class}">
  <header>
    <h3>{_esc(f.title)} <span class="badge sev-{f.severity.lower()}">{_esc(f.severity)}</span>
      <span class="badge status-{f.status.lower().replace('_','-')}">{_esc(f.status)}</span></h3>
    <p class="muted">{_esc(f.case_id)} · attacker={_esc(f.attacker)} · victim={_esc(f.victim)} ·
       ATLAS {_esc(f.atlas_technique)} ({_esc(f.atlas_tactic)}) · OWASP {_esc(f.owasp_asi)}</p>
  </header>
  <div class="ladder">{_lifecycle_ladder(f.stages)}</div>
  <details>
    <summary>Причинная трасса</summary>
    {_causal_trace_html(events)}
  </details>
  <details>
    <summary>Evidence (raw JSON)</summary>
    <pre class="evidence">{evidence_json}</pre>
  </details>
  <p class="repro"><strong>Воспроизведение:</strong> <code>memnotsafe run --scenario scenarios/{_esc(f.family)}.yaml --output runs/repro-{_esc(f.case_id)}</code>
     <br><span class="muted">case_id={_esc(f.case_id)} — конкретный прогон см. в evidence/ и traces/ исходного runs/-каталога.</span></p>
</article>"""


_CSS = """
:root{--bg:#0b0d12;--panel:#141821;--text:#e8ecf3;--muted:#8b93a7;--ok:#3ddc84;--fail:#ff5d6c;--unk:#f5c344;
      --crit:#ff3b5c;--high:#ff8a3d;--med:#f5c344;--info:#5b9dff;--border:#232838;}
@media (prefers-color-scheme: light){
  :root{--bg:#f7f8fb;--panel:#ffffff;--text:#161a22;--muted:#5b6472;--border:#e3e6ee;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;}
.wrap{max-width:980px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:32px 0 12px;border-bottom:1px solid var(--border);padding-bottom:6px}
.muted{color:var(--muted);font-size:13px}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
.stat .n{font-size:24px;font-weight:700}
.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);font-size:13px}
th{color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:none}
.finding{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:16px}
.finding.success{border-left:4px solid var(--fail)}
.finding.not-exploitable{border-left:4px solid var(--ok);opacity:.85}
.badge{display:inline-block;font-size:11px;padding:2px 8px;border-radius:999px;margin-left:6px;vertical-align:middle}
.sev-critical{background:var(--crit);color:#fff}
.sev-high{background:var(--high);color:#1a1200}
.sev-medium{background:var(--med);color:#1a1200}
.sev-info{background:var(--info);color:#fff}
.status-success{background:var(--fail);color:#fff}
.status-not-exploitable{background:var(--ok);color:#04210f}
.ladder{margin:10px 0;font-size:13px}
.stage-chip{display:inline-block;margin-right:2px}
.ok{color:var(--ok)} .fail{color:var(--fail)} .unk{color:var(--unk)}
.causal-chain{font-size:13px;margin:8px 0 0 18px}
.causal-chain code{background:rgba(127,127,127,.15);padding:1px 5px;border-radius:4px}
pre.evidence{background:rgba(127,127,127,.08);padding:12px;border-radius:8px;overflow:auto;font-size:12px;max-height:400px}
.repro code{background:rgba(127,127,127,.15);padding:1px 6px;border-radius:4px;font-size:12px}
details summary{cursor:pointer;font-size:13px;color:var(--muted);margin-top:8px}
"""


def render_html(campaign: CampaignResult, run_events_by_case: dict[str, list[dict]] | None = None) -> str:
    run_events_by_case = run_events_by_case or {}
    findings = build_findings(campaign.results)
    m = campaign.aggregate_metrics
    successful = [f for f in findings if f.status == "SUCCESS"]

    def pct(x: float | None) -> str:
        return f"{x * 100:.0f}%" if x is not None else "н/д"

    cards = "\n".join(
        _finding_card(f, run_events_by_case.get(f.case_id, [])) for f in sorted(findings, key=lambda f: f.status != "SUCCESS")
    )

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Your Memory Is Not Safe — {_esc(campaign.scenario_id)}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
  <h1>Your Memory Is Not Safe — {_esc(campaign.scenario_id)}</h1>
  <p class="muted">Agentic Memory Red Teaming · run_id={_esc(campaign.run_id)} · попыток: {campaign.attempts}</p>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat"><div class="n">{m['attempts']}</div><div class="l">Attempts</div></div>
    <div class="stat"><div class="n">{m['successful']}</div><div class="l">Successful</div></div>
    <div class="stat"><div class="n">{pct(m['end_to_end_asr'])}</div><div class="l">End-to-End ASR</div></div>
    <div class="stat"><div class="n">{len(successful)}</div><div class="l">Critical/High findings</div></div>
  </div>

  <h2>Stage funnel</h2>
  <table>
    <tr><th>Stage</th><th>Pass</th><th>Fail</th><th>Unknown</th><th>Rate</th></tr>
    {_funnel_table(m['funnel'])}
  </table>

  <h2>Findings ({len(findings)})</h2>
  {cards}
</div></body></html>"""


def write_html_report(campaign: CampaignResult, output_path: Path, run_events_by_case: dict[str, list[dict]] | None = None) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(campaign, run_events_by_case), encoding="utf-8")
    return output_path
