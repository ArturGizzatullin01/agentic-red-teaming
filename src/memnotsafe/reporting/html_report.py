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


def _source_badge(prov: dict | None) -> str:
    """Бейдж источника рядом с глифом вердикта: `D` — доказано снимком памяти
    или телеметрией, `J` — вердикт держится на суждении модели. Читатель
    отличает одно от другого, не разворачивая ни одного блока (SC-004)."""
    if not prov:
        return ""
    if prov.get("verdict_source") == "judge":
        return '<span class="src src-j" title="подтверждено LLM-судьёй">J</span>'
    return f'<span class="src src-d" title="{_esc(prov.get("evidence_kind", ""))}">D</span>'


def _lifecycle_ladder(stages: dict[str, bool | None], provenance: dict | None = None) -> str:
    provenance = provenance or {}
    parts = [
        f'<span class="stage-chip">{_STAGE_LABEL[s]} {_verdict_glyph(stages.get(s))}'
        f'{_source_badge(provenance.get(s))}</span>'
        for s in _STAGE_ORDER
    ]
    return " → ".join(parts)


def _judge_block(f: Finding) -> str:
    """Блок стадии для судейских вердиктов и расхождений.

    Цитата экранируется как и любой текст таргета: она приходит из враждебного
    источника — из ответа агента, которого мы сами и отравили."""
    rows = []
    for stage in _STAGE_ORDER:
        prov = f.stage_provenance.get(stage) or {}
        judge = (f.judge_verdicts or {}).get(stage)
        if not judge:
            continue
        by_judge = prov.get("verdict_source") == "judge"
        head = (
            f'<strong>{_STAGE_LABEL[stage]}</strong> — '
            f'{"вердикт вынес судья" if by_judge else "вердикт детерминированный"}'
        )
        meta = (
            f'<div class="muted">модель {_esc(judge.get("model"))} · рубрика {_esc(judge.get("rubric"))} · '
            f'исход <code>{_esc(judge.get("outcome"))}</code> · уверенность {judge.get("confidence")}'
            + (f' · причина <code>{_esc(judge.get("error"))}</code>' if judge.get("error") else "")
            + "</div>"
        )
        quote = (
            f'<blockquote class="judge-quote">{_esc(judge.get("quote"))}</blockquote>'
            if judge.get("quote") else ""
        )
        clash = ""
        if prov.get("disagreement"):
            det = (f.stage_deterministic or {}).get(stage) or {}
            clash = (
                '<div class="clash"><span class="badge status-disagree">РАСХОЖДЕНИЕ</span>'
                f'<div>дословная проверка ({_esc(det.get("evidence_kind"))}): '
                f'<em>{_esc(det.get("reason"))}</em></div>'
                f'<div>судья: <em>{_esc(judge.get("rationale"))}</em></div></div>'
            )
        rows.append(f'<div class="judge-row">{head}{meta}{quote}{clash}</div>')
    if not rows:
        return ""
    return '<details open><summary>Вердикты судьи</summary>' + "\n".join(rows) + "</details>"


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


def _tier_plaque(f: Finding) -> str:
    """Явная плашка о пониженной достоверности: находка, где хотя бы одна
    композитная стадия судейская, держится на суждении модели, а не на
    снимке памяти (FR-015)."""
    if f.status == "SUCCESS" and f.llm_confirmed:
        return (
            '<p class="plaque">Подтверждено LLM-судьёй: достоверность ниже, чем у находки, '
            'доказанной снимком памяти или телеметрией. Цитата и версия рубрики — ниже.</p>'
        )
    if f.status == "INCONCLUSIVE":
        return (
            '<p class="plaque">Судья был недоступен на композитной стадии: это НЕ значит, '
            'что атака не прошла — вердикт не получен.</p>'
        )
    return ""


def _finding_card(f: Finding, events: list[dict]) -> str:
    status_class = {"SUCCESS": "success", "INCONCLUSIVE": "inconclusive"}.get(f.status, "not-exploitable")
    evidence_json = _esc(json.dumps(f.evidence, ensure_ascii=False, indent=2))
    tier = f' <span class="badge tier-{f.confidence_tier}">{_esc(f.confidence_tier)}</span>' if f.confidence_tier else ""
    return f"""
<article class="finding {status_class}">
  <header>
    <h3>{_esc(f.title)} <span class="badge sev-{f.severity.lower()}">{_esc(f.severity)}</span>
      <span class="badge status-{f.status.lower().replace('_','-')}">{_esc(f.status)}</span>{tier}</h3>
    <p class="muted">{_esc(f.case_id)} · attacker={_esc(f.attacker)} · victim={_esc(f.victim)} ·
       ATLAS {_esc(f.atlas_technique)} ({_esc(f.atlas_tactic)}) · OWASP {_esc(f.owasp_asi)}</p>
  </header>
  {_tier_plaque(f)}
  <div class="ladder">{_lifecycle_ladder(f.stages, f.stage_provenance)}</div>
  {_judge_block(f)}
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
.finding.inconclusive{border-left:4px solid var(--unk)}
.src{display:inline-block;font-size:10px;font-weight:700;line-height:1;padding:2px 4px;border-radius:3px;
     margin-left:3px;vertical-align:top;cursor:help}
.src-d{background:rgba(127,127,127,.25);color:var(--muted)}
.src-j{background:var(--info);color:#fff}
.status-disagree{background:var(--unk);color:#1a1200}
.status-inconclusive{background:var(--unk);color:#1a1200}
.tier-proved{background:rgba(127,127,127,.25);color:var(--muted)}
.tier-llm_confirmed{background:var(--info);color:#fff}
.plaque{background:rgba(91,157,255,.12);border-left:3px solid var(--info);padding:8px 12px;border-radius:6px;
        font-size:13px;margin:10px 0}
.judge-row{border-top:1px solid var(--border);padding:10px 0;font-size:13px}
.judge-row:first-of-type{border-top:none}
blockquote.judge-quote{margin:8px 0;padding:8px 12px;border-left:3px solid var(--info);
        background:rgba(127,127,127,.08);border-radius:0 6px 6px 0;font-style:italic}
.clash{margin-top:8px;padding:8px 12px;background:rgba(245,195,68,.10);border-radius:6px}
.clash .badge{margin-left:0;margin-bottom:4px}
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
