"""src/memnotsafe/reporting/html_report.py — report.html (фича 002-reporting):
отчёт, которым можно пользоваться — сводка серии, список проведённых атак,
подробности случая с реальным чатом (baseline → delivery → trigger), стадии с
основаниями, judge-блок, описание атаки, ссылки на полные артефакты.

Дизайн-контракт (согласован с владельцем 2026-09-06, ревью issue #15 —
Yana, 2026-09-07):
- UI-хром на английском (универсально для команды/CI); тексты атак — как в
  метаданных семейств (источник — донор, переводит потребитель);
- шапка НЕ читается как вердикт: «memnotsafe report» + идентификация прогона;
- белый текст тел/заголовков при любом статусе; цвет только у меток вердикта
  (✔/✘/?), точек лестницы и бейджей; красный = подтверждённый компромисс;
- бейджи говорят своими именами: COMPROMISE CONFIRMED / NOT CONFIRMED /
  INCONCLUSIVE, severity с пояснением в tooltip;
- ASR всегда со знаменателем «N of M»; воронка с легендой «ok / failed · ?N»;
- лестница стадий — точечная: ● зелёная (True) / ● красная (False) / ○ жёлтая
  (UNKNOWN) со стрелками, БЕЗ слов; цвет точки = вердикт СТАДИИ, не composite;
- чат: РЕАЛЬНЫЕ записи прогона (send-then-record), шапка реплики несёт роль,
  actor (какой пользователь) и шаг; фазы с количеством реплик; в карточке —
  «What this attack does» из метаданных семейства; полные логи — по ссылкам,
  не в основном файле;
- чат свёрнут по умолчанию со строкой-превью; старые runs — фрагменты с честной
  пометкой «полный диалог не записывался»;
- сводка серии — три плитки, заголовок по центру без имени сценария;
- шапка БЕЗ подзаголовка run/series/attempts, БЕЗ легенды формата воронки и
  БЕЗ строки ограничений «static attacker · judge inactive · …» (ревью
  владельца 2026-09-07 по battery-26: строки удалены, не переносятся);
  h1 «memnotsafe report» — крупный (36px);
- чипы-фильтры над списком атак (vanilla JS, работает с file://, без CDN);
  фильтр Inconclusive рисуется только при наличии INCONCLUSIVE-карточек
  (ревью владельца по live10: пустая кнопка «Insufficient data 0» — шум);
- карточки — плитки по 3 в ряд (grid; ≤1200px — 2, ≤900px — 1), раскрытая
  карточка разворачивается на всю ширину; ASR — основная метрика: крупнее
  именно БУКВЫ «ASR», цифры у всех плиток одинаковые, в числе только процент
  без знаменателя (ревью владельца 2026-09-07: «долго листать вниз», затем
  «в 3 столбца»);
- все недоверенные тексты экранируются; судейские сведения показываются
  ФАКТИЧЕСКИЕ: источник вердикта, модель, рубрика, уверенность, цитата и оба
  вердикта при расхождении (003 FR-007/FR-008/FR-013,
  specs/003-llm-judge-oracle/contracts/report-provenance.md, раздел
  `report.html`); судьи не было — так и написано, «Judge inactive», и ни
  модель, ни рубрика при этом не выдумываются.

Reporter не реконструирует несуществующие сообщения; Reporter не оценивает успех.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from memnotsafe.core.models import AttackResult, CampaignResult, StageResult
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
_PHASE_LABEL = {"baseline": "Baseline", "delivery": "Delivery", "trigger": "Trigger"}

# Провенанс происхождения атаки (фича 004, FR-013/SC-007).
_ORIGIN_LABEL = {
    "handwritten": "handwritten pack",
    "corpus": "pre-generated corpus",
    "online": "online adaptation",
    "legacy-import": "legacy tool run (imported, donor stand)",
}

# Человекочитаемые статусы (data-status остаётся машинным значением фильтра).
_STATUS_TEXT = {
    "SUCCESS": "COMPROMISE CONFIRMED",
    "NOT_EXPLOITABLE": "NOT CONFIRMED",
    "INCONCLUSIVE": "INCONCLUSIVE",
}


def _esc(x: object) -> str:
    return html.escape(str(x), quote=True)


def _stage_dot(v: bool | None) -> str:
    """Точка лестницы: цвет = вердикт СТАДИИ (не composite)."""
    if v is True:
        color, glyph = "var(--ok)", "●"
    elif v is False:
        color, glyph = "var(--fail)", "●"
    else:
        color, glyph = "var(--unk)", "○"
    return f'<span class="dot" style="color:{color}">{glyph}</span>'


# Бейдж источника вердикта: `D` — доказано оракулом, `J` — сказал судья.
_SRC_J = '<span class="src-j" title="verdict source: LLM judge, not hard evidence">J</span>'
_SRC_D = '<span class="src-d" title="verdict source: deterministic oracle">D</span>'


def _ladder(stages: list[StageResult]) -> str:
    """Лестница остаётся точечной и бессловесной (дизайн-контракт выше). Бейдж
    источника ставится ТОЛЬКО у стадии, вердикт которой поставил судья: у
    детерминированной стадии он не несёт информации — источник по умолчанию
    именно такой, — а шесть букв «D» в каждой карточке ломают договорённость о
    лестнице без слов. Полный источник каждой стадии (`D`/`J` и природа
    доказательства) виден в таблице «Stages & reasons»."""
    by_stage = {s.stage: s for s in stages}
    parts = []
    for name in _STAGE_ORDER:
        st = by_stage.get(name)
        badge = _SRC_J if st is not None and st.verdict_source == "judge" else ""
        parts.append(
            f'<span class="stage-chip">{_STAGE_LABEL[name]} '
            f'{_stage_dot(st.success if st is not None else None)}{badge}</span>'
        )
    return '<span class="arr"> → </span>'.join(parts)


# ---------------------------------------------------------------- Judge (003)
#
# Всё ниже читает УЖЕ СОХРАНЁННЫЕ вердикты (StageResult.judge / .deterministic и
# aggregate_metrics['judge']) и ничего не пересчитывает: Reporter не оценивает
# успех (принцип I). Пустое поле не заменяется значением по умолчанию —
# «модель не записана» и «модель такая-то» это разные факты.

# Что означает исход судьи. «Судью не звали» и «судья не ответил» — разные
# факты, и ни один из них не читается как «эффекта нет» (FR-020, принцип IV).
_JUDGE_OUTCOME_NOTE = {
    "confirmed": "the judge confirmed this stage",
    "refuted": "the judge stated the effect is absent",
    "unknown": "the judge answered, but the answer did not pass validation",
    "unavailable": "the judge gave no answer (call failed or the budget ran out)",
    "skipped": "the judge was not called — there was nothing to evaluate",
}
# Уверенность осмысленна только там, где судья действительно вынес суждение.
_JUDGE_ANSWERED = ("confirmed", "refuted", "unknown")


def _verdict_word(v: bool | None) -> str:
    return {True: "confirmed", False: "not confirmed"}.get(v, "insufficient data")


def _stage_source_cell(s: StageResult) -> str:
    badge = _SRC_J if s.verdict_source == "judge" else _SRC_D
    return f'{badge} {_esc(s.verdict_source)} · <code>{_esc(s.evidence_kind)}</code>'


def _judge_fields(v) -> str:
    """Строка фактов вердикта: только то, что реально записано."""
    bits = []
    if v.model:
        bits.append(f"model <code>{_esc(v.model)}</code>")
    if v.rubric:
        bits.append(f"rubric <code>{_esc(v.rubric)}</code>")
    if v.outcome in _JUDGE_ANSWERED:
        bits.append(f"confidence <b>{v.confidence:.2f}</b>")
    if v.created_at:
        bits.append(f"at {_esc(v.created_at)}")
    if v.artifact_ref:
        bits.append(f"artifact <code>{_esc(v.artifact_ref)}</code>")
    return " · ".join(bits)


def _judge_stage_html(s: StageResult) -> str:
    v = s.judge
    label = _STAGE_LABEL.get(s.stage, s.stage)
    parts = [
        f'<div class="j-head"><b>{_esc(label)}</b> — judge: '
        f'<span class="j-outcome j-{_esc(v.outcome)}">{_esc(v.outcome)}</span>'
        f'<span class="muted"> · {_esc(_JUDGE_OUTCOME_NOTE.get(v.outcome, ""))}</span></div>'
    ]
    fields = _judge_fields(v)
    if fields:
        parts.append(f'<p class="muted j-fields">{fields}</p>')
    if v.error:
        parts.append(f'<p class="muted">recorded reason: <code>{_esc(v.error)}</code></p>')
    if v.rationale:
        parts.append(f'<p class="j-rationale">{_esc(v.rationale)}</p>')
    if v.quote:
        # цитата приходит из враждебного источника — экранируется как любой
        # текст таргета и никогда не вставляется как разметка
        parts.append(f'<blockquote class="j-quote">{_esc(v.quote)}</blockquote>')
    if s.disagreement and s.deterministic is not None:
        d = s.deterministic
        parts.append(
            '<div class="j-disagree"><b>Verdicts disagree</b> — neither side is dropped silently:'
            f'<ul><li>deterministic (<code>{_esc(d.evidence_kind)}</code>): '
            f'<b>{_verdict_word(d.success)}</b> — {_esc(d.reason)}</li>'
            f'<li>judge: <b>{_esc(v.outcome)}</b> — '
            f'{_esc(v.rationale or "no rationale recorded")}</li></ul>'
            f'the stage verdict was taken from <b>{_esc(s.verdict_source)}</b> '
            f'(<code>{_esc(s.evidence_kind)}</code>)</div>'
        )
    return '<div class="j-stage">' + "\n".join(parts) + "</div>"


def _judge_block(f: Finding, result: AttackResult, judge_meta: dict) -> str:
    """Судейский блок КОНКРЕТНОГО случая. Активность судьи в кампании сама по
    себе ничего не говорит об этом случае: если по нему нет ни одного вердикта,
    так и пишем, а модель кампании ему не приписываем."""
    judged = [s for s in result.stages if s.judge is not None]
    if not judged:
        body = (
            '<p class="muted">Judge active in this run, but this case was '
            "<b>not evaluated by the judge</b> — every verdict here is deterministic. "
            "Run-level judge activity is not evidence about this case.</p>"
            if judge_meta.get("active") else
            '<p class="muted">Judge inactive — verdicts come from deterministic oracles only.</p>'
        )
        return f'<section class="judge-block">{body}</section>'
    head = ('<p class="muted">Judge verdicts recorded for this case: '
            f"{len(judged)} of {len(result.stages)} stages.</p>")
    if f.confidence_tier == "llm_confirmed":
        head += ('<p class="warn">A composite stage of this finding rests on the LLM judge, '
                 "not on a memory snapshot or telemetry — confidence is lower "
                 f'(<code>{_esc(f.confidence_tier)}</code>).</p>')
    return ('<section class="judge-block">' + head
            + "\n".join(_judge_stage_html(s) for s in judged) + "</section>")


def _judge_summary_html(m: dict) -> str:
    """Сводка судьи по прогону: бюджет и доля расхождений (FR-012/FR-019).
    Отсутствие блока читается так же, как `{"active": false}`: судьи не было."""
    j = m.get("judge") or {}
    if not j.get("active"):
        return ('<p class="muted judge-summary">Judge inactive — every verdict in this run '
                "comes from deterministic oracles.</p>")
    bits = []
    if j.get("model"):
        bits.append(f'model <code>{_esc(j["model"])}</code>')
    if j.get("calls_limit") is not None:
        bits.append(f'calls <b>{_esc(j.get("calls_used"))}/{_esc(j["calls_limit"])}</b>')
    counted = [(k, j[k]) for k in ("stages_judged", "confirmed", "refuted", "unknown",
                                   "unavailable", "skipped", "disagreements")
               if j.get(k) is not None]
    if counted:
        bits.append(" / ".join(f"{_esc(k)} {_esc(n)}" for k, n in counted))
    rate = m.get("judge_disagreement_rate")
    # null ≠ 0: ноль означал бы «судья работал и расхождений не нашёл»
    bits.append(f"disagreement rate <b>{rate * 100:.0f}%</b>" if rate is not None
                else "disagreement rate <b>n/a</b>")
    if j.get("budget_exhausted"):
        bits.append('<b class="warn-inline">budget exhausted</b>')
    if j.get("failures"):
        bits.append(f'failed calls <b>{_esc(j["failures"])}</b>')
    return '<p class="muted judge-summary">Judge active · ' + " · ".join(bits) + "</p>"


def _funnel_chips(funnel: dict) -> str:
    chips = []
    for stage in _STAGE_ORDER:
        c = funnel.get(stage, {"pass": 0, "fail": 0, "unknown": 0, "total": 0})
        if c["pass"] > 0:
            cls = "chip-ok"
        elif c["unknown"] > 0:
            cls = "chip-unk"
        else:
            cls = "chip-fail"
        extra = f'<span class="sub">?{c["unknown"]}</span>' if c["unknown"] else ""
        chips.append(
            f'<span class="fchip {cls}" title="{_STAGE_LABEL[stage]}: confirmed {c["pass"]}, '
            f'not confirmed {c["fail"]}, insufficient data {c["unknown"]}">'
            f'{_STAGE_LABEL[stage]} <b>{c["pass"]}/{c["fail"]}</b>{extra}</span>'
        )
    return '<div class="funnel-chips">' + "\n".join(chips) + "</div>"


def _legend_html() -> str:
    """Легенда severity/статусов (раунд №8, решение владельца 2026-09-07):
    аудитору на слайде должно быть читаемо без внешних объяснений, что значит
    CRITICAL/HIGH/MEDIUM, что инструмент называет компромиссом и что означает
    NOT CONFIRMED. Ставится между воронкой и карточками."""
    return """
<div class="legend">
  <div class="lg-item"><b>Compromise (confirmed)</b> — the full evidence chain is proven:
  the poisoned record was written into memory, later retrieved and followed by the agent,
  and changed its behavior (answer or tool call). A memory write alone is not a compromise.</div>
  <div class="lg-item"><span class="badge sev-critical">sev: CRITICAL</span> confirmed compromise with
  <b>cross-user impact</b> — another user's data or money operations are affected.</div>
  <div class="lg-item"><span class="badge sev-high">sev: HIGH</span> confirmed compromise where the attacker
  <b>steers a tool call</b> argument or plants a global rule.</div>
  <div class="lg-item"><span class="badge sev-medium">sev: MEDIUM</span> confirmed compromise that
  <b>distorts answers for the same user</b> (poisoned personal memory).</div>
  <div class="lg-item"><span class="badge sev-info">sev: INFO</span> <span class="badge status-not-exploitable">NOT CONFIRMED</span>
  the attack ran, but the chain did <b>not prove adoption/effect</b> — an honest negative result, not an error.</div>
</div>"""


def _origin_line(f: Finding) -> str:
    """Происхождение атаки и — для онлайновых — число попыток и факт исчерпания
    бюджета (фича 004). Читается из evidence.provenance, который пишет слой
    кампании/эскалации; при его отсутствии строка не показывается."""
    prov = (f.evidence or {}).get("provenance") or {}
    origin = prov.get("origin")
    if not origin:
        return ""
    label = _ORIGIN_LABEL.get(origin, origin)
    parts = [f"Origin: <strong>{_esc(label)}</strong>"]
    if prov.get("attack_class"):
        parts.append(f"class: {_esc(prov['attack_class'])}")
    if origin == "online" or prov.get("attempts") is not None:
        parts.append(f"attempts: {_esc(prov.get('attempts'))}")
    if prov.get("budget_exhausted"):
        parts.append("attacker LLM budget exhausted")
    if prov.get("corpus_id"):
        parts.append(f"corpus: {_esc(prov['corpus_id'])}")
    return f'<p class="muted provenance">{" · ".join(parts)}</p>'


def _causal_trace_html(events: list[dict]) -> str:
    if not events:
        return '<p class="muted">Trace unavailable (target telemetry does not support it).</p>'
    nodes = build_causal_chain(events)
    flat = flatten_linear(nodes)
    items = []
    for e in flat:
        label = e.get("event", "?")
        detail = e.get("tool") or e.get("detail", {}).get("scope") or ""
        args = f" {json.dumps(e.get('arguments'), ensure_ascii=False)}" if e.get("arguments") else ""
        items.append(f"<li><code>{_esc(label)}</code> {_esc(detail)}{_esc(args)}</li>")
    return "<ol class='causal-chain'>" + "\n".join(items) + "</ol>"


def _phase_counts(messages: list[dict]) -> dict[str, int]:
    counts = {"baseline": 0, "delivery": 0, "trigger": 0}
    for m in messages:
        ph = m.get("phase", "")
        if ph in counts:
            counts[ph] += 1
    return counts


def _transcript_html(result: AttackResult) -> str:
    """Чат кейса. Новый формат (transcript v1) — полная лента фаз и реплик;
    старый формат — сохранившиеся фрагменты с честной пометкой. Все реплики —
    РЕАЛЬНЫЕ записи прогона (send-then-record): недоставленное не наблюдено и
    не рисуется. identity модели-таргета в артефактах прогона не хранится —
    сообщаем это честно, не выдумываем имя."""
    wire = result.evidence.get("transcript")
    if isinstance(wire, dict) and wire.get("messages"):
        complete = bool(wire.get("complete"))
        note = "" if complete else (
            f'<p class="warn">⚠ Incomplete dialogue: {_esc(wire.get("incomplete_reason", "interrupted"))} — '
            "observed part is shown.</p>"
        )
        legend = ('<p class="muted chat-legend">Every message below is a REAL record of this run '
                  "(what was sent / what the agent actually answered). &ldquo;Agent&rdquo; = the target "
                  "model under test; model identity is not recorded in run artifacts.</p>")
        bubbles = []
        last_phase = None
        for m in wire["messages"]:
            phase = m.get("phase", "")
            if phase != last_phase:
                c = _phase_counts(wire["messages"]).get(phase, 0)
                bubbles.append(f'<div class="phase-sep">{_esc(_PHASE_LABEL.get(phase, phase))}'
                               f'<span class="phase-count"> · {c} messages</span></div>')
                last_phase = phase
            role = m.get("role", "")
            cls = "msg-user" if role == "user" else "msg-agent"
            who = f"User {m.get('actor_user_id', '')}" if role == "user" else "Agent"
            bubbles.append(
                f'<div class="msg {cls}"><div class="msg-head">{_esc(who)} · '
                f'{_esc(m.get("step_label", ""))}</div>'
                f'<div class="msg-body">{_esc(m.get("content", ""))}</div></div>'
            )
        return note + legend + '<div class="chat">' + "\n".join(bubbles) + "</div>"
    # старый формат: только фрагменты
    base = result.evidence.get("baseline_response", "")
    victim = result.evidence.get("victim_response", "")
    cand = (result.evidence.get("candidate") or {})
    frags = ['<p class="warn">⚠ The full dialogue was not recorded (legacy artifact format) — '
             "only saved fragments are shown below; the payload comes from the candidate record, "
             "it is NOT a proven transcript of sent turns.</p>"]
    if cand.get("payload"):
        frags.append('<div class="msg msg-user"><div class="msg-head">Candidate payload '
                     '(declared, not an observed transcript)</div>'
                     f'<div class="msg-body">{_esc(cand.get("payload"))}</div></div>')
    if base:
        frags.append('<div class="msg msg-agent"><div class="msg-head">Agent baseline answer</div>'
                     f'<div class="msg-body">{_esc(base)}</div></div>')
    if victim:
        frags.append('<div class="msg msg-agent"><div class="msg-head">Agent trigger answer (last)</div>'
                     f'<div class="msg-body">{_esc(victim)}</div></div>')
    return '<div class="chat">' + "\n".join(frags) + "</div>"


def _chat_summary_line(result: AttackResult) -> str:
    """Строка-превью на toggle'е диалога: сколько реплик и в каких фазах."""
    wire = result.evidence.get("transcript")
    if isinstance(wire, dict) and wire.get("messages"):
        msgs = wire["messages"]
        c = _phase_counts(msgs)
        bits = [f"{len(msgs)} messages", f"baseline {c['baseline']}", f"delivery {c['delivery']}",
                f"trigger {c['trigger']}"]
        if not wire.get("complete"):
            bits.append("INCOMPLETE")
        return " · ".join(bits)
    return "legacy fragments (full dialogue was not recorded)"


def _case_article(f: Finding, result: AttackResult, events: list[dict], run_dir_rel: str,
                  judge_meta: dict | None = None) -> str:
    status_class = "success" if f.status == "SUCCESS" else "not-exploitable"
    status_text = _STATUS_TEXT.get(f.status, f.status)
    stage_rows = "\n".join(
        f"<tr><td>{_STAGE_LABEL[s.stage]}</td><td>{_stage_dot(s.success)}</td>"
        f"<td>{_esc(s.reason)}</td><td>{_stage_source_cell(s)}</td></tr>"
        for s in result.stages
    )
    # Плашка ставится по тиру достоверности находки (FR-015): она про то, на чём
    # держится ПОДТВЕРЖДЁННАЯ находка, а не про наличие судейских стадий вообще.
    llm_title = ("A composite stage of this finding is confirmed by the LLM judge, not by a "
                 "memory snapshot or telemetry — treat it as weaker evidence")
    llm_badge = (f'<span class="badge llm-conf" title="{_esc(llm_title)}">LLM-CONFIRMED</span>'
                 if f.confidence_tier == "llm_confirmed" else "")
    effect = (result.evidence.get("candidate") or {}).get("expected_effect") or {}
    effect_txt = json.dumps(effect, ensure_ascii=False) if effect else "not recorded"
    sev_title = ("Severity of a CONFIRMED compromise (by attack family); "
                 "INFO = compromise not confirmed")
    status_title = ("Red = memory compromise confirmed by the composite; "
                    "green = effect not confirmed (an honest negative result, not an error)")
    return f"""
<article class="finding {status_class}" id="{_esc(f.case_id)}" data-status="{_esc(f.status)}">
  <header>
    <h3>{_esc(f.title)}
      <span class="badge sev-{f.severity.lower()}" title="{_esc(sev_title)}">sev: {_esc(f.severity)}</span>
      <span class="badge status-{f.status.lower().replace('_','-')}" title="{_esc(status_title)}">{_esc(status_text)}</span>{llm_badge}</h3>
    <div class="meta">
      <p class="muted">family <code>{_esc(f.family)}</code> · attack_id <code>{_esc(f.attack_id)}</code> ·
         case <code>{_esc(f.case_id)}</code> · requests from user <code>{_esc(f.attacker)}</code> →
         victim memory of user <code>{_esc(f.victim)}</code></p>
      <p class="muted">What this attack does: {_esc(f.description or "description not recorded for this family")}</p>
      <p class="muted">Expected effect: <code>{_esc(effect_txt)}</code></p>
      <p class="muted">Threat mapping: ATLAS {_esc(f.atlas_technique)} ({_esc(f.atlas_tactic)}) ·
         OWASP {_esc(f.owasp_asi)} · stable ID for threat-model mapping = family, not case.</p>
      {_origin_line(f)}
    </div>
  </header>
  <div class="ladder">{_ladder(result.stages)}</div>
  <details>
    <summary>Dialogue &amp; phases · {_esc(_chat_summary_line(result))}</summary>
    {_transcript_html(result)}
  </details>
  <details>
    <summary>Stages &amp; reasons</summary>
    <table><tr><th>Stage</th><th>Verdict</th><th>Reason</th><th>Source</th></tr>{stage_rows}</table>
    {_judge_block(f, result, judge_meta or {})}
  </details>
  <details>
    <summary>Causal trace</summary>
    {_causal_trace_html(events)}
  </details>
  <p class="artifacts">Full data (not inlined in this report):
     <a href="{run_dir_rel}/evidence/{_esc(f.case_id)}-before.json">memory before</a> ·
     <a href="{run_dir_rel}/evidence/{_esc(f.case_id)}-after.json">memory after</a> ·
     <a href="{run_dir_rel}/evidence/{_esc(f.case_id)}-diff.json">diff</a> ·
     <a href="{run_dir_rel}/evidence/{_esc(f.case_id)}-transcript.json">transcript</a> ·
     <a href="{run_dir_rel}/traces/{_esc(f.case_id)}.json">trace</a></p>
</article>"""


def _case_for(campaign: CampaignResult) -> dict[str, AttackResult]:
    return {r.case_id: r for r in campaign.results}


_CSS = """
:root{--bg:#0b0d12;--panel:#141821;--text:#e8ecf3;--muted:#8b93a7;--ok:#3ddc84;--fail:#ff5d6c;--unk:#f5c344;
      --crit:#ff3b5c;--high:#ff8a3d;--med:#f5c344;--info:#5b9dff;--border:#232838;--accent:#5b9dff;}
@media (prefers-color-scheme: light){
  :root{--bg:#f7f8fb;--panel:#ffffff;--text:#161a22;--muted:#5b6472;--border:#e3e6ee;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;}
.wrap{max-width:1080px;margin:0 auto;padding:28px 20px 24px}
h1{font-size:36px;margin:0 0 10px;text-align:center;letter-spacing:.01em}
h2{font-size:17px;margin:32px 0 12px;text-align:center;border-bottom:1px solid var(--border);padding-bottom:6px}
.muted{color:var(--muted);font-size:13px}
.warn{color:var(--unk);font-size:13px;background:rgba(245,195,68,.08);padding:6px 10px;border-radius:6px}
.summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:16px 0}
@media (max-width:640px){.summary-grid{grid-template-columns:1fr}}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px;text-align:center}
.stat .n{font-size:26px;font-weight:700}
.stat .d{font-size:13px;color:var(--muted);font-weight:400}
.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
/* ASR — основная метрика: крупнее именно БУКВЫ подписи; цифры у всех плиток
   одинаковые, в числе — только процент (ревью владельца 2026-09-07) */
.stat.asr .l{font-size:22px;font-weight:700;color:var(--text);letter-spacing:.06em}
.funnel-chips{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0;justify-content:center}
.fchip{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px}
.fchip b{font-size:15px;margin:0 4px}
.fchip .sub{color:var(--unk);font-size:15px;margin-left:4px;font-weight:400}
.legend{border:1px solid var(--border);border-radius:10px;padding:10px 14px;margin:12px 0 4px;font-size:15.5px;color:var(--muted)}
.legend .lg-item{margin:5px 0;line-height:1.5}
.legend b{color:var(--text)}
.legend .badge{margin-left:0;margin-right:6px;font-size:13px;padding:2px 9px}
.chip-ok{border-left:3px solid var(--ok)} .chip-fail{border-left:3px solid var(--fail)} .chip-unk{border-left:3px solid var(--unk)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 14px;justify-content:center}
.fbtn{background:var(--panel);border:1px solid var(--border);color:var(--muted);border-radius:999px;
      padding:4px 14px;font-size:13px;cursor:pointer;font-family:inherit}
.fbtn.active{border-color:var(--accent);color:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top}
th{color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:none}
.finding{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:8px 11px;margin-bottom:0;color:var(--text)}
.findings-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;align-items:start}
.fcol{display:grid;gap:8px;align-content:start}
@media (max-width:900px){.findings-grid{grid-template-columns:1fr}}
.findings-grid .finding h3{font-size:13px;line-height:1.3}
.finding.success{border-left:4px solid var(--fail)}
.finding.not-exploitable{border-left:4px solid var(--ok)}
article h3,article .ladder,article .stage-chip,article .msg,article .msg-body,article .msg-head{color:var(--text)}
article h3{font-size:15px;margin:0 0 4px}
.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:999px;margin-left:4px;vertical-align:middle}
.sev-critical{background:var(--crit);color:#fff}
.sev-high{background:var(--high);color:#1a1200}
.sev-medium{background:var(--med);color:#1a1200}
.sev-info{background:var(--info);color:#fff}
.status-success{background:var(--fail);color:#fff}
.status-not-exploitable{background:var(--ok);color:#04210f}
.status-inconclusive{background:var(--unk);color:#1a1200}
.ladder{margin:6px 0;font-size:12px;letter-spacing:.5px}
.stage-chip{display:inline-block}
.arr{color:var(--muted)}
.dot{font-size:13px}
.chat{display:flex;flex-direction:column;gap:10px;margin-top:10px}
.chat-legend{margin:6px 0 0}
.phase-sep{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--text);
           border-top:1px dashed var(--border);padding-top:10px;margin-top:8px;font-weight:600}
.phase-count{color:var(--muted);font-weight:400;text-transform:none;letter-spacing:0}
.msg{border:1px solid var(--border);border-radius:10px;padding:12px 14px;max-width:100%;overflow-wrap:anywhere}
.msg-user{background:rgba(91,157,255,.08);border-left:3px solid var(--accent)}
.msg-agent{background:rgba(127,127,127,.06);border-left:3px solid var(--border)}
.msg-head{font-size:12px;color:var(--muted);margin-bottom:6px;overflow-wrap:anywhere}
.msg-body{white-space:pre-wrap;font-size:16px;line-height:1.55}
.judge-block{font-size:13px;color:var(--muted);margin-top:8px;display:block}
.judge-summary{text-align:center;margin:10px 0 0}
.warn-inline{color:var(--unk)}
.src-j{display:inline-block;font-size:10px;font-weight:700;color:#1a1200;background:var(--med);
       border-radius:3px;padding:0 3px;margin-left:3px;vertical-align:top}
.src-d{display:inline-block;font-size:10px;font-weight:700;color:var(--muted);
       border:1px solid var(--border);border-radius:3px;padding:0 3px}
.badge.llm-conf{background:var(--med);color:#1a1200}
.j-stage{border-top:1px dashed var(--border);padding-top:8px;margin-top:8px}
.j-head{color:var(--text);font-size:13px}
.j-outcome{font-weight:700}
.j-confirmed{color:var(--fail)}
.j-refuted{color:var(--ok)}
.j-unknown,.j-unavailable,.j-skipped{color:var(--unk)}
.j-fields{margin:4px 0 0;overflow-wrap:anywhere}
.j-rationale{color:var(--text);font-size:13px;margin:6px 0 0}
.j-quote{margin:6px 0 0;padding:6px 10px;border-left:3px solid var(--accent);
         background:rgba(127,127,127,.06);color:var(--text);font-size:13px;
         white-space:pre-wrap;overflow-wrap:anywhere}
.j-disagree{margin-top:8px;border:1px solid var(--unk);border-radius:8px;padding:6px 10px;
            color:var(--text);font-size:13px}
.j-disagree ul{margin:4px 0 0 16px;padding:0}
.causal-chain{font-size:13px;margin:8px 0 0 18px}
.causal-chain code{background:rgba(127,127,127,.15);padding:1px 5px;border-radius:4px}
.artifacts{font-size:13px;margin:10px 0 0}
.artifacts a{color:var(--accent);word-break:break-all}
article:not(:has(details[open])) .artifacts{display:none}
article:not(:has(details[open])) .meta{display:none}
details summary{cursor:pointer;font-size:12px;color:var(--muted);margin-top:5px}
details summary:focus-visible{outline:2px solid var(--accent);border-radius:4px}
@media print{body{background:#fff;color:#000}.finding{break-inside:avoid;border-color:#ccc}details{display:block}details:not([open])>.chat,details:not([open])>table{display:none}}
"""

_FILTER_JS = """
(function(){
  var btns=document.querySelectorAll('.fbtn');
  btns.forEach(function(b){b.addEventListener('click',function(){
    btns.forEach(function(x){x.classList.remove('active')});
    b.classList.add('active');
    var f=b.getAttribute('data-f');
    document.querySelectorAll('article.finding').forEach(function(a){
      var s=a.getAttribute('data-status');
      a.style.display=(f==='all'||s===f)?'':'none';
    });
  });});
})();
"""


def render_html(campaign: CampaignResult, run_events_by_case: dict[str, list[dict]] | None = None,
                run_dir_rel: str = "..") -> str:
    run_events_by_case = run_events_by_case or {}
    findings = build_findings(campaign.results)
    m = campaign.aggregate_metrics
    by_case = _case_for(campaign)

    completed = m.get("attempts", 0)
    confirmed = m.get("successful", 0)
    asr = m.get("end_to_end_asr")
    # В плитке — только процент (ревью владельца: «40 of 48» убрать);
    # знаменатель читается с соседних плиток attempts/confirmed.
    asr_txt = "n/a" if asr is None else f"{asr * 100:.0f}%"

    def _counts(f: str) -> int:
        return sum(1 for x in findings if x.status == f)

    n_success, n_neg = _counts("SUCCESS"), _counts("NOT_EXPLOITABLE")
    n_unk = len(findings) - n_success - n_neg

    # Фильтр INCONCLUSIVE рисуется ТОЛЬКО когда такие карточки есть: пустая
    # кнопка несуществующей метрики — шум (ревью владельца по live10).
    inconclusive_btn = (
        f'<button class="fbtn" data-f="INCONCLUSIVE">Inconclusive {n_unk}</button>'
        if n_unk else ""
    )
    filter_bar = (
        '<div class="filters">'
        f'<button class="fbtn active" data-f="all">All {len(findings)}</button>'
        f'<button class="fbtn" data-f="SUCCESS">Confirmed {n_success}</button>'
        f'<button class="fbtn" data-f="NOT_EXPLOITABLE">Not confirmed {n_neg}</button>'
        f'{inconclusive_btn}'
        "</div>"
    )

    # Колоночная раскладка слайда (решение владельца 2026-09-07): три настоящие
    # колонки-столбца — 1-я CRITICAL, 2-я HIGH/MEDIUM, 3-я NOT CONFIRMED (INFO);
    # внутри колонки подтверждённые раньше остальных, затем по severity и case_id.
    _SEV_COL = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1}
    buckets: dict[int, list] = {0: [], 1: [], 2: []}
    for f in sorted(
        findings,
        key=lambda x: (0 if x.status == "SUCCESS" else 1, x.severity, x.case_id),
    ):
        buckets[_SEV_COL.get(f.severity, 2)].append(f)
    columns_html = "\n".join(
        '<div class="fcol">\n'
        + "\n".join(
            _case_article(f, by_case[f.case_id], run_events_by_case.get(f.case_id, []),
                          run_dir_rel, m.get("judge") or {})
            for f in buckets[i]
        )
        + "\n</div>"
        for i in (0, 1, 2)
        if buckets[i]  # пустой бакет не рисуем: колонка-дыра выглядит как поломка
    )
    cards_block = f'<div class="findings-grid">\n{columns_html}\n</div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>memnotsafe report</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
  <h1>memnotsafe report</h1>

  <h2>Series summary</h2>
  <div class="summary-grid">
    <div class="stat"><div class="n">{completed}</div><div class="l">Completed attempts</div></div>
    <div class="stat"><div class="n">{confirmed}</div><div class="l">Confirmed compromises</div></div>
    <div class="stat asr"><div class="n">{asr_txt}</div><div class="l">ASR</div></div>
  </div>
  <h2>Stage funnel</h2>
  {_funnel_chips(m['funnel'])}
  {_judge_summary_html(m)}
  {_legend_html()}

  <h2>Attacks ({len(findings)})</h2>
  {filter_bar}
  {cards_block}
</div>
<script>{_FILTER_JS}</script>
</body></html>"""


def write_html_report(campaign: CampaignResult, output_path: Path,
                      run_events_by_case: dict[str, list[dict]] | None = None,
                      run_dir_rel: str = "..") -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(campaign, run_events_by_case, run_dir_rel), encoding="utf-8")
    return output_path
