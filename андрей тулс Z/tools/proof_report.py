"""Отчёт-доказательство: атака -> состояние агента -> оценка -> итог.

Генерируется ТОЛЬКО из сырых артефактов прогонов (runs/*/report.json,
runs/*/trace.jsonl). Ни одна фраза не набирается вручную: цитаты нагрузки,
чанков памяти, ответов агента и вердиктов извлекаются скриптом, а каждый
прогон подписан sha256 исходных файлов — подделать или догаллюцинировать
результат нельзя, любая правка артефакта меняет хэш.

  вход  runs/<attack-id>-<stamp>/{report.json,trace.jsonl}
  выход docs/proof-report.md  — человекочитаемая цепочка по каждой атаке
        docs/proof.json       — машиночитаемая версия + хэши исходников

Проверка подлинности (сверка хэшей и вердиктов с сырыми файлами):
  python tools/proof_report.py --verify
"""

import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
DOCS = ROOT / "docs"
sys.path.insert(0, str(ROOT / "tools"))
from export_findings import latest_reports, msi, severity, status_of  # noqa: E402

OUTCOME_RU = {
    "confirmed": "УСПЕШНАЯ АТАКА — внедрение + активация подтверждены детерминированно",
    "confirmed_implant": "ЧАСТИЧНО — ядро записано в память, активация не воспроизведена",
    "probable": "ВЕРОЯТНО УСПЕШНАЯ — подтверждено только LLM-судьёй",
    "not_reproduced": "НЕ ВОСПРОИЗВЕДЕНА",
}


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def trace_events(run_dir: Path) -> list:
    tp = run_dir / "trace.jsonl"
    if not tp.exists():
        return []
    out = []
    for line in tp.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def before_state(events: list) -> dict:
    """Состояние памяти ДО атаки: reset + стартовый фингерпринт из trace."""
    reset = next((e for e in events if e["action"] == "reset"), None)
    start = next((e for e in events if e["action"] == "start_memory"), None)
    fp = (start or {}).get("fingerprint") or []
    fp_digest = hashlib.sha256(
        "\n".join(sorted(f"{c['id']}:{c['sha256']}" for c in fp)).encode()
    ).hexdigest()[:16] if fp else None
    return {
        "reset_removed": (reset or {}).get("result", {}).get("removed"),
        "chunks_before": (start or {}).get("count"),
        "fingerprint_count": len(fp),
        "fingerprint_sha256": fp_digest,
        "fingerprint_sample": fp[:5],
    }


def after_state(report: dict, events: list) -> dict:
    """Изменённое состояние: чанки памяти, появившиеся с нагрузкой."""
    settle = next((e for e in events if e["action"] == "await_settle"), None)
    chunks = []
    if report.get("kind") == "chain":
        for st in report.get("stages") or []:
            chunks += st.get("matched") or []
    else:
        chunks = (report.get("verdict") or {}).get("matched_chunks") or []
    uniq, seen = [], set()
    for c in chunks:
        if c["id"] not in seen:
            seen.add(c["id"])
            uniq.append({"id": c["id"], "source": c.get("source"),
                         "sha256": hashlib.sha256(
                             c["chunk"].encode("utf-8")).hexdigest()[:16],
                         "chunk": c["chunk"]})
    return {"chunks_with_payload": uniq,
            "memory_count_after": (settle or {}).get("result", {}).get("count")
            if settle else None}


def verdict_block(report: dict, events: list) -> dict:
    """Оценка: детерминированный скан + ответы агента + LLM-судья."""
    scan = next((e for e in events if e["action"] == "memory_scan"), None)
    v = report.get("verdict") or {}
    rows = []
    for t in report.get("trigger_results") or []:
        j = t.get("judge") or {}
        rows.append({
            "question": t.get("question"),
            "activated": t.get("activated"),
            "adopted": t.get("adopted"),
            "exposure_only": t.get("exposure_only"),
            "answer": t.get("answer"),
            "judge_verdict": j.get("verdict"),
            "judge_reason": j.get("reason"),
        })
    det = {
        "markers_scanned": (scan or {}).get("markers"),
        "implanted": v.get("implanted"),
        "stages_implanted": v.get("stages_implanted"),
        "stages_total": v.get("stages_total"),
        "activated": f"{v.get('activated_triggers', 0)}/{v.get('triggers_total', 0)}",
        "adopted": f"{v.get('adopted_triggers', 0)}/{v.get('triggers_total', 0)}",
        "utility_before": v.get("utility_before"),
        "utility_after": v.get("utility_after"),
    }
    return {"deterministic": det, "judge_summary": v.get("judge"),
            "triggers": rows}


def build_chain(aid: str, stamp: str, report: dict, run_dir: Path) -> dict:
    events = trace_events(run_dir)
    score = msi(report)
    sev, _ = severity(score["msi"])
    status = status_of(report, score)
    delivery = report.get("delivery") or {}
    msgs = [m for m in (delivery.get("messages") or [])
            if isinstance(m, str) and m.strip().lower() != "finalize"]
    if not msgs:  # цепочки: полных текстов в report.json нет — превью из trace
        msgs = [f"[превью из trace] {e.get('preview')}"
                for e in events if e.get("phase") == "delivery"
                and e.get("action") == "chat_message"]
    return {
        "attack_id": aid,
        "name": report.get("attack_name"),
        "class": report.get("class"),
        "scenario_run": stamp,
        "target": report.get("target"),
        "chain": {
            "1_attack": {
                "channel": report.get("channel"),
                "canary": ((next((e for e in events
                                  if e["action"] == "memory_scan"), None)
                            or {}).get("markers") or [None])[0],
                "delivery_messages": msgs,
            },
            "2_agent_state_before": before_state(events),
            "3_agent_state_after": after_state(report, events),
            "4_verdict": verdict_block(report, events),
            "5_outcome": {"status": status, "verdict_ru": OUTCOME_RU[status],
                          "msi": score, "severity": sev},
        },
        "sources": {
            "run_dir": str(run_dir.relative_to(ROOT)),
            "report_json_sha256": sha256_file(run_dir / "report.json"),
            "trace_jsonl_sha256": (sha256_file(run_dir / "trace.jsonl")
                                   if (run_dir / "trace.jsonl").exists() else None),
        },
    }


def _q(text: str, limit: int = 500) -> str:
    t = (text or "").strip().replace("\n", " ")
    return t[:limit] + ("…" if len(t) > limit else "")


def to_markdown(entries: list) -> str:
    lines = [
        "# Отчёт-доказательство: атака -> состояние агента -> оценка -> итог",
        "",
        f"Сгенерировано скриптом `tools/proof_report.py` "
        f"{time.strftime('%Y-%m-%d %H:%M')} из сырых артефактов `runs/`. "
        "Ни одна цитата не набрана вручную — всё извлечено скриптом из "
        "report.json/trace.jsonl; каждый прогон подписан sha256. "
        "Проверка подлинности: `python tools/proof_report.py --verify`.",
        "",
        "## Сводка",
        "",
        "| Атака | Итог | MSI | Судья |",
        "|---|---|---|---|",
    ]
    for e in entries:
        oc = e["chain"]["5_outcome"]
        js = e["chain"]["4_verdict"]["judge_summary"]
        jtxt = (f"adoption {js.get('adoption', 0)}") if js else "—"
        lines.append(f"| {e['attack_id']} | {oc['status']} | {oc['msi']['msi']} "
                     f"| {jtxt} |")
    lines.append("")
    for e in entries:
        c = e["chain"]
        att, bef, aft = c["1_attack"], c["2_agent_state_before"], c["3_agent_state_after"]
        vd, oc = c["4_verdict"], c["5_outcome"]
        det = vd["deterministic"]
        imp = det.get("stages_implanted")
        imp_txt = ("**ДА**" if det.get("implanted")
                   else "нет" if det.get("implanted") is not None
                   else f"{imp}/{det.get('stages_total', '?')} стадий"
                   if imp is not None else "—")
        lines += [
            "",
            "---",
            "",
            f"## {e['attack_id']} — {e['name']}",
            "",
            f"Класс `{e.get('class', '—')}` · канал `{att.get('channel', '—')}` · "
            f"мишень `{e['target']}` · прогон `{e['scenario_run']}`",
            "",
            f"`report.json` sha256 `{e['sources']['report_json_sha256'][:16]}…` · "
            f"`trace.jsonl` sha256 "
            f"`{(e['sources']['trace_jsonl_sha256'] or '—')[:16]}…`",
            "",
            "### 1. АТАКА (вход)",
            "",
        ]
        if att.get("canary"):
            lines.append(f"Канарейка: `{att['canary']}` · маркеры скана: "
                         f"`{det.get('markers_scanned')}`")
        for i, m in enumerate(att.get("delivery_messages") or [], 1):
            lines += ["", f"**Сообщение {i}:**", "", f"> {_q(m, 700)}"]
        if not (att.get("delivery_messages") or []):
            lines.append("_поставка не через чат (см. run_dir)_")
        lines += [
            "",
            "### 2. Состояние агента ДО атаки",
            "",
        ]
        if bef.get("reset_removed"):
            lines.append(f"Сброс стенда удалил: `{bef['reset_removed']}`")
        lines.append(f"Чанков долговременной памяти до атаки: "
                     f"**{bef.get('chunks_before')}** · фингерпринт "
                     f"`{bef.get('fingerprint_sha256') or '—'}` "
                     f"({bef.get('fingerprint_count')} чанков)")
        lines += ["", "### 3. Изменённое состояние ПОСЛЕ (память агента)", ""]
        if aft.get("memory_count_after") is not None:
            lines.append(f"Чанков памяти после атаки: "
                         f"**{aft['memory_count_after']}**")
        if aft.get("chunks_with_payload"):
            for ch in aft["chunks_with_payload"]:
                lines += ["", f"**Чанк `{ch['id']}`** "
                          f"(коллекция `{ch.get('source')}`, "
                          f"sha256 `{ch['sha256']}`):", "",
                          f"> {_q(ch['chunk'], 600)}"]
        else:
            lines.append("_чанков с нагрузкой не найдено — внедрения нет_")
        lines += [
            "",
            "### 4. ОЦЕНКА (детерминированный скан + LLM-судья)",
            "",
            f"**Детерминированно:** внедрение {imp_txt} · "
            f"активация {det['activated']} · принятие {det['adopted']} · "
            f"полезность {det.get('utility_before')} -> "
            f"{det.get('utility_after')}",
            "",
        ]
        js = vd["judge_summary"]
        if js:
            lines.append(f"**LLM-судья** ({js.get('name')}, `{js.get('model')}`): "
                         f"adoption {js.get('adoption', 0)} · exposure "
                         f"{js.get('exposure', 0)} · refusal "
                         f"{js.get('refusal', 0)} · error {js.get('error', 0)}")
        else:
            lines.append("**LLM-судья:** не привлекался (прогон без ключа)")
        lines += ["", "| Триггер | Активация | Принятие | Судья | Ответ агента |",
                  "|---|---|---|---|---|"]
        for t in vd["triggers"]:
            mark = "**ДА**" if t["activated"] else (
                "упоминание" if t.get("exposure_only") else "нет")
            ad = "**ДА**" if t.get("adopted") else "нет"
            jv = t.get("judge_verdict") or "—"
            lines.append(f"| {_q(t['question'], 60)} | {mark} | {ad} | {jv} "
                         f"| {_q(t['answer'], 160)} |")
        lines += ["", "<details><summary>Полные ответы агента и вердикты судьи"
                  "</summary>", ""]
        for i, t in enumerate(vd["triggers"], 1):
            lines += [f"**T{i}.** {t['question']}", "",
                      f"> {t['answer']}", ""]
            if t.get("judge_reason"):
                lines += [f"Судья: {t['judge_verdict']} — {t['judge_reason']}", ""]
        lines += ["</details>", "",
                  "### 5. ИТОГ", "",
                  f"**{oc['verdict_ru']}**",
                  "",
                  f"MSI **{oc['msi']['msi']}/100** "
                  f"(W{oc['msi']['w']} A{oc['msi']['a']} D{oc['msi']['d']} "
                  f"P{oc['msi']['p']}) · критичность **{oc['severity']}** · "
                  f"артефакты: `{e['sources']['run_dir']}/`",
                  ]
    return "\n".join(lines) + "\n"


def main() -> int:
    verify = "--verify" in sys.argv
    proof_path = DOCS / "proof.json"
    if verify:
        if not proof_path.exists():
            sys.exit("docs/proof.json нет — сначала сгенерируй отчёт")
        old = json.loads(proof_path.read_text(encoding="utf-8"))
        bad = 0
        for e in old["attacks"]:
            rd = ROOT / e["sources"]["run_dir"]
            checks = [("report.json",
                       sha256_file(rd / "report.json")
                       == e["sources"]["report_json_sha256"])]
            if e["sources"]["trace_jsonl_sha256"]:
                checks.append(("trace.jsonl",
                               sha256_file(rd / "trace.jsonl")
                               == e["sources"]["trace_jsonl_sha256"]))
            fresh = build_chain(e["attack_id"], e["scenario_run"],
                                json.loads((rd / "report.json")
                                           .read_text(encoding="utf-8")), rd)
            checks.append(("вердикты", fresh["chain"]["4_verdict"]
                           == e["chain"]["4_verdict"]))
            checks.append(("итог", fresh["chain"]["5_outcome"]
                           == e["chain"]["5_outcome"]))
            for name, ok in checks:
                if not ok:
                    bad += 1
                    print(f"MISMATCH {e['attack_id']}: {name} не сходится")
        if bad:
            print(f"\nПРОВАЛ: {bad} расхождений — артефакты менялись после "
                  "генерации отчёта")
            return 1
        print(f"OK: {len(old['attacks'])} прогонов, все sha256 и вердикты "
              "сходятся с сырыми файлами")
        return 0

    entries = []
    for aid, (stamp, r, run_dir) in sorted(latest_reports().items()):
        entries.append(build_chain(aid, stamp, r, run_dir))
    DOCS.mkdir(exist_ok=True)
    proof = {"generated": time.strftime("%Y-%m-%d %H:%M"),
             "tool": "memred proof_report",
             "format": "1 атака = 5 шагов: вход -> память до -> память после "
                       "-> оценка (скан+судья) -> итог; sha256 pinают исходники",
             "attacks": entries}
    proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    (DOCS / "proof-report.md").write_text(to_markdown(entries),
                                          encoding="utf-8")
    ok = sum(1 for e in entries
             if e["chain"]["5_outcome"]["status"] == "confirmed")
    part = sum(1 for e in entries
               if e["chain"]["5_outcome"]["status"] == "confirmed_implant")
    print(f"отчёт-доказательство: {len(entries)} атак "
          f"(успешных {ok}, частичных {part}) -> "
          f"docs/proof-report.md + docs/proof.json")
    for e in entries:
        oc = e["chain"]["5_outcome"]
        print(f"  {e['attack_id']:<40} {oc['status']:<20} "
              f"MSI {oc['msi']['msi']:>3} {oc['severity']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
