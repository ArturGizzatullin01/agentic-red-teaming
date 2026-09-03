"""Матрица покрытия: все атаки/цепочки из runs/ одним взглядом.

Сканирует runs/*/report.json, берёт ПОСЛЕДНИЙ прогон каждого id и строит
docs/coverage-matrix.md — таблицу «атака × вердикт × куда лег яд».
Запуск: python tools/coverage_report.py
"""

import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
OUT = ROOT / "docs" / "coverage-matrix.md"


def latest_reports():
    by_id = {}
    for p in glob.glob(str(RUNS / "*" / "report.json")):
        try:
            r = json.loads(Path(p).read_text(encoding="utf-8"))
        except Exception:
            continue
        aid = r.get("attack_id")
        if not aid:
            continue
        prev = by_id.get(aid)
        if prev is None or str(r.get("run_dir", "")) > str(prev.get("run_dir", "")):
            by_id[aid] = r
    return by_id


def main():
    reps = latest_reports()
    if not reps:
        print("в runs/ нет отчётов")
        return 1

    rows = []
    for aid in sorted(reps):
        r = reps[aid]
        v = r["verdict"]
        chunk_sources = {c.get("source", "?") for c in v.get("matched_chunks", [])}
        for st in r.get("stages", []):  # у цепочек маркеры по стадиям
            chunk_sources |= {c.get("source", "?") for c in st.get("matched", [])}
        sources = sorted(chunk_sources)
        rows.append({
            "id": aid,
            "kind": r.get("kind", "attack"),
            "cls": r.get("class", ""),
            "signal": r.get("signal", ""),
            "implanted": v.get("implanted", v.get("stages_implanted", 0)),
            "impl_max": v.get("stages_total", 1),
            "act": v.get("activated_triggers", 0),
            "trig": v.get("triggers_total", 0),
            "adopt": v.get("adopted_triggers", 0),
            "sources": sources,
        })

    attacks = [r for r in rows if r["kind"] == "attack"]
    chains = [r for r in rows if r["kind"] == "chain"]
    classes = {r["cls"] for r in rows if r["cls"]}
    n_impl = sum(1 for r in rows if r["implanted"])
    t_act = sum(r["act"] for r in rows)
    t_trig = sum(r["trig"] for r in rows)

    lines = [
        "# Матрица покрытия атак (авто-отчёт по runs/)",
        "",
        f"Сгенерирован: {__import__('time').strftime('%Y-%m-%d %H:%M')} · "
        f"прогонов-артефактов: {len(rows)} "
        f"(атак: {len(attacks)}, цепочек: {len(chains)}) · классов: {len(classes)}",
        "",
        f"**Внедрение: {n_impl}/{len(rows)} · активация {t_act}/{t_trig} триггеров** "
        "(последний прогон каждого id; активация вероятностна — см. findings, раздел 6)",
        "",
        "| Атака | Класс | Сигнал | Внедрение | Активация | Куда лег яд |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        impl = "да" if r["implanted"] else "нет"
        if r["kind"] == "chain":
            impl = f"{r['implanted']}/{r['impl_max']} стадий"
        src = ", ".join(s.replace("_memories", "").replace("dialog_sessions", "dialog")
                        for s in r["sources"]) or "—"
        lines.append(f"| {r['id']} | {r['cls']} | {r['signal']} | {impl} "
                     f"| {r['act']}/{r['trig']} ({r['adopt']} принято) | {src} |")
    lines += [
        "",
        "Коллекции: dialog — сырой диалог, episodic — саммари-эпизоды, "
        "semantic — факты о клиенте, agent_policy — **глобальная политика "
        "всех клиентов**.",
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"готово: {OUT} ({len(rows)} атак/цепочек, {len(classes)} классов)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
