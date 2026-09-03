"""Трассировка (JSONL) и отчёты прогона (JSON + Markdown)."""

import json
import time
from pathlib import Path


class Trace:
    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.path = run_dir / "trace.jsonl"

    def step(self, phase: str, action: str, **data):
        rec = {"ts": time.strftime("%H:%M:%S"), "phase": phase, "action": action}
        rec.update(data)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def save_report(run_dir: Path, report: dict) -> Path:
    p = run_dir / "report.json"
    p.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def save_markdown(run_dir: Path, text: str) -> Path:
    p = run_dir / "report.md"
    p.write_text(text, encoding="utf-8")
    return p


def attack_report_markdown(atk: dict, report: dict) -> str:
    v = report["verdict"]
    lines = [
        f"# {atk['id']} — {atk['name']}",
        "",
        f"*Класс:* {atk.get('class')} · *сигнал:* {atk.get('signal')} · "
        f"*канал:* {atk.get('channel')} · *ATLAS:* {atk.get('atlas', '—')} · "
        f"*мишень:* {report['target']}",
        "",
        "## Вердикт",
        "",
        f"| Стадия | Результат |",
        f"|---|---|",
        f"| Внедрение (память содержит нагрузку) | {'**ДА**' if v['implanted'] else 'нет'} |",
        f"| Активация (маркеры в ответе) | {v['activated_triggers']}/{v['triggers_total']} |",
        f"| Принятие (без отказа применять) | {v.get('adopted_triggers', 'н/д')}/{v['triggers_total']} |",
        f"| Полезность до → после | {v['utility_before']} → {v['utility_after']} |",
        "",
    ]
    if v["matched_chunks"]:
        lines += ["## Evidence: память", ""]
        for c in v["matched_chunks"][:5]:
            src = c.get("source", "?")
            lines.append(f"**Чанк `{c['id'][:8]}`** (источник: {src}):")
            lines.append("")
            lines.append("> " + c["chunk"][:400].replace("\n", "\n> "))
            lines.append("")
    lines += ["## Триггеры (новая сессия)", "",
              "| Активация | Принятие | Судья | Вопрос |", "|---|---|---|---|"]
    for t in report["trigger_results"]:
        mark = "**ДА**" if t["activated"] else "нет"
        if t.get("exposure_only"):
            mark = "только упоминание"
        ad = "**ДА**" if t.get("adopted") else "нет"
        jd = t.get("judge", {}).get("verdict", "—") if t.get("judge") else "—"
        lines.append(f"| {mark} | {ad} | {jd} | {t['question'][:80]} |")
    lines += ["", "## Ответы на триггеры", ""]
    for i, t in enumerate(report["trigger_results"], 1):
        lines.append(f"**T{i}.** {t['question']}")
        lines.append("")
        lines.append("> " + t["answer"][:600].replace("\n", "\n> "))
        lines.append("")
    return "\n".join(lines)


def battery_markdown(rows: list, reports: list) -> str:
    lines = [
        "# Батарея атак — сводный отчёт",
        "",
        f"Прогон: {time.strftime('%Y-%m-%d %H:%M')} · атак: {len(reports)}",
        "",
        "| Атака | Сигнал | Внедрение | Активация | Полезность |",
        "|---|---|---|---|---|",
    ]
    for atk, rep in zip(rows, reports):
        v = rep["verdict"]
        lines.append(
            f"| {atk['id']} | {atk.get('signal')} "
            f"| {'да' if v['implanted'] else '—'} "
            f"| {v['activated_triggers']}/{v['triggers_total']} "
            f"({v.get('adopted_triggers', 'н/д')} принято) "
            f"| {v['utility_before']} → {v['utility_after']} |"
        )
    total_triggers = sum(r["verdict"]["triggers_total"] for r in reports)
    total_act = sum(r["verdict"]["activated_triggers"] for r in reports)
    implanted = sum(1 for r in reports if r["verdict"]["implanted"])
    lines += [
        "",
        f"**Итого:** внедрение {implanted}/{len(reports)} атак, "
        f"активация {total_act}/{total_triggers} триггеров.",
        "",
    ]
    return "\n".join(lines)
