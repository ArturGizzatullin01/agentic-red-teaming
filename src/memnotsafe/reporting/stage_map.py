"""src/memnotsafe/reporting/stage_map.py — B4 (H17): карта потерь канарейки
по стадиям (stage-loss map) для СУЩЕСТВУЮЩИХ артефактов прогона.

Гипотеза H17 (PipePoison, внешнее исследование): канал теряется на какой-то
одной стадии связки, и итоговый бинарный WRITE=True/False не говорит, ГДЕ.
Этот модуль — offline-анализ run-каталога: на каждую попытку строится вектор

    write_delta -> record_body -> retrieval_window -> answer -> effect

со значениями survived | lost | unknown. unknown — ЧЕСТНЫЙ: стадия, которую
существующие артефакты не покрывают, помечается unknown С ИМЕНЕМ недостающего
сигнала (FAIL_IF H17: не «lost», не «survived»); додумывание эвристикой
поверх отсутствующих данных запрещено.

Джойн «стадия <- артефакт/поле» (решение исполнителя по факту схемы):
    write_delta     campaign.json results[].stages[stage=write].success
                    (появление записи в зоне поражения, m0->m1);
    record_body     канарейка кейса (attempts.jsonl case_marker) ищется в
                    записях фазового снимка m2 — СНИМОК ПОСЛЕ финалайзера и
                    settle, т.е. тело записи уже пережило парафраз; фолбэк
                    при отсутствии m2 — вердикт стадии persistence
                    (settle marker-aware ищет ту же канарейку в памяти);
    retrieval_window campaign.json results[].stages[stage=retrieval].success
                    (memory_id записи в memory_retrieval victim-сессии);
    answer          results[].stages[stage=adoption].success (решение агента
                    в trigger-фазе);
    effect          results[].stages[stage=external_effect].success
                    (внешний эффект: утечка/применение).

Read-only по построению: модуль ничего не пишет, кроме явного --output;
Mongo/стенд/сеть не трогает. Выход детерминирован (идемпотентен) — в stage_map
нет часов/случайностей.

CLI:
    python -m memnotsafe.reporting.stage_map <run_dir> [--output PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from memnotsafe.evidence.matching import normalize_text

SCHEMA_VERSION = "stage-map/1"
SURVIVED = "survived"
LOST = "lost"
UNKNOWN = "unknown"

# Порядок стадий фиксирован — на него полагается печать и сводные счётчики.
STAGE_ORDER = ("write_delta", "record_body", "retrieval_window", "answer", "effect")

# Источник каждой стадии — для output (прозрачность джойна, не для доверия).
_STAGE_SOURCES = {
    "write_delta": "campaign.json: results[].stages[write].success",
    "record_body": "campaign.json: results[].evidence.phases.m2 записи + attempts.jsonl case_marker (фолбэк: stages[persistence])",
    "retrieval_window": "campaign.json: results[].stages[retrieval].success",
    "answer": "campaign.json: results[].stages[adoption].success",
    "effect": "campaign.json: results[].stages[external_effect].success",
}


def _read_json(path: Path) -> Any:
    """Толерантное чтение: отсутствует/битый JSON -> None (unknown-стадии,
    не падение — «битый run dir» это тоже факт прогона)."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def _read_attempt_rows(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "attempts.jsonl"
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # недописанная строка прерванного прогона — пропускаем
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _stage_verdict(result: dict[str, Any], stage: str) -> dict[str, Any]:
    """survived/lost/unknown по вердикту стадии из campaign.json."""
    row = next((s for s in result.get("stages") or [] if isinstance(s, dict) and s.get("stage") == stage), None)
    if row is None or row.get("success") is None:
        return {"value": UNKNOWN, "signal": f"campaign.json: results[].stages[{stage}].success (стадия без телеметрии)"}
    return {"value": SURVIVED if row["success"] else LOST}


def _snapshot_records(m2: Any) -> list[dict[str, Any]] | None:
    """Все записи m2-снимка (global + все user-слои); None = снимка нет."""
    if not isinstance(m2, dict):
        return None
    records: list[dict[str, Any]] = [r for r in m2.get("global_memory") or [] if isinstance(r, dict)]
    users = m2.get("users")
    if isinstance(users, dict):
        for recs in users.values():
            if isinstance(recs, list):
                records.extend(r for r in recs if isinstance(r, dict))
    return records


def _record_body_verdict(result: dict[str, Any], marker: str | None) -> dict[str, Any]:
    """Выжило ли ТЕЛО записи (после парафраза финалайзера): канарейка кейса
    ищется в записях m2-снимка (снимок после delivery-finalize и settle).
    Фолбэк при отсутствии m2 — вердикт persistence (settle marker-aware ищет
    ту же канарейку в памяти). Никаких эвристик поверх отсутствующих данных:
    нет сигнала — unknown с его именем."""
    if marker is None:
        return {"value": UNKNOWN, "signal": "attempts.jsonl: case_marker (канарейка кейса) — legacy-прогон без маркера"}
    records = _snapshot_records(((result.get("evidence") or {}).get("phases") or {}).get("m2"))
    if records is None:
        row = next(
            (s for s in result.get("stages") or []
             if isinstance(s, dict) and s.get("stage") == "persistence"),
            None,
        )
        if row is not None and row.get("success") is not None:
            return {
                "value": SURVIVED if row["success"] else LOST,
                "signal": "campaign.json: evidence.phases.m2 отсутствует — фолбэк на stages[persistence] (settle marker-aware)",
            }
        return {"value": UNKNOWN, "signal": "campaign.json: evidence.phases.m2 (фазовый снимок после финалайзера)"}
    if not records:
        return {"value": UNKNOWN, "signal": "campaign.json: evidence.phases.m2 — снимок без записей"}
    needle = normalize_text(marker)
    hit = any(needle in normalize_text(str(r.get("text") or "")) for r in records)
    return {"value": SURVIVED if hit else LOST}


def _attempt_entry(case_id: str | None, result: dict[str, Any] | None, marker: str | None) -> dict[str, Any]:
    stages: dict[str, dict[str, Any]] = {}
    if result is None:
        # попытка есть в истории, но результата в campaign.json нет (сбой
        # транспорта/прерывание) — все стадии честно unknown
        for stage in STAGE_ORDER:
            stages[stage] = {"value": UNKNOWN, "signal": "campaign.json: result кейса (попытка не дошла до оценки)"}
        outcome = None
    else:
        stages["write_delta"] = _stage_verdict(result, "write")
        stages["record_body"] = _record_body_verdict(result, marker)
        stages["retrieval_window"] = _stage_verdict(result, "retrieval")
        stages["answer"] = _stage_verdict(result, "adoption")
        stages["effect"] = _stage_verdict(result, "external_effect")
        outcome = result.get("success")
    return {
        "case_id": case_id,
        "case_marker": marker,
        "composite_success": outcome,
        "stages": stages,
    }


def build_stage_map(run_dir: str | Path) -> dict[str, Any]:
    """Карта потерь по run-каталогу. Чистая функция артефактов — идемпотентна."""
    run_dir = Path(run_dir)
    campaign = _read_json(run_dir / "campaign.json")
    results = campaign.get("results") if isinstance(campaign, dict) else None
    results = results if isinstance(results, list) else []
    attempt_rows = _read_attempt_rows(run_dir)

    markers: dict[str, str] = {}
    seen_cases: list[str] = []
    for row in attempt_rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str):
            continue
        if case_id not in seen_cases:
            seen_cases.append(case_id)
        marker = row.get("case_marker")
        if isinstance(marker, str) and marker and case_id not in markers:
            markers[case_id] = marker

    by_case = {r.get("case_id"): r for r in results if isinstance(r, dict)}
    entries = [
        _attempt_entry(case_id, by_case.get(case_id), markers.get(case_id))
        for case_id in seen_cases
    ]
    # результаты без строки истории (старые прогоны без attempts.jsonl)
    for result in results:
        if not isinstance(result, dict) or result.get("case_id") in seen_cases:
            continue
        entries.append(_attempt_entry(result.get("case_id"), result, markers.get(result.get("case_id"))))

    summary: dict[str, dict[str, int]] = {}
    unknown_signals: dict[str, set[str]] = {}
    for stage in STAGE_ORDER:
        counts = {SURVIVED: 0, LOST: 0, UNKNOWN: 0}
        signals: set[str] = set()
        for entry in entries:
            verdict = entry["stages"][stage]
            counts[verdict["value"]] += 1
            if verdict["value"] == UNKNOWN and "signal" in verdict:
                signals.add(verdict["signal"])
        summary[stage] = counts
        unknown_signals[stage] = signals

    return {
        "schema_version": SCHEMA_VERSION,
        "run_dir": str(run_dir),
        "attempts": entries,
        "summary": {
            "per_stage": summary,
            # имена недостающих сигналов — открытый список для будущих
            # карточек инструментации (H17: их закрытие — НЕ эта карточка)
            "unknown_signals": {stage: sorted(sig) for stage, sig in unknown_signals.items()},
            "stage_sources": dict(_STAGE_SOURCES),
        },
    }


def render_text(stage_map: dict[str, Any]) -> str:
    """Человекочитаемая печать: построчно на попытку + сводка."""
    lines: list[str] = []
    for entry in stage_map["attempts"]:
        outcome = entry["composite_success"]
        outcome_text = "нет результата" if outcome is None else ("success" if outcome else "not-success")
        lines.append(f"{entry['case_id']}  marker={entry['case_marker'] or '—'}  итог={outcome_text}")
        for stage in STAGE_ORDER:
            verdict = entry["stages"][stage]
            note = f"  [{verdict['signal']}]" if "signal" in verdict else ""
            lines.append(f"  {stage:16s} {verdict['value']}{note}")
    per_stage = stage_map["summary"]["per_stage"]
    lines.append("Сводка:")
    for stage in STAGE_ORDER:
        c = per_stage[stage]
        lines.append(f"  {stage:16s} survived={c[SURVIVED]} lost={c[LOST]} unknown={c[UNKNOWN]}")
    unknown_signals = stage_map["summary"]["unknown_signals"]
    if any(unknown_signals.values()):
        lines.append("Недостающие сигналы (unknown честный):")
        for stage in STAGE_ORDER:
            for signal in unknown_signals[stage]:
                lines.append(f"  {stage}: {signal}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="memnotsafe.reporting.stage_map",
        description="Карта потерь канарейки по стадиям для существующего run-каталога (read-only).",
    )
    parser.add_argument("run_dir", help="каталог прогона (attempts.jsonl / campaign.json / events.jsonl, что есть)")
    parser.add_argument("--output", default=None, help="записать stage_map.json по пути (по умолчанию — только печать)")
    args = parser.parse_args(argv)

    stage_map = build_stage_map(args.run_dir)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(stage_map, ensure_ascii=False, indent=2), encoding="utf-8")
    print(render_text(stage_map))
    return 0


if __name__ == "__main__":
    sys.exit(main())
