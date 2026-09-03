"""core/report.py — JSON (машиночитаемый) + человекочитаемая сводка одного или
нескольких прогонов. Маппинг на MITRE ATLAS / OWASP ASI06 — прямо из AttackMetadata,
не выводится эвристикой (интерпретируемость важнее ASR — project-context.md).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.attack_base import AttackMetadata
from core.runner import AttackRunResult


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_to_dict(result: AttackRunResult, metadata: AttackMetadata) -> dict[str, Any]:
    return {
        "attack_id": result.attack_id,
        "attack_name": metadata.name,
        "channel": metadata.channel.value,
        "mpbench_class": metadata.mpbench_class.value,
        "signal_strength": metadata.signal_strength.value,
        "mitre_atlas": {"technique": metadata.atlas_technique, "tactic": metadata.atlas_tactic},
        "owasp_asi": metadata.owasp_asi,
        "references": metadata.references,
        "run": {
            "victim_user_id": result.ctx.victim_user_id,
            "witness_user_id": result.ctx.witness_user_id,
            "session_id": result.ctx.session_id,
            "seed": result.ctx.run_seed,
        },
        "verdict": {
            "success": result.verdict.success,
            "when_activated": result.verdict.when_activated,
            "trace_present": result.verdict.trace_present,
            "combinator": result.verdict.combinator,
            "stages": [
                {
                    "stage": v.stage.value,
                    "success": v.success,
                    "confidence": v.confidence,
                    "rationale": v.rationale,
                    "what_written": v.what_written,
                    "who_affected": v.who_affected,
                }
                for v in result.verdict.stage_verdicts
            ],
        },
        "evidence": result.evidence.to_report_dict(),
    }


def write_json_report(results: list[tuple[AttackRunResult, AttackMetadata]], path: str | Path) -> Path:
    """Пишет ОБА: снапшот с таймстемпом (история — ничего не теряется между прогонами,
    урок 2026-09-03: `latest.json` без снапшотов молча съел 3 из 4 первых живых
    прогонов, потому что каждый следующий `cli.py run` его перезаписывал) и сам
    `path` (для скриптов/CI, которым нужен предсказуемый путь на "последний прогон")."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": _utc_now_iso(),
        "runs": [run_to_dict(r, m) for r, m in results],
        "summary": summarize(results),
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_path = path.parent / f"{path.stem}_{ts}{path.suffix}"
    snapshot_path.write_text(text, encoding="utf-8")
    path.write_text(text, encoding="utf-8")
    return path


def summarize(results: list[tuple[AttackRunResult, AttackMetadata]]) -> dict[str, Any]:
    total = len(results)
    succeeded = sum(1 for r, _ in results if r.verdict.success)
    by_class: dict[str, dict[str, int]] = {}
    for r, m in results:
        bucket = by_class.setdefault(m.mpbench_class.value, {"total": 0, "success": 0})
        bucket["total"] += 1
        bucket["success"] += int(r.verdict.success)
    return {
        "total_runs": total,
        "successful_runs": succeeded,
        "asr": round(succeeded / total, 3) if total else None,
        "by_mpbench_class": by_class,
    }


def human_summary(results: list[tuple[AttackRunResult, AttackMetadata]]) -> str:
    lines = ["# Сводка прогона red-teaming памяти\n"]
    s = summarize(results)
    lines.append(f"Прогонов: {s['total_runs']}, успешных: {s['successful_runs']}, ASR: {s['asr']}\n")
    for r, m in results:
        v = r.verdict
        status = "✅ УСПЕХ" if v.success else "❌ не подтверждено"
        lines.append(
            f"## {m.name} (`{m.id}`) — {status}\n"
            f"- канал: {m.channel.value}; класс MPBench: {m.mpbench_class.value}; "
            f"сигнал: {m.signal_strength.value}\n"
            f"- MITRE ATLAS: {m.atlas_technique} ({m.atlas_tactic}); OWASP: {m.owasp_asi}\n"
            f"- жертва: {r.ctx.victim_user_id}; свидетель: {r.ctx.witness_user_id}\n"
            f"- when_activated: {v.when_activated}; trace: {'есть' if v.trace_present else 'НЕТ'}\n"
            f"- диф памяти: {r.evidence.diff.summary()}\n"
            f"- обоснование: {v.rationale_text()}\n"
            f"{_what_written_lines(v)}"
        )
    return "\n".join(lines)


def _what_written_lines(v) -> str:  # v: core.judge.Verdict — не импортируем тип, чтобы не плодить цикл
    """ЧТО именно записалось (verify-finding.md требует явный ответ на этот вопрос) —
    печатаем текст находки прямо в человекочитаемом отчёте, а не только в JSON: на
    реальном прогоне против стенда с маленькой локальной моделью WRITE-стадия иногда
    формально проходит (что-то добавилось в agent_policy_memories), но текст оказывается
    НЕ похож на инъецированный payload (модель извлекла не то) — без явной цитаты в
    отчёте это легко принять за чистый успех, хотя интерпретируемость важнее ASR."""
    texts = [sv.what_written for sv in v.stage_verdicts if sv.what_written]
    if not texts:
        return ""
    quoted = "\n".join(f"  > {t}" for t in dict.fromkeys(texts))  # de-dup, сохранить порядок
    return f"- записанный текст (проверь, что это ДЕЙСТВИТЕЛЬНО ваш payload, не что-то ещё):\n{quoted}\n"
