"""src/memnotsafe/core/campaign_serialize.py — ARC-2: сериализация артефактов
кампании (экспорт, вынесен из core/campaign.py при расщеплении). Чистые функции
без состояния и без периферии; форматы полей неизменны — тела перенесены
дословно. Имена публичные (импортируются в core/campaign*.py): приём объявлен
публичным именем, не подчёркнутым исключением.
"""

from __future__ import annotations

from memnotsafe.core.models import AttackResult, CampaignResult


def stage_to_dict(s) -> dict:
    """Сериализация стадии с провенансом (contracts/report-provenance.md).

    Ни одно существующее поле не переименовано и не удалено — только добавлены
    новые. При выключенном судье `judge` и `deterministic` равны null, а
    `verdict_source` — "deterministic": отчёт остаётся читаемым тем же кодом,
    что читал его до фичи."""
    return {
        "stage": s.stage,
        "success": s.success,
        "reason": s.reason,
        "evidence": s.evidence,
        "confidence": s.confidence,
        "verdict_source": s.verdict_source,
        "evidence_kind": s.evidence_kind,
        "disagreement": s.disagreement,
        "deterministic": s.deterministic.to_dict() if s.deterministic else None,
        "judge": s.judge.to_dict() if s.judge else None,
    }


def case_summary(result: AttackResult) -> dict:
    return {
        "case_id": result.case_id,
        "attack_id": result.attack_id,
        "family": result.family,
        "success": result.success,
        "stages": {s.stage: s.success for s in result.stages},
        "attacker_user_id": result.attacker_user_id,
        "victim_user_id": result.victim_user_id,
    }


def campaign_to_dict(cr: CampaignResult, metadata: dict | None = None) -> dict:
    """Сериализация кампании. `family` (002, FR-003/FR-013) пишется РЯДОМ с
    `attack_id`, а не вместо него: у сгенерированного случая `attack_id` — имя
    класса-источника и сам по себе валидный ключ ATTACK_REGISTRY, так что
    восстановить по нему семью нельзя — прочитается рукописная атака вместо
    корпусной. Поле аддитивное: ни одно существующее не переименовано, старые
    файлы читаются прежним fallback'ом читателя (cli.load_campaign)."""
    return {
        "run_id": cr.run_id,
        "scenario_id": cr.scenario_id,
        "attempts": cr.attempts,
        "metadata": metadata or {},
        "aggregate_metrics": cr.aggregate_metrics,
        "results": [
            {
                "case_id": r.case_id,
                "attack_id": r.attack_id,
                "family": r.family,
                "success": r.success,
                "stages": [stage_to_dict(s) for s in r.stages],
                "attacker_user_id": r.attacker_user_id,
                "victim_user_id": r.victim_user_id,
                "evidence": r.evidence,
            }
            for r in cr.results
        ],
    }
