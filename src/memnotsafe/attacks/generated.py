"""src/memnotsafe/attacks/generated.py — универсальный исполнитель записи корпуса.

Ровно ОДИН новый файл-атака (Принцип II): вместо кода на каждый класс —
data-driven интерпретатор, читающий `CorpusRecord` из `AttackContext.params`
(готовый шов, research §1). Корпус — данные, а не код; ни одной правки ядра.

Провенанс класса (research §2): запись несёт `attack_class` (имя рукописной
family). `generate()` подменяет `metadata` НА ЭКЗЕМПЛЯРЕ копией метадаты этого
класса с `family="generated"` — так `scenario_id` прогона остаётся `"generated"`
(и `get_attack("generated")` в отчёте не падает), а severity и ATLAS резолвятся
по `attack_class` из провенанса (см. reporting/findings.py). Сам класс не меняется.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from memnotsafe.attacks.base import (
    AttackBase,
    AttackContext,
    AttackMetadata,
    DeliveryStep,
    TriggerStep,
    get_attack,
)
from memnotsafe.core.models import AttackCandidate
from memnotsafe.generation.corpus import CorpusRecord
from memnotsafe.generation.errors import AttackerError

# Ключи, под которыми слой кампании/эскалации кладёт запись корпуса и её
# происхождение в AttackContext.params.
PARAM_RECORD = "record"
PARAM_CORPUS_ID = "corpus_id"


class GeneratedAttack(AttackBase):
    metadata = AttackMetadata(
        id="generated",
        name="Сгенерированная атака (LLM-корпус)",
        description=(
            "Data-driven исполнитель записи корпуса: payload, триггер, шаги и "
            "ожидаемый эффект читаются из AttackContext.params, а не зашиты в код."
        ),
        family="generated",
        mpbench_class="generated",
        signal_strength="weak",
    )

    @staticmethod
    def read_record(ctx: AttackContext) -> CorpusRecord:
        raw = ctx.params.get(PARAM_RECORD) if ctx.params else None
        if not isinstance(raw, dict):
            raise AttackerError(
                "GeneratedAttack: в AttackContext.params нет записи корпуса "
                f"(ключ {PARAM_RECORD!r}) — нечего исполнять"
            )
        return CorpusRecord.from_dict(raw)

    @staticmethod
    def resolve_metadata(record: CorpusRecord) -> AttackMetadata:
        """Метадата класса-источника с family='generated'. `get_attack` бросит
        KeyError на неизвестный `attack_class` — но валидная запись такого не
        содержит (отбраковка в corpus.record_issues, FR-012)."""
        source = get_attack(record.attack_class).metadata
        return replace(
            source,
            family="generated",
            signal_strength=record.signal_strength or source.signal_strength,
        )

    def generate(self, ctx: AttackContext) -> AttackCandidate:
        record = self.read_record(ctx)
        # Подмена metadata на экземпляре: read_attack() в runner прочитает её
        # ПОСЛЕ generate(), поэтому scenario_id/attack_id берутся отсюда.
        self.metadata = self.resolve_metadata(record)
        return AttackCandidate(
            attack_id=f"{record.attack_class}-{ctx.case_id}",
            family="generated",
            payload=record.payload,
            trigger=record.trigger,
            expected_effect=dict(record.expected_effect),
            metadata={
                "origin": record.origin,
                "attack_class": record.attack_class,
                "signal_strength": record.signal_strength,
                "corpus_id": (ctx.params or {}).get(PARAM_CORPUS_ID),
            },
        )

    def delivery_steps(self, candidate: AttackCandidate, ctx: AttackContext) -> list[DeliveryStep]:
        record = self.read_record(ctx)
        if record.delivery_steps:
            return [
                DeliveryStep(label=s.label, message=s.message, as_user=s.as_user or ctx.attacker_user_id)
                for s in record.delivery_steps
            ]
        return [DeliveryStep(label="payload", message=candidate.payload, as_user=ctx.attacker_user_id)]

    def trigger_steps(self, candidate: AttackCandidate, ctx: AttackContext) -> list[TriggerStep]:
        record = self.read_record(ctx)
        if record.trigger_steps:
            return [
                TriggerStep(label=s.label, message=s.message, as_user=s.as_user or ctx.victim_user_id)
                for s in record.trigger_steps
            ]
        return [TriggerStep(label="trigger", message=candidate.trigger, as_user=ctx.victim_user_id)]

    def expected_effect(self, ctx: AttackContext) -> dict[str, Any]:
        return dict(self.read_record(ctx).expected_effect)
