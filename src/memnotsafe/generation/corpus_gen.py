"""src/memnotsafe/generation/corpus_gen.py — precompute-генерация корпуса (US1).

По файлу-профилю и универсальным описаниям классов атак атакующая LLM порождает
конкретные записи атак, которые собираются в переиспользуемый корпус. Чистое ЧТО:
модуль не знает о таргете и не исполняет атаки — он лишь просит модель составить
записи, разбирает ответ и отбраковывает невалидные (FR-012).

Стоимость считается через `CallBudget`: один вызов на класс, исчерпание бюджета —
штатный стоп (часть классов останется без записей, но корпус сохранится, exit 0).
"""

from __future__ import annotations

import json
from datetime import date
from typing import Any

from memnotsafe.generation.attack_classes import AttackClassSpec
from memnotsafe.generation.attacker_client import AttackerClient
from memnotsafe.generation.budget import CallBudget
from memnotsafe.generation.corpus import (
    ORIGIN_CORPUS,
    Corpus,
    CorpusProvenance,
    CorpusRecord,
    StepSpec,
    record_issues,
    tool_version,
)
from memnotsafe.generation.errors import AttackerError
from memnotsafe.generation.profile import AgentProfile
from memnotsafe.generation.prompts import build_generation_prompt


def _extract_json(text: str) -> dict[str, Any]:
    """Достаёт JSON-объект из ответа модели: голый JSON, ```json-ограждение или
    объект внутри прозы. Неудача → ValueError (запись отбраковывается)."""
    text = (text or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("в ответе модели не найден JSON-объект")
        obj = json.loads(text[start : end + 1])
    if not isinstance(obj, dict):
        raise ValueError("ответ модели — не JSON-объект")
    return obj


def parse_generation_output(raw: str, *, attack_class: str, origin: str = ORIGIN_CORPUS) -> CorpusRecord | None:
    """Разбор сырого ответа модели в запись атаки. `attack_class`/`origin` задаёт
    вызывающий слой, а не модель. Неразбираемый/отказной ответ → None (отбраковка,
    FR-012), а НЕ исключение: сбой одного класса не рушит генерацию остальных."""
    try:
        obj = _extract_json(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    return CorpusRecord(
        attack_class=attack_class,
        payload=str(obj.get("payload", "")),
        trigger=str(obj.get("trigger", "")),
        expected_effect=dict(obj.get("expected_effect") or {}),
        signal_strength=str(obj.get("signal_strength", "strong")),
        origin=origin,
        delivery_steps=[StepSpec.from_dict(s) for s in (obj.get("delivery_steps") or [])],
        trigger_steps=[StepSpec.from_dict(s) for s in (obj.get("trigger_steps") or [])],
    )


def _assert_profile_matches_classes(profile: AgentProfile, classes: list[AttackClassSpec]) -> None:
    """Contract agent-profile: `external_effect.type` профиля обязан совпасть с
    `expected_effect.type` хотя бы одного класса — иначе весь корпус отбракуется
    на прогоне и генерация бессмысленна (config-ошибка до сетевых вызовов)."""
    available = {k.effect_type for k in classes}
    if profile.compromise.external_effect_type not in available:
        raise AttackerError(
            f"профиль {profile.id}: external_effect.type="
            f"{profile.compromise.external_effect_type!r} не совпадает ни с одним классом "
            f"(доступны: {sorted(available)}) — корпус был бы бесполезен"
        )


async def generate_corpus(
    profile: AgentProfile,
    classes: list[AttackClassSpec],
    client: AttackerClient,
    budget: CallBudget,
    *,
    provider: str,
    model: str | None,
) -> Corpus:
    _assert_profile_matches_classes(profile, classes)

    records: list[CorpusRecord] = []
    used_classes: list[str] = []
    for klass in classes:
        if budget.exhausted:
            break  # штатный стоп по бюджету — часть классов без записей, но корпус сохранится
        system, user = build_generation_prompt(profile, klass)
        budget.spend()
        raw = await client.complete(user, system=system)  # AttackerError пробрасывается → exit 1

        record = parse_generation_output(raw, attack_class=klass.family)
        if record is None:
            continue  # неразбираемый ответ → отбраковка (FR-012)
        if record_issues(record, class_spec=klass):
            continue  # запись не соответствует контракту класса → отбраковка (FR-012)
        records.append(record)
        used_classes.append(klass.family)

    provenance = CorpusProvenance(
        profile_id=profile.id,
        profile_sha256=profile.sha256,
        attack_classes=sorted(set(used_classes)),
        generator_model=model or "",
        generator_provider=provider,
        tool_version=tool_version(),
        created_at=date.today().isoformat(),
        attacker_calls=budget.used,
    )
    return Corpus(provenance=provenance, records=records)
