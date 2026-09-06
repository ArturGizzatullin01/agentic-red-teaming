"""src/memnotsafe/generation/attack_classes.py — реестр универсальных описаний
классов атак (вход генерации, US1).

Описание класса агент-независимо: `goal`, намерения доставки и триггера, контракт
ожидаемого эффекта и сила сигнала. Оно несёт то, чего нет в `AttackMetadata`
рукописной атаки (метадата — для отчёта, а не для генератора). Новый класс =
новый YAML, без правок Python (FR-017). Схема — contracts/attack-class.schema.md.

Инвариант: `family` обязан существовать в `ATTACK_REGISTRY` — иначе провенанс
`attack_class` не резолвится в отчёте (`reporting/findings.py`, research §2).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from memnotsafe.generation.errors import AttackerError


@dataclass
class AttackClassSpec:
    family: str
    goal: str
    delivery_intent: str
    trigger_intent: str
    effect_type: str
    effect_required_fields: list[str]
    signal_strength: str


def _require(block: dict[str, Any], key: str, where: str) -> Any:
    if key not in block or block[key] in (None, "", [], {}):
        raise AttackerError(f"описание класса атаки {where}: отсутствует обязательное поле {key!r}")
    return block[key]


def parse_attack_class(raw: dict[str, Any], *, where: str = "<inline>") -> AttackClassSpec:
    if not isinstance(raw, dict):
        raise AttackerError(f"описание класса {where}: ожидался YAML-объект, получено {type(raw).__name__}")

    # ATTACK_REGISTRY импортируется лениво: избегаем цикла attacks<->generation
    # на этапе загрузки модулей (attacks/__init__ регистрирует GeneratedAttack).
    from memnotsafe.attacks.base import ATTACK_REGISTRY

    family = str(_require(raw, "family", where))
    if family not in ATTACK_REGISTRY:
        raise AttackerError(
            f"описание класса {where}: family={family!r} нет в ATTACK_REGISTRY "
            f"(известные: {sorted(ATTACK_REGISTRY)})"
        )

    effect = _require(raw, "expected_effect", where)
    effect_type = _require(effect, "type", f"{where}.expected_effect")
    required_fields = _require(effect, "required_fields", f"{where}.expected_effect")

    strength = str(_require(raw, "signal_strength", where))
    if strength not in ("strong", "weak"):
        raise AttackerError(f"описание класса {where}: signal_strength={strength!r} должно быть strong|weak")

    return AttackClassSpec(
        family=family,
        goal=str(_require(raw, "goal", where)),
        delivery_intent=str(_require(raw, "delivery_intent", where)),
        trigger_intent=str(_require(raw, "trigger_intent", where)),
        effect_type=str(effect_type),
        effect_required_fields=[str(x) for x in required_fields],
        signal_strength=strength,
    )


def load_attack_class(path: str | Path) -> AttackClassSpec:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AttackerError(f"описание класса {path} не разобрано как YAML: {exc}") from exc
    return parse_attack_class(raw, where=str(path))


def load_attack_classes(source: str | Path | list[str | Path]) -> list[AttackClassSpec]:
    """Источник — каталог (все `*.yaml` в нём, отсортированные по имени файла —
    детерминированный порядок для воспроизводимости) или явный список файлов."""
    if isinstance(source, (list, tuple)):
        paths = [Path(p) for p in source]
    else:
        src = Path(source)
        if src.is_dir():
            paths = sorted(src.glob("*.yaml"))
        else:
            paths = [src]

    if not paths:
        raise AttackerError(f"не найдено описаний классов атак в {source}")

    return [load_attack_class(p) for p in paths]
