"""attacks_loader.py — автоподхват attack-паков из attacks/ (killer feature).

Новый файл в attacks/ = новая атака. Loader ничего не знает про конкретные атаки
заранее — только про интерфейс core.attack_base.AttackBase. Никаких правок здесь не
требуется, чтобы добавить атаку — только чтобы изменить САМ протокол обнаружения
(и это BREAKING, см. CLAUDE.md).

Регистрация — через AttackBase.__init_subclass__ (см. core/attack_base.py): импорт
файла пака сам кладёт класс в реестр, discover() просто обходит файлы и импортирует их.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.attack_base import AttackBase


class AttackRegistry:
    _classes: dict[str, type[AttackBase]] = {}

    @classmethod
    def register(cls, attack_cls: type[AttackBase]) -> None:
        attack_id = attack_cls.metadata.id
        existing = cls._classes.get(attack_id)
        if existing is not None and existing is not attack_cls:
            raise ValueError(
                f"Дублирующийся attack id={attack_id!r}: {existing.__module__} vs {attack_cls.__module__}. "
                "id атаки должен быть уникален — переименуй один из паков."
            )
        cls._classes[attack_id] = attack_cls

    @classmethod
    def all(cls) -> dict[str, type[AttackBase]]:
        return dict(cls._classes)

    @classmethod
    def get(cls, attack_id: str) -> type[AttackBase]:
        if attack_id not in cls._classes:
            raise KeyError(
                f"Атака {attack_id!r} не найдена. Известные: {sorted(cls._classes)}. "
                "Вызван discover()?"
            )
        return cls._classes[attack_id]

    @classmethod
    def clear(cls) -> None:
        cls._classes.clear()


def _iter_pack_files(attacks_dir: Path):
    for path in sorted(attacks_dir.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        if path.name == "CLAUDE.md":
            continue
        yield path


def discover(attacks_dir: str | Path = "attacks") -> dict[str, type[AttackBase]]:
    """Импортирует каждый *.py под attacks_dir (кроме __init__.py) — импорт файла
    триггерит __init_subclass__ у любого AttackBase-подкласса внутри, что и
    регистрирует атаку. Дубликат id -> ValueError сразу при загрузке (fail fast)."""
    attacks_dir = Path(attacks_dir)
    if not attacks_dir.exists():
        return AttackRegistry.all()

    for path in _iter_pack_files(attacks_dir):
        module_name = "attacks_pack_" + "_".join(path.relative_to(attacks_dir).with_suffix("").parts)
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

    return AttackRegistry.all()


def reload(attacks_dir: str | Path = "attacks") -> dict[str, type[AttackBase]]:
    """Стретч-цель: 'онлайн'-кастомизация без рестарта процесса. Сброс реестра +
    повторный discover(). Вызывается явно (CLI-команда `reload`), не filesystem-watch —
    watch можно добавить поверх, не меняя этот контракт."""
    AttackRegistry.clear()
    for name in [m for m in sys.modules if m.startswith("attacks_pack_")]:
        del sys.modules[name]
    return discover(attacks_dir)


def load(attack_id: str, attacks_dir: str | Path = "attacks") -> type[AttackBase]:
    if attack_id not in AttackRegistry.all():
        discover(attacks_dir)
    return AttackRegistry.get(attack_id)
