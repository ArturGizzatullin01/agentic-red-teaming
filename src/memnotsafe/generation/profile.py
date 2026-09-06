"""src/memnotsafe/generation/profile.py — загрузка и валидация файла-профиля агента.

Профиль — декларативный вход генерации (US1): назначение агента, интерфейс,
инструменты, модель памяти и признаки компрометации. Секретов не содержит
(FR-016). Схема — contracts/agent-profile.schema.md.

Вся валидация — ДО любых сетевых вызовов (research §3, §11): отсутствие
обязательной секции или пустой `compromise.external_effect` → `AttackerError`
(config) → `exit 1`. `external_effect` обязателен, потому что без него композит
(Принцип V) не может дать `success` — генерация «бесполезного корпуса» отсекается
на входе (acceptance scenario US1-3).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from memnotsafe.generation.errors import AttackerError


@dataclass
class InterfaceSpec:
    language: str
    message_format: str
    identity_field: str


@dataclass
class ToolSpec:
    name: str
    arguments: list[str]
    identity_arg: str | None = None


@dataclass
class MemorySpec:
    layers: list[str]
    write_triggers: list[str]


@dataclass
class CompromiseSpec:
    leak_indicators: list[str]
    external_effect_type: str
    external_effect_required_fields: list[str]


@dataclass
class AgentProfile:
    id: str
    purpose: str
    interface: InterfaceSpec
    tools: list[ToolSpec]
    memory: MemorySpec
    compromise: CompromiseSpec
    sha256: str
    raw: dict[str, Any] = field(default_factory=dict)


def _require(block: dict[str, Any], key: str, where: str) -> Any:
    if key not in block or block[key] in (None, "", [], {}):
        raise AttackerError(f"профиль {where}: отсутствует обязательная секция/поле {key!r}")
    return block[key]


def _profile_sha256(raw: dict[str, Any]) -> str:
    """Хеш нормализованного содержимого профиля — идёт в провенанс корпуса,
    чтобы прогон не под родной профиль был заметен в отчёте (SC-002, Edge Case).
    Нормализация — канонический JSON с сортировкой ключей: перестановка секций
    в YAML не меняет хеш, а любое смысловое изменение меняет."""
    canonical = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_profile(raw: dict[str, Any], *, where: str = "<inline>") -> AgentProfile:
    if not isinstance(raw, dict):
        raise AttackerError(f"профиль {where}: ожидался YAML-объект, получено {type(raw).__name__}")

    interface_raw = _require(raw, "interface", where)
    tools_raw = _require(raw, "tools", where)
    memory_raw = _require(raw, "memory", where)
    compromise_raw = _require(raw, "compromise", where)

    interface = InterfaceSpec(
        language=str(_require(interface_raw, "language", f"{where}.interface")),
        message_format=str(_require(interface_raw, "message_format", f"{where}.interface")),
        identity_field=str(_require(interface_raw, "identity_field", f"{where}.interface")),
    )

    tools: list[ToolSpec] = []
    for i, t in enumerate(tools_raw):
        tools.append(
            ToolSpec(
                name=str(_require(t, "name", f"{where}.tools[{i}]")),
                arguments=[str(a) for a in _require(t, "arguments", f"{where}.tools[{i}]")],
                identity_arg=(str(t["identity_arg"]) if t.get("identity_arg") else None),
            )
        )

    memory = MemorySpec(
        layers=[str(x) for x in _require(memory_raw, "layers", f"{where}.memory")],
        write_triggers=[str(x) for x in _require(memory_raw, "write_triggers", f"{where}.memory")],
    )

    external = _require(compromise_raw, "external_effect", f"{where}.compromise")
    effect_type = _require(external, "type", f"{where}.compromise.external_effect")
    required_fields = _require(external, "required_fields", f"{where}.compromise.external_effect")

    compromise = CompromiseSpec(
        leak_indicators=[str(x) for x in _require(compromise_raw, "leak_indicators", f"{where}.compromise")],
        external_effect_type=str(effect_type),
        external_effect_required_fields=[str(x) for x in required_fields],
    )

    return AgentProfile(
        id=str(_require(raw, "id", where)),
        purpose=str(_require(raw, "purpose", where)),
        interface=interface,
        tools=tools,
        memory=memory,
        compromise=compromise,
        sha256=_profile_sha256(raw),
        raw=raw,
    )


def load_profile(path: str | Path) -> AgentProfile:
    path = Path(path)
    if not path.exists():
        raise AttackerError(f"файл-профиль не найден: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AttackerError(f"профиль {path} не разобран как YAML: {exc}") from exc
    return parse_profile(raw, where=str(path))
