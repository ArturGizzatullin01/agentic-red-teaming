"""memred/core/config.py — YAML как чистый configuration layer (spec §10):
КТО атакует/жертва, КАКОЙ adapter/family, СКОЛЬКО повторов. Никакой Python-
логики в YAML — сами шаги атаки декларирует класс в memred/attacks/*.py."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ActorConfig:
    user_id: str


@dataclass
class TargetSpec:
    adapter: str = "mock"
    base_url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    id: str
    path: Path
    target: TargetSpec
    attacker: ActorConfig
    victim: ActorConfig
    attack_family: str
    repetitions: int = 1
    trigger_override: str | None = None
    oracle_overrides: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def load_scenario(path: str | Path) -> Scenario:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Сценарий не найден: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    try:
        actors = raw["actors"]
        attack = raw["attack"]
    except KeyError as exc:
        raise ValueError(f"В сценарии {path} отсутствует обязательное поле {exc}") from exc

    target_raw = raw.get("target", {}) or {}
    victim_raw = actors.get("victim") or actors["attacker"]  # single-user атаки: victim==attacker по умолчанию

    return Scenario(
        id=raw.get("id", path.stem),
        path=path,
        target=TargetSpec(
            adapter=target_raw.get("adapter", "mock"),
            base_url=target_raw.get("base_url"),
            extra={k: v for k, v in target_raw.items() if k not in ("adapter", "base_url")},
        ),
        attacker=ActorConfig(user_id=str(actors["attacker"]["user_id"])),
        victim=ActorConfig(user_id=str(victim_raw["user_id"])),
        attack_family=attack["family"],
        repetitions=int((raw.get("metrics") or {}).get("repetitions", 1)),
        trigger_override=(raw.get("trigger") or {}).get("prompt"),
        oracle_overrides=raw.get("oracle", {}) or {},
        raw=raw,
    )


def build_adapter(scenario: Scenario, target_override: str | None = None):
    """Резолвит TargetAdapter по scenario.target.adapter. --target с CLI
    переопределяет base_url (или сам adapter, если передано имя известного
    адаптера вместо URL) — не трогает атаку/сценарий."""
    from memred.adapters.mock import MockTarget

    adapter_name = scenario.target.adapter
    base_url = scenario.target.base_url
    if target_override and target_override != "mock":
        base_url = target_override

    if adapter_name == "mock" or target_override == "mock":
        vulnerable = bool(scenario.target.extra.get("vulnerable", True))
        return MockTarget(vulnerable=vulnerable)

    if adapter_name in ("openai", "openai_compatible"):
        from memred.adapters.openai import OpenAICompatibleAdapter

        if not base_url:
            raise ValueError(f"Сценарию {scenario.id} нужен target.base_url или --target <url> для adapter=openai")
        return OpenAICompatibleAdapter(base_url=base_url, **scenario.target.extra)

    if adapter_name == "investment_stand":
        from memred.adapters.investment_stand import InvestmentStandAdapter

        if not base_url:
            raise ValueError(f"Сценарию {scenario.id} нужен target.base_url или --target <url> для adapter=investment_stand")
        return InvestmentStandAdapter(base_url=base_url, **scenario.target.extra)

    raise ValueError(f"Неизвестный adapter={adapter_name!r} в сценарии {scenario.id}")
