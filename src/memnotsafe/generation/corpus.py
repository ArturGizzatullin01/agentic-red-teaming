"""src/memnotsafe/generation/corpus.py — модель корпуса атак и его YAML-сериализация.

Корпус — сохранённый переиспользуемый набор конкретных атак под формат профиля.
Выход `generate`, вход прогона `run`/`campaign`. Коммитится (research §5). Схема —
contracts/corpus.schema.md.

Отбраковка невалидной записи (FR-012) — единственное место, где решается, что
атака вообще НЕ проводится: пустой payload/trigger, неизвестный `attack_class`,
`expected_effect` без обязательных полей класса. На precompute такая запись просто
не пишется; на онлайн-уровне (эскалация) её отбраковка тратит попытку и
фиксируется в провенансе.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from memnotsafe.generation.attack_classes import AttackClassSpec
from memnotsafe.generation.errors import AttackerError

ORIGIN_CORPUS = "corpus"
ORIGIN_ONLINE = "online"


def tool_version() -> str:
    """Версия инструмента для провенанса корпуса — из метаданных пакета, с
    запасным значением для src-layout без установки."""
    try:
        from importlib.metadata import version

        return version("memnotsafe")
    except Exception:  # noqa: BLE001 — пакет может быть не установлен (pythonpath=src)
        return "0.1.0"


@dataclass
class StepSpec:
    """Один мультитёрн-шаг доставки/триггера. `as_user=None` → раннер подставит
    атакующего (для доставки) или жертву (для триггера)."""

    label: str
    message: str
    as_user: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"label": self.label, "message": self.message}
        if self.as_user is not None:
            out["as_user"] = self.as_user
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> StepSpec:
        return cls(label=str(raw.get("label", "")), message=str(raw.get("message", "")), as_user=raw.get("as_user"))


@dataclass
class CorpusRecord:
    attack_class: str
    payload: str
    trigger: str
    expected_effect: dict[str, Any]
    signal_strength: str = "strong"
    origin: str = ORIGIN_CORPUS
    delivery_steps: list[StepSpec] = field(default_factory=list)
    trigger_steps: list[StepSpec] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "attack_class": self.attack_class,
            "payload": self.payload,
            "trigger": self.trigger,
            "expected_effect": self.expected_effect,
            "signal_strength": self.signal_strength,
            "origin": self.origin,
        }
        if self.delivery_steps:
            out["delivery_steps"] = [s.to_dict() for s in self.delivery_steps]
        if self.trigger_steps:
            out["trigger_steps"] = [s.to_dict() for s in self.trigger_steps]
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CorpusRecord:
        if not isinstance(raw, dict):
            raise AttackerError(f"запись корпуса должна быть объектом, получено {type(raw).__name__}")
        return cls(
            attack_class=str(raw.get("attack_class", "")),
            payload=str(raw.get("payload", "")),
            trigger=str(raw.get("trigger", "")),
            expected_effect=dict(raw.get("expected_effect") or {}),
            signal_strength=str(raw.get("signal_strength", "strong")),
            origin=str(raw.get("origin", ORIGIN_CORPUS)),
            delivery_steps=[StepSpec.from_dict(s) for s in (raw.get("delivery_steps") or [])],
            trigger_steps=[StepSpec.from_dict(s) for s in (raw.get("trigger_steps") or [])],
        )


@dataclass
class CorpusProvenance:
    profile_id: str
    profile_sha256: str
    attack_classes: list[str]
    generator_model: str
    generator_provider: str
    tool_version: str
    created_at: str
    attacker_calls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CorpusProvenance:
        raw = raw or {}
        return cls(
            profile_id=str(raw.get("profile_id", "")),
            profile_sha256=str(raw.get("profile_sha256", "")),
            attack_classes=[str(x) for x in (raw.get("attack_classes") or [])],
            generator_model=str(raw.get("generator_model", "")),
            generator_provider=str(raw.get("generator_provider", "")),
            tool_version=str(raw.get("tool_version", "")),
            created_at=str(raw.get("created_at", "")),
            attacker_calls=int(raw.get("attacker_calls", 0) or 0),
        )


@dataclass
class Corpus:
    provenance: CorpusProvenance
    records: list[CorpusRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance.to_dict(),
            "attacks": [r.to_dict() for r in self.records],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Corpus:
        if not isinstance(raw, dict):
            raise AttackerError(f"корпус должен быть YAML-объектом, получено {type(raw).__name__}")
        return cls(
            provenance=CorpusProvenance.from_dict(raw.get("provenance") or {}),
            records=[CorpusRecord.from_dict(r) for r in (raw.get("attacks") or [])],
        )


def record_issues(record: CorpusRecord, *, class_spec: AttackClassSpec | None = None) -> list[str]:
    """Причины отбраковки записи (FR-012). Пустой список = запись валидна.
    `class_spec` доступен на генерации (полная проверка полей эффекта); на
    прогоне из готового корпуса его нет — проверяются лишь внутренние инварианты."""
    from memnotsafe.attacks.base import ATTACK_REGISTRY  # ленивый импорт: см. attack_classes.py

    issues: list[str] = []
    if not record.payload.strip():
        issues.append("пустой payload")
    if not record.trigger.strip():
        issues.append("пустой trigger")
    if record.attack_class not in ATTACK_REGISTRY:
        issues.append(f"attack_class {record.attack_class!r} вне ATTACK_REGISTRY")
    if not isinstance(record.expected_effect, dict) or not record.expected_effect.get("type"):
        issues.append("expected_effect без поля type")

    if class_spec is not None:
        if record.expected_effect.get("type") != class_spec.effect_type:
            issues.append(
                f"expected_effect.type={record.expected_effect.get('type')!r} "
                f"!= {class_spec.effect_type!r} класса {class_spec.family}"
            )
        for f in class_spec.effect_required_fields:
            if f not in record.expected_effect:
                issues.append(f"в expected_effect нет обязательного поля {f!r}")
    return issues


def is_valid_record(record: CorpusRecord, *, class_spec: AttackClassSpec | None = None) -> bool:
    return not record_issues(record, class_spec=class_spec)


def read_corpus(path: str | Path) -> Corpus:
    path = Path(path)
    if not path.exists():
        raise AttackerError(f"корпус не найден: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AttackerError(f"корпус {path} не разобран как YAML: {exc}") from exc
    return Corpus.from_dict(raw)


def valid_records(corpus: Corpus) -> list[CorpusRecord]:
    """Записи, пригодные к прогону (FR-012). Невалидные молча отсеиваются — на
    прогоне из готового корпуса это защита от вручную испорченного файла."""
    return [r for r in corpus.records if is_valid_record(r)]


def write_corpus(corpus: Corpus, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(corpus.to_dict(), allow_unicode=True, sort_keys=False, width=100),
        encoding="utf-8",
    )
    return path
