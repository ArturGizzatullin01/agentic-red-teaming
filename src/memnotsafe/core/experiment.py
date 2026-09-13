"""src/memnotsafe/core/experiment.py — воспроизводимая конфигурация эксперимента
(P10b, фича 007).

ExperimentSpec фиксирует всё, от чего зависит смысл эксперимента: таргет и
модель, доступные ревизии writer/chat prompt, конфигурацию судьи и начальное
состояние, корпус и его версию, канал доставки и область пользователей,
бюджеты, digest значимых файлов рабочего дерева. Кампания пишет его в
`runs/<name>/experiment.json` ДО первого случая; experiment_id связывает
пакеты доказательств (EvidenceBundle) и историю попыток (AttemptRecord).

Неизвестные ревизии помечаются литералом "unknown" (не None-шум и не догадка):
например chat-prompt ревизия адаптера сейчас недоступна телеметрически
(P09-full закроет), target-модель берётся из scenario.target.extra, если там
указана.

Секреты НЕ включаются: хранятся только ИМЕНА переменных окружения
(api_key_env), никогда значения. Летучие поля (created_at) — в секции
`volatile`, ВНЕ digest.

**Что создаёт новый эксперимент** (изменение любого из них меняет experiment_id):
сценарий YAML; целевой adapter/base_url/модель; ревизия writer-промпта
(sha256 generation/prompts.py); атакующий provider/model/budget; судья
(включение/модель/базовый URL/порог); корпус (путь+содержимое); канал доставки
и область пользователей (attacker/victim user_id); budgets (repetitions,
online_attempts, require_case_marker); digest'ы значимых файлов.

**Что НЕ создаёт новый эксперимент**: created_at; run_id; Stop-on-success и
оракул-оверрайды попадают в spec как конфигурация, но их список зафиксирован
в payload и потому изменение тоже создаёт новый эксперимент (осознанно).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from memnotsafe.core.goal_contract import canonical_json, sha256_hex

EXPERIMENT_SCHEMA_VERSION = 1

UNKNOWN = "unknown"


class ExperimentError(ValueError):
    """Контрактное нарушение ExperimentSpec (чужая версия и т.п.)."""


def file_sha256(path: str | Path) -> str | None:
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class ExperimentSpec:
    schema_version: int
    experiment_id: str
    scenario_id: str
    target: dict
    attacker: dict
    judge: dict
    corpus: dict | None
    delivery: dict
    budgets: dict
    file_digests: dict
    volatile: dict = field(default_factory=dict)

    def _digest_payload(self) -> dict:
        """Всё, кроме летучих полей. Секреты сюда не попадают по построению
        (build_experiment_spec кладёт только имена env-переменных)."""
        return {
            "scenario_id": self.scenario_id,
            "target": self.target,
            "attacker": self.attacker,
            "judge": self.judge,
            "corpus": self.corpus,
            "delivery": self.delivery,
            "budgets": self.budgets,
            "file_digests": self.file_digests,
        }

    def digest_source(self) -> str:
        return canonical_json(self._digest_payload())

    def to_dict(self) -> dict:
        data = self._digest_payload()
        data.update(
            {
                "schema_version": self.schema_version,
                "experiment_id": self.experiment_id,
                "volatile": dict(self.volatile),
            }
        )
        return data

    @classmethod
    def from_serialized(cls, data: dict) -> "ExperimentSpec":
        if data.get("schema_version") != EXPERIMENT_SCHEMA_VERSION:
            raise ExperimentError(
                f"ExperimentSpec: schema_version={data.get('schema_version')!r} не поддерживается "
                f"(ожидается {EXPERIMENT_SCHEMA_VERSION})"
            )
        spec = cls(
            schema_version=EXPERIMENT_SCHEMA_VERSION,
            experiment_id=str(data.get("experiment_id") or ""),
            scenario_id=str(data.get("scenario_id") or ""),
            target=dict(data.get("target") or {}),
            attacker=dict(data.get("attacker") or {}),
            judge=dict(data.get("judge") or {}),
            corpus=data.get("corpus"),
            delivery=dict(data.get("delivery") or {}),
            budgets=dict(data.get("budgets") or {}),
            file_digests=dict(data.get("file_digests") or {}),
            volatile=dict(data.get("volatile") or {}),
        )
        # experiment_id — это digest содержимого: пересчитанный id обязан
        # совпасть, иначе spec подменён или сериализован чужой версией кода.
        if spec.experiment_id != sha256_hex(spec.digest_source()):
            raise ExperimentError(
                "ExperimentSpec: experiment_id не совпадает с digest содержимого — "
                "спека подменена или несовместима"
            )
        return spec


def build_experiment_spec(
    scenario,
    *,
    attacker_config=None,
    online: bool = False,
    online_attempts: int = 5,
) -> ExperimentSpec:
    """Собирает spec из конфигурации кампании. Всё неизвестное — "unknown".
    Значения секретов недоступны по построению: config несёт только имена
    переменных окружения."""
    import memnotsafe.generation.prompts as prompts_module
    from memnotsafe.attacks.base import ATTACK_REGISTRY, get_attack

    target_extra = scenario.target.extra or {}
    model_name = target_extra.get("model_name") or UNKNOWN
    auth_mode = target_extra.get("auth_mode") or UNKNOWN

    family_module = ""
    if scenario.attack_family in ATTACK_REGISTRY:
        family_module = get_attack(scenario.attack_family).__module__
    family_file = ""
    if family_module:
        import importlib

        family_file = file_sha256(importlib.import_module(family_module).__file__ or "") or UNKNOWN

    corpus_section = None
    if scenario.corpus_path:
        corpus_section = {
            "path": str(scenario.corpus_path),
            "sha256": file_sha256(scenario.corpus_path) or UNKNOWN,
        }

    spec = ExperimentSpec(
        schema_version=EXPERIMENT_SCHEMA_VERSION,
        experiment_id="",
        scenario_id=scenario.id,
        target={
            "adapter": scenario.target.adapter,
            "base_url": scenario.target.base_url,
            "model_name": model_name,
            "auth_mode": auth_mode,
        },
        attacker={
            "provider": getattr(attacker_config, "provider", None) or ("stub" if online else None),
            "model": getattr(attacker_config, "model", None) or UNKNOWN,
            "api_key_env": getattr(attacker_config, "api_key_env", None),  # только ИМЯ
            "online": online,
            # ревизия writer-промпта — sha256 исходника; chat-prompt ревизия
            # адаптера телеметрически недоступна (P09-full) — явно unknown.
            "writer_prompt_sha256": file_sha256(prompts_module.__file__) or UNKNOWN,
            "chat_prompt_revision": UNKNOWN,
        },
        judge={
            "enabled": bool(scenario.judge.enabled),
            "model": scenario.judge.model or UNKNOWN,
            "base_url": scenario.judge.base_url,
            "api_key_env": scenario.judge.api_key_env,  # только ИМЯ
            "min_confidence": scenario.judge.min_confidence,
        },
        corpus=corpus_section,
        delivery={
            "channel": scenario.target.adapter,
            "attacker_user_id": scenario.attacker.user_id,
            "victim_user_id": scenario.victim.user_id,
        },
        budgets={
            "repetitions": scenario.repetitions,
            "online_attempts": online_attempts,
            "attacker_budget": getattr(attacker_config, "budget", None),
            "require_case_marker": scenario.require_case_marker,
        },
        file_digests={
            "scenario_yaml": file_sha256(scenario.path) or UNKNOWN,
            "attack_family_source": family_file or UNKNOWN,
        },
        volatile={"created_at": datetime.now(timezone.utc).isoformat()},
    )
    object.__setattr__(spec, "experiment_id", sha256_hex(spec.digest_source()))
    return spec


def write_experiment(output_dir: str | Path, spec: ExperimentSpec) -> Path:
    path = Path(output_dir) / "experiment.json"
    path.write_text(json.dumps(spec.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def read_experiment(output_dir: str | Path) -> ExperimentSpec | None:
    """Читает experiment.json прогона. Нет файла (исторический run) → None —
    читателю ничего не выдумывается. Сломанная/подменённая спека → ExperimentError."""
    path = Path(output_dir) / "experiment.json"
    if not path.exists():
        return None
    return ExperimentSpec.from_serialized(json.loads(path.read_text(encoding="utf-8")))
