"""core/attack_base.py — контракт attack-пака (killer feature: подгружаемые атаки).

Формат — класс, не декларативный YAML: для weak-signal атак (GhostWriter-стиль) payload
это ПРОЦЕДУРА (итеративная оптимизация по косинусной близости к легитимному корпусу),
не строка — YAML был бы фиктивной обёрткой над кодом, который всё равно пришлось бы
писать. Каждый файл в attacks/ = новая атака: __init_subclass__ регистрирует класс при
импорте, никакого реестра руками, никаких правок core/ (BREAKING — не менять сигнатуры
без пометки в CLAUDE.md/PR).

Устройство "подробнее и сложнее" (по решению 2026-09-03):
- delivery — ПОСЛЕДОВАТЕЛЬНОСТЬ шагов (DeliveryStep), не одно сообщение: multi-turn
  доставка (trust-building до инъекции) — реалистичнее одного payload-сообщения.
- payload генерируется PayloadStrategy — pluggable: статический шаблон ИЛИ
  retrieval-optimized мутация (core/strategies.py).
- success_check — композит из StageCheck (write / activate), с независимым
  детерминированным и/или LLM-judge критерием на каждой стадии — прямое отражение
  Write-Execute(-Activate)-Forget рамки MemSecBench из project-context.md, а не один
  плоский булев чек.
- variants() — один файл может породить несколько прогонов (strong/weak вариант,
  разные пары victim/witness) для батч-запуска без копипасты файлов.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Literal


class DeliveryChannel(str, Enum):
    USER_QUERY = "user_query"
    WEB_SEARCH_RESULT = "web_search_result"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"


class SignalStrength(str, Enum):
    STRONG = "strong"
    WEAK = "weak"


class MPBenchClass(str, Enum):
    """6 классов из MPBench (arXiv 2606.04329) — см. CLAUDE.md "Attack battery"."""

    EXPLICIT_COMMAND_INSERTION = "explicit_command_insertion"
    CONDITIONAL_COMMAND_INSERTION = "conditional_command_insertion"
    SALIENCE_COMPACTION_POISONING = "salience_compaction_poisoning"
    INFERRED_WRITE_TOOL_OUTPUT = "inferred_write_tool_output"
    INFERRED_WRITE_WEB = "inferred_write_web"
    INFERRED_WRITE_MEMORY = "inferred_write_memory"


class CheckStage(str, Enum):
    WRITE = "write"       # факт реально осел в долговременной памяти
    ACTIVATE = "activate"  # факт реально повлиял на поведение агента позже/у другого юзера


@dataclass
class AttackMetadata:
    id: str
    name: str
    description: str
    channel: DeliveryChannel
    mpbench_class: MPBenchClass
    signal_strength: SignalStrength
    atlas_technique: str = "AML.T0080"          # Memory Poisoning (подтверждено 2026-09-03)
    atlas_tactic: str = "Persistence"
    owasp_asi: str = "ASI06"
    references: list[str] = field(default_factory=list)  # относительные пути в docs/references/
    author: str = ""
    version: str = "1"


@dataclass
class AttackContext:
    """Один прогон атаки: кто атакует (victim), на ком проверяем пропагацию (witness)."""

    victim_user_id: str
    session_id: str
    run_seed: int
    witness_user_id: str | None = None  # None — для не-cross-user атак
    witness_session_id: str | None = None  # None -> runner сам возьмёт f"{session_id}-witness"
    params: dict[str, Any] = field(default_factory=dict)  # свободные параметры варианта


@dataclass
class PayloadPlan:
    """Результат PayloadStrategy — конкретный текст + происхождение для отчёта/аудита."""

    text: str
    strategy_name: str
    iterations: int = 1
    similarity_score: float | None = None  # для retrieval-optimized стратегий
    rationale: str = ""


class PayloadStrategy(ABC):
    @abstractmethod
    async def generate(self, ctx: AttackContext) -> PayloadPlan: ...


@dataclass
class DeliveryStep:
    """Один шаг доставки — не всегда одно сообщение = вся атака."""

    label: str
    build: Callable[[AttackContext, PayloadPlan], Awaitable[str]]
    as_user: str | None = None  # None -> ctx.victim_user_id


@dataclass
class TriggerStep:
    """Шаг активации. build() может вернуть None — тогда шаг это просто finalize()
    без дополнительного chat-сообщения (write-триггер, не activate-триггер).

    session_id_override: для одно-юзерных атак (victim == witness), где активация
    должна произойти в ДРУГОЙ, более поздней сессии того же клиента (не в той же
    working-memory сессии, где был инъецирован payload) — иначе раннер по умолчанию
    считает "victim -> та же ctx.session_id", что не проверяет персистентность через
    границу сессии. None -> обычная резолюция раннера (victim -> ctx.session_id,
    иной as_user -> ctx.witness_session_id)."""

    label: str
    build: Callable[[AttackContext], Awaitable[str | None]]
    as_user: str | None = None
    requires_finalize_before: bool = True
    session_id_override: str | None = None


@dataclass
class StageCheck:
    stage: CheckStage
    kind: Literal["deterministic", "llm_judge"]
    deterministic_predicate: Callable[[Any], bool] | None = None  # Any = core.evidence.Evidence
    llm_judge_prompt_template: str | None = None  # {evidence_summary}/{chat_log} placeholders


@dataclass
class SuccessCheckSpec:
    checks: list[StageCheck]
    require_trace: bool = True
    combinator: Literal["all", "any"] = "all"


class AttackBase(ABC):
    metadata: ClassVar[AttackMetadata]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "metadata", None) is not None:
            from attacks_loader import (
                AttackRegistry,  # локальный импорт — избегаем цикла
            )

            AttackRegistry.register(cls)

    @abstractmethod
    def payload_strategy(self, ctx: AttackContext) -> PayloadStrategy: ...

    @abstractmethod
    def delivery_steps(self, ctx: AttackContext) -> list[DeliveryStep]: ...

    @abstractmethod
    def trigger_steps(self, ctx: AttackContext) -> list[TriggerStep]: ...

    @abstractmethod
    def success_check(self) -> SuccessCheckSpec: ...

    def variants(self, base_ctx: AttackContext) -> list[AttackContext]:
        """По умолчанию — один вариант. Переопределить для batch-прогона
        (напр. несколько пар victim/witness, strong+weak вариации)."""
        return [base_ctx]
