"""src/memnotsafe/tracing/transcript.py — журнал диалога (фича 002-reporting).

Контракт: каждая ОТПРАВЛЕННАЯ реплика и каждый РЕАЛЬНО полученный ответ агента
в baseline-, delivery- и trigger-ходах сохраняются в порядке наблюдения.
Владелец сбора — Runner (знает фазу/шаг/сессию), источник content — Adapter
(реальный ответ таргета), сохранение — Campaign, показ — Reporter. Collector не
содержит стендовой логики и не оценивает успех; Reporter не реконструирует
несуществующие сообщения.

Аддитивный wire-контракт v1: {"schema_version": 1, "complete": bool,
"messages": [...]}. Старые runs поля не содержат — Reporter показывает
сохранившиеся фрагменты с пометкой «полный диалог не записывался». Скрытые
reasoning-токены модели не включаются. При ошибке сохраняется наблюдённая часть
(complete=false) — завершённая часть диалога не теряется из-за следующего
неудачного await.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SCHEMA_VERSION = 1


@dataclass
class TranscriptMessage:
    """Одна реплика диалога в порядке наблюдения."""

    run_id: str
    case_id: str
    session_id: str
    actor_user_id: str  # principal, от имени которого отправлено (или чья сессия)
    role: str  # "user" | "agent"
    phase: str  # "baseline" | "delivery" | "trigger"
    step_label: str
    sequence: int  # сквозной номер в пределах case (0-based, порядок наблюдения)
    direction: str  # "user->agent" | "agent->user"
    content: str
    observed_at: str | None = None  # фактическое время наблюдения, если известно

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TranscriptBuilder:
    """Буфер одного case. Runner добавляет сообщения по мере наблюдения;
    при ошибке помечает incomplete — сохраняется наблюдённая часть."""

    run_id: str
    case_id: str
    _messages: list[TranscriptMessage] = field(default_factory=list)
    _incomplete: bool = False
    _incomplete_reason: str = ""

    def add(self, *, session_id: str, actor_user_id: str, role: str, phase: str,
            step_label: str, content: str) -> None:
        self._messages.append(TranscriptMessage(
            run_id=self.run_id,
            case_id=self.case_id,
            session_id=session_id,
            actor_user_id=actor_user_id,
            role=role,
            phase=phase,
            step_label=step_label,
            sequence=len(self._messages),
            direction="user->agent" if role == "user" else "agent->user",
            content=content,
        ))

    def mark_incomplete(self, reason: str) -> None:
        self._incomplete = True
        self._incomplete_reason = reason

    def to_wire(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "complete": not self._incomplete,
            **({"incomplete_reason": self._incomplete_reason} if self._incomplete else {}),
            "messages": [m.to_dict() for m in self._messages],
        }


def parse_wire(data: dict | None) -> dict:
    """Обратное чтение wire-формата (для Reporter). Unknown/старый формат → None —
    вызывающий код обязан показать фрагменты, а не выдумывать диалог."""
    if not isinstance(data, dict) or "messages" not in data:
        return {"schema_version": None, "complete": False, "messages": []}
    return {
        "schema_version": data.get("schema_version"),
        "complete": bool(data.get("complete")),
        "incomplete_reason": data.get("incomplete_reason", ""),
        "messages": list(data.get("messages", [])),
    }
