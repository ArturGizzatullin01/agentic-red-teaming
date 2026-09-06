"""src/memnotsafe/generation/budget.py — счётчик вызовов атакующей LLM.

Бюджет — ограничитель стоимости прогона (Performance Goals плана): не latency,
а число обращений к атакующей модели. Исчерпание бюджета — ШТАТНЫЙ стоп, а не
ошибка: эскалация корректно прекращается, уже полученные результаты сохраняются
(FR-010), инструмент возвращает `exit 0` и фиксирует факт в провенансе (FR-014).
Именно поэтому исчерпание бюджета — не `AttackerError`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CallBudget:
    """Жёсткий лимит вызовов атакующей LLM на операцию (генерацию корпуса или
    эскалацию одной атаки). `spend()` вызывается ПЕРЕД обращением к модели;
    вызывающий сначала проверяет `exhausted`."""

    limit: int
    used: int = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def spend(self) -> None:
        """Учитывает один вызов атакующей LLM. Не бросает при переполнении —
        стоп по бюджету реализует вызывающий, проверяя `exhausted`."""
        self.used += 1
