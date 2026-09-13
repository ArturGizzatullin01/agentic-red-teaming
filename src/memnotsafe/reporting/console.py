"""src/memnotsafe/reporting/console.py — единый output-слой CLI (фича 006).

Весь человекочитаемый и машинный вывод команд memnotsafe идёт через
ConsoleReporter; cmd_* в cli.py только готовят данные и render-колбэк.

Принципы:
- потоки ИНЪЕКТИРУЮТСЯ (OutputOptions.stdout/stderr); глобальный print для
  результата команды не используется;
- режимы: human (таблица в stdout) | --json (ровно один JSON-объект в stdout)
  | --quiet (пусто); --json сильнее --quiet;
- ошибки: human → «[FATAL] …» в stderr (формат заффиксен регрессом
  test_config_error_is_exit_1_before_touching_the_target); --json → один
  JSON-объект в stderr, stdout остаётся пустым;
- UNKNOWN/INCONCLUSIVE — состояние находки/стадии: в JSON это null, статусная
  строка — глиф UNKNOWN; никакой отдельный exit-код для него не вводится;
- цвет (C3) включается ТОЛЬКО на TTY; без него вывод — чистый ASCII.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import IO, Any, Callable

SCHEMA_VERSION = 1

# Глифы статусов: только ASCII, безопасны на любой ширине терминала.
GLYPHS: dict[str, str] = {
    "pass": "PASS",
    "fail": "FAIL",
    "unknown": "UNKNOWN",
    "error": "ERROR",
}

_JSON_KEYS = ("schema_version", "command", "outcome", "exit_code", "data", "artifacts")

Render = Callable[["ConsoleReporter"], None]


@dataclass
class OutputOptions:
    """Куда и как писать вывод. stdout/stderr None → системные потоки
    (разрешаются при использовании, а не при создании — чтобы capsys и
    подмена sys.stdout в тестах работали)."""

    json: bool = False
    quiet: bool = False
    no_color: bool = False
    stdout: IO[str] | None = None
    stderr: IO[str] | None = None


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


class ConsoleReporter:
    """Печатает результат команды в режимах human/json/quiet. Примитивы
    line/heading/rule/kv/status_line/glyph — язык render-колбэков; вызывать их
    можно только внутри render (human-режим), reporter сам решает, рисовать ли."""

    def __init__(self, options: OutputOptions) -> None:
        self.options = options

    # ------------------------------------------------------------------ потоки
    @property
    def out(self) -> IO[str]:
        return self.options.stdout if self.options.stdout is not None else sys.stdout

    @property
    def err(self) -> IO[str]:
        return self.options.stderr if self.options.stderr is not None else sys.stderr

    # ------------------------------------------------------- результат команды
    def emit_result(
        self,
        *,
        command: str,
        outcome: str,
        exit_code: int,
        data: dict[str, Any],
        artifacts: list[str],
        render: Render,
    ) -> None:
        if self.options.json:
            payload = {
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "outcome": outcome,
                "exit_code": exit_code,
                "data": _jsonable(data),
                "artifacts": [str(a) for a in artifacts],
            }
            print(json.dumps(payload, ensure_ascii=False), file=self.out)
            return
        if self.options.quiet:
            return
        render(self)

    def emit_error(self, *, command: str, message: str, data: dict[str, Any] | None = None) -> None:
        if self.options.json:
            payload = {
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "outcome": "error",
                "exit_code": 1,
                "data": {"message": str(message), **_jsonable(data or {})},
                "artifacts": [],
            }
            print(json.dumps(payload, ensure_ascii=False), file=self.err)
            return
        print(f"[FATAL] {message}", file=self.err)

    def warn(self, message: str) -> None:
        """Предупреждение конфигурации — всегда stderr, в обоих режимах:
        диагностика не входит в JSON-контракт результата (stdout остаётся
        «один объект» и в human, и в json)."""
        print(f"[WARN] {message}", file=self.err)

    # -------------------------------------------- примитивы human-рендера
    def line(self, text: str = "", role: str = "text") -> None:
        print(text, file=self.out)

    def heading(self, text: str) -> None:
        self.rule()
        self.line(text)
        self.rule()

    def rule(self) -> None:
        print("=" * 50, file=self.out)

    def kv(self, key: str, value: str) -> None:
        self.line(f"{key:<14} {value}")

    def glyph(self, role: str) -> str:
        return GLYPHS.get(role, role.upper())

    def status_line(self, label: str, ok: int, total: int, unknown: int = 0) -> None:
        """Строка стадии воронки — формат прежний (документирован), роль
        подсказывает цвет в C3: все pass → PASS, все fail → FAIL, иначе нейтрально."""
        role = "text"
        if total and ok == total:
            role = "pass"
        elif total and ok == 0 and unknown == 0:
            role = "fail"
        self.line(f"{label.upper():<14} {ok}/{total} pass ({unknown} unknown)", role)
