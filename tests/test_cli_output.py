"""tests/test_cli_output.py — output-слой CLI (фича 006): ConsoleReporter.

Контракт репортера:
- потоки ИНЪЕЦИРУЮТСЯ (OutputOptions.stdout/stderr), глобальный print не используется;
- режимы: human (таблица в stdout) | --json (один JSON-объект в stdout) |
  --quiet (пусто); --json сильнее --quiet;
- ошибки: human → «[FATAL] …» в stderr; --json → один JSON-объект в stderr,
  stdout пуст;
- Rich/цвет — только на TTY (C3): non-TTY/`--no-color`/`NO_COLOR` → чистый ASCII.

До C2 файл RED целиком: memnotsafe.reporting.console ещё не существует.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from memnotsafe.reporting.console import SCHEMA_VERSION, ConsoleReporter, OutputOptions


def _opts(**kw) -> tuple[OutputOptions, io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    kw.setdefault("stdout", out)
    kw.setdefault("stderr", err)
    return OutputOptions(**kw), out, err


def _render(rep: ConsoleReporter) -> None:
    rep.heading("AGENTIC MEMORY RED TEAMING")
    rep.line("Scenario: demo")
    rep.line("END-TO-END ASR: 67%")


def test_human_render_goes_to_injected_stdout_only() -> None:
    opts, out, err = _opts()
    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0,
        data={"attempts": 1}, artifacts=["report.html"], render=_render,
    )
    text = out.getvalue()
    assert "AGENTIC MEMORY RED TEAMING" in text
    assert "END-TO-END ASR: 67%" in text
    assert err.getvalue() == ""


def test_quiet_suppresses_human_output_completely() -> None:
    opts, out, err = _opts(quiet=True)

    def render(rep: ConsoleReporter) -> None:
        raise AssertionError("render не должен вызываться в quiet-режиме")

    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=render,
    )
    assert out.getvalue() == ""
    assert err.getvalue() == ""


def test_json_wins_over_quiet_one_object() -> None:
    opts, out, err = _opts(json=True, quiet=True)
    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0,
        data={"attempts": 1}, artifacts=["report.html"], render=_render,
    )
    payload = json.loads(out.getvalue())  # ровно один объект — целиком парсится
    assert set(payload) == {"schema_version", "command", "outcome", "exit_code", "data", "artifacts"}
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["command"] == "report"
    assert payload["outcome"] == "success"
    assert payload["exit_code"] == 0
    assert payload["data"] == {"attempts": 1}
    assert payload["artifacts"] == ["report.html"]
    assert err.getvalue() == ""


def test_emit_error_human_keeps_fatal_marker_on_stderr() -> None:
    opts, out, err = _opts()
    ConsoleReporter(opts).emit_error(command="run", message="сценарий не найден")
    assert out.getvalue() == ""
    assert "[FATAL]" in err.getvalue()
    assert "сценарий не найден" in err.getvalue()


def test_emit_error_json_goes_to_stderr_stdout_stays_empty() -> None:
    opts, out, err = _opts(json=True)
    ConsoleReporter(opts).emit_error(command="run", message="boom")
    assert out.getvalue() == ""
    payload = json.loads(err.getvalue())  # один JSON-объект об ошибке в stderr
    assert payload["outcome"] == "error"
    assert payload["exit_code"] == 1
    assert "boom" in json.dumps(payload["data"], ensure_ascii=False)


def test_streams_default_to_sys_stdout_and_stderr(monkeypatch) -> None:
    fake_out, fake_err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", fake_out)
    monkeypatch.setattr(sys, "stderr", fake_err)
    ConsoleReporter(OutputOptions()).emit_result(
        command="probe", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    assert "AGENTIC MEMORY RED TEAMING" in fake_out.getvalue()
