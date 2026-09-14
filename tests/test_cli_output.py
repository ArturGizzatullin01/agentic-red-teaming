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


# ----------------------------------------------------------------- C3: цвет/TTY


class _FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def _tty_opts(**kw) -> tuple[OutputOptions, _FakeTTY, io.StringIO]:
    """Репортер с фейковым TTY в stdout; тест читает ИМЕННО инъекцированный
    поток (второй элемент), а не посторонний StringIO."""
    err = io.StringIO()
    tty = _FakeTTY()
    kw.setdefault("stderr", err)
    kw.setdefault("stdout", tty)
    return OutputOptions(**kw), tty, err


def _forget_rich(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    # TERM окружения влияет на rich даже при force_terminal: в CI/дамповом
    # терминале (TERM=dumb) rich корректно не выдаёт ANSI. Production-контракт
    # («цвет только на рендерящем TTY») соблюдён — тест задаёт цветной TERM
    # сам, а не зависит от машины (фикс воспроизводимости приёмки).
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delitem(sys.modules, "rich", raising=False)
    monkeypatch.delitem(sys.modules, "rich.console", raising=False)


def test_non_tty_stays_plain_and_does_not_import_rich(monkeypatch) -> None:
    _forget_rich(monkeypatch)
    opts, out, err = _opts()  # io.StringIO → isatty() False
    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    assert "\x1b[" not in out.getvalue()
    assert "rich" not in sys.modules  # ленивый импорт: non-TTY rich вообще не трогает


def test_no_color_flag_forces_plain_even_on_tty(monkeypatch) -> None:
    _forget_rich(monkeypatch)
    opts, tty, err = _tty_opts(no_color=True)
    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    assert "AGENTIC MEMORY RED TEAMING" in tty.getvalue()  # вывод состоялся
    assert "\x1b[" not in tty.getvalue()
    assert "rich" not in sys.modules


def test_no_color_env_forces_plain_even_on_tty(monkeypatch) -> None:
    _forget_rich(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "1")
    opts, tty, err = _tty_opts()
    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    assert "AGENTIC MEMORY RED TEAMING" in tty.getvalue()
    assert "\x1b[" not in tty.getvalue()
    assert "rich" not in sys.modules


def test_json_and_quiet_paths_do_not_import_rich(monkeypatch) -> None:
    _forget_rich(monkeypatch)
    ConsoleReporter(_tty_opts(json=True)[0]).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    ConsoleReporter(_tty_opts(quiet=True)[0]).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    assert "rich" not in sys.modules


def test_tty_gets_ansi_and_lazy_import_happens_only_there(monkeypatch) -> None:
    _forget_rich(monkeypatch)
    opts, tty, err = _tty_opts()
    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    assert "\x1b[" in tty.getvalue()  # заголовок отрисован rich с цветом
    assert "rich" in sys.modules  # импорт случился только в TTY-ветке


def test_narrow_width_is_safe(monkeypatch) -> None:
    _forget_rich(monkeypatch)
    monkeypatch.setenv("COLUMNS", "20")
    opts, tty, err = _tty_opts()
    ConsoleReporter(opts).emit_result(
        command="report", outcome="success", exit_code=0, data={}, artifacts=[], render=_render,
    )
    assert "AGENTIC MEMORY RED TEAMING" in tty.getvalue()  # не падает даже на 20 колонках


# ------------------------------------------------------------ C4: флаги CLI

_COMMANDS = ["probe", "run", "campaign", "generate", "report", "judge-calibrate", "replay"]

# минимально валидный argv на подкоманду (required-аргументы покрыть до флагов)
_MINIMAL_ARGV = {
    "probe": ["probe"],
    "run": ["run", "--scenario", "s.yaml", "--output", "out"],
    "campaign": ["campaign", "--scenario", "s.yaml", "--output", "out"],
    "generate": ["generate", "--profile", "p.yaml", "--out", "corpus.yaml"],
    "report": ["report", "--input", "in", "--output", "out"],
    "judge-calibrate": ["judge-calibrate"],
    "replay": ["replay", "--input", "in", "--case", "CASE-1"],
}


@pytest.mark.parametrize("command", _COMMANDS)
def test_output_flags_default_to_false(command) -> None:
    from memnotsafe.cli import build_parser

    args = build_parser().parse_args(_MINIMAL_ARGV[command])
    assert args.json is False
    assert args.quiet is False
    assert args.no_color is False


@pytest.mark.parametrize("command", _COMMANDS)
def test_output_flags_parse_on_every_subcommand(command) -> None:
    from memnotsafe.cli import build_parser

    args = build_parser().parse_args(_MINIMAL_ARGV[command] + ["--json", "--quiet", "--no-color"])
    assert args.json is True
    assert args.quiet is True
    assert args.no_color is True
