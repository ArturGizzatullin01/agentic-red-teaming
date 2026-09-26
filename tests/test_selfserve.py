"""tests/test_selfserve.py — CARD-P18: мастер `memnotsafe go` (selfserve.py).

Всё офлайн/mock — ни одного живого обращения. Замки:
- `.env` подхватывается ТОЛЬКО в `go`, окружение сильнее файла, наружу — лишь имена;
- штатный `run` `.env` не читает (регресс);
- каталог строится из метаданных (имена из реестра/title, контроли помечены);
- аддитивный `title:` в схеме сценария (старые YAML — как раньше);
- строка на попытку с таймерами P12 из attempts.jsonl;
- красный preflight = [БЛОКЕР] + check_id, не traceback, прогон не стартует;
- платный `--ping` — отдельный шаг, в бесплатный preflight не входит;
- ASCII-имена автоген run-каталогов; путь с пробелами из --output работает;
- сквозной `go --yes` на mock даёт report.html + threat-report.html.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

from rich.console import Console

from memnotsafe import selfserve
from memnotsafe.cli import build_parser, cmd_run, load_campaign, main
from memnotsafe.core.config import load_scenario
from memnotsafe.preflight import BLOCKER, Check, PreflightResult

REPO = Path(__file__).resolve().parents[1]
SCENARIO = REPO / "scenarios" / "cross_user_bac.yaml"


def _console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, force_terminal=False, no_color=True, width=200), buf


# --------------------------------------------------------------------- .env
def test_load_dotenv_parses_and_env_wins(tmp_path):
    env = {"EXISTING": "keepme"}
    (tmp_path / ".env").write_text(
        "# comment\n\nexport FOO=bar\nBAZ='quoted val'\nEXISTING=overwrite_me\nBAD KEY=1\nNOEQ\n",
        encoding="utf-8",
    )
    applied = selfserve.load_dotenv(tmp_path / ".env", env)
    assert set(applied) == {"FOO", "BAZ"}
    assert env["FOO"] == "bar"
    assert env["BAZ"] == "quoted val"
    assert env["EXISTING"] == "keepme"  # окружение сильнее файла
    assert "BAD KEY" not in env and "NOEQ" not in env


def test_load_dotenv_missing_file_returns_empty(tmp_path):
    assert selfserve.load_dotenv(tmp_path / "nope.env", {}) == []


def test_run_command_does_not_read_dotenv(tmp_path, monkeypatch):
    """Регресс: штатный `run` (не `go`) `.env` не открывает."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("MEMNOTSAFE_P18_LEAK=do_not_load\n", encoding="utf-8")
    monkeypatch.delenv("MEMNOTSAFE_P18_LEAK", raising=False)
    rc = main(["run", "--scenario", str(SCENARIO), "--output", str(tmp_path / "out"), "--quiet"])
    assert rc == 0
    assert "MEMNOTSAFE_P18_LEAK" not in os.environ


def test_go_reads_dotenv_names_only(tmp_path, monkeypatch):
    """`go` подхватывает .env; печатает ИМЯ, но не ЗНАЧЕНИЕ."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('MEMNOTSAFE_P18_GOENV="secretvalue"\n', encoding="utf-8")
    monkeypatch.delenv("MEMNOTSAFE_P18_GOENV", raising=False)
    fake = PreflightResult(scenario_id="x", scenario_path="x")
    fake.checks.append(Check("B2", "t", BLOCKER, "t"))  # остановит до прогона
    monkeypatch.setattr(selfserve, "run_preflight", lambda p, **kw: fake)
    args = build_parser().parse_args(
        ["go", "--yes", "--scenario", str(SCENARIO), "--output", str(tmp_path / "o"), "--no-color"]
    )
    console, buf = _console()
    selfserve.run_go(args, run_command=lambda ns: 0, load_campaign=load_campaign, console=console)
    text = buf.getvalue()
    assert "MEMNOTSAFE_P18_GOENV" in text
    assert "secretvalue" not in text
    assert os.environ.get("MEMNOTSAFE_P18_GOENV") == "secretvalue"


# ------------------------------------------------------------- title / каталог
def test_title_schema_additive(tmp_path):
    sc0 = load_scenario(SCENARIO)
    assert sc0.title is None  # старый YAML без ключа — None
    base = SCENARIO.read_text(encoding="utf-8")
    titled = tmp_path / "titled.yaml"
    titled.write_text('title: "Мой сценарий"\n' + base, encoding="utf-8")
    assert load_scenario(titled).title == "Мой сценарий"


def test_human_name_prefers_title_then_registry():
    reg = selfserve._ensure_registry()
    sc = load_scenario(SCENARIO)
    assert selfserve.human_name(sc, reg) == "Cross-user broken access control via memory poisoning"
    sc.title = "Custom name"
    assert selfserve.human_name(sc, reg) == "Custom name"


def test_build_catalog_groups_by_adapter_and_flags_controls():
    catalog = selfserve.build_catalog(REPO / "scenarios")
    groups = selfserve.group_by_adapter(catalog)
    assert "mock" in groups and "investment_stand" in groups
    by_id = {e.scenario_id: e for e in catalog}
    base = by_id["cross_user_bac"]
    assert base.name == "Cross-user broken access control via memory poisoning"
    assert base.is_control is False
    assert base.goal and "customer id" in base.goal
    prot = by_id["cross_user_bac_protected"]
    assert prot.is_control is True
    assert prot.name == base.name  # имя из реестра, не из тела сценария


# ------------------------------------------------------------- attempts / P12
def test_attempt_lines_formats_p12_timers(tmp_path):
    rec = {
        "case_id": "c1", "candidate_id": "cand123456789", "attempt_no": 1, "outcome": "delivered",
        "timing": {"t_reset": 0.01, "t_delivery": 0.2, "t_settle": None,
                   "t_trigger": 0.05, "t_finalize": None, "t_scoring": 0.001},
    }
    (tmp_path / "attempts.jsonl").write_text(json.dumps(rec) + "\nnot-json-line\n", encoding="utf-8")
    lines = selfserve.attempt_lines(tmp_path)
    assert len(lines) == 1  # битая строка пропущена
    line = lines[0]
    assert "delivered" in line and "c1" in line and "#1" in line
    assert "Σ=" in line
    assert "-" in line  # невыполненная фаза = "-"


def test_attempt_lines_missing_file_empty(tmp_path):
    assert selfserve.attempt_lines(tmp_path) == []


# ------------------------------------------------------------- вывод / пути
def test_resolve_run_output_ascii_and_passthrough(tmp_path):
    auto = selfserve._resolve_run_output(None, "кросс_bac")  # кириллический id
    assert str(auto).startswith(str(Path("runs") / "go-"))
    assert auto.name.isascii()
    spaced = tmp_path / "пробел каталог"
    assert selfserve._resolve_run_output(str(spaced), "x") == Path(str(spaced))


# ------------------------------------------------------------- сквозной go
def test_go_yes_end_to_end_on_mock(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # без .env в cwd
    out = tmp_path / "run out"  # пробел в пути
    args = build_parser().parse_args(
        ["go", "--yes", "--scenario", str(SCENARIO), "--output", str(out), "--no-color"]
    )
    console, buf = _console()
    rc = selfserve.run_go(args, run_command=cmd_run, load_campaign=load_campaign, console=console)
    text = buf.getvalue()
    assert rc == 0
    for marker in ("ДО ПРОГОНА", "PREFLIGHT", "ПОПЫТКИ", "ПОСЛЕ ПРОГОНА"):
        assert marker in text
    assert "Σ=" in text  # строка попытки с таймерами P12
    assert (out / "attempts.jsonl").exists()
    assert (out / "report" / "report.html").exists()
    assert (out / "threat-report.html").exists()


def test_go_yes_requires_scenario(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = build_parser().parse_args(["go", "--yes"])
    console, _ = _console()
    calls: list = []
    rc = selfserve.run_go(
        args, run_command=lambda ns: calls.append(ns) or 0, load_campaign=load_campaign, console=console
    )
    assert rc == 2
    assert calls == []  # прогон не стартовал


def test_go_ping_is_separate_paid_step_skipped_without_judge(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = build_parser().parse_args(
        ["go", "--yes", "--ping", "--scenario", str(SCENARIO), "--output", str(tmp_path / "o"), "--no-color"]
    )
    console, buf = _console()
    calls: list = []
    rc = selfserve.run_go(
        args, run_command=lambda ns: calls.append(ns) or 0, load_campaign=load_campaign, console=console
    )
    text = buf.getvalue()
    assert "--ping" in text  # отдельный платный шаг, не часть preflight
    assert "судья не сконфигурирован" in text  # платный вызов не сделан
    assert len(calls) == 1  # прогон всё равно идёт после пропущенного ping
    assert rc == 0


def test_go_preflight_blocker_stops_before_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake = PreflightResult(scenario_id="x", scenario_path="x")
    fake.checks.append(Check("B2", "две личности — один ключ", BLOCKER, "attacker и victim делят ключ"))
    monkeypatch.setattr(selfserve, "run_preflight", lambda p, **kw: fake)
    args = build_parser().parse_args(
        ["go", "--yes", "--scenario", str(SCENARIO), "--output", str(tmp_path / "out"), "--no-color"]
    )
    console, buf = _console()
    calls: list = []
    rc = selfserve.run_go(
        args, run_command=lambda ns: calls.append(ns) or 0, load_campaign=load_campaign, console=console
    )
    text = buf.getvalue()
    assert rc == 1
    assert "[БЛОКЕР] B2" in text
    assert "Traceback" not in text
    assert calls == []  # прогон не стартовал
