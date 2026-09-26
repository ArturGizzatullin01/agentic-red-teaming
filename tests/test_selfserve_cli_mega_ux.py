"""tests/test_selfserve_cli_mega_ux.py — CARD-CLI-MEGA-UX §2–§5 (мастер `go`).

Всё офлайн/mock — ни одного живого обращения (живой прогон делает A0). Замки:
§2  цель КРУПНО первой строкой (mock=smoke / живой стенд <url>);
    непропускаемое подтверждение живого (--yes требует --live-ack);
    блокер отсутствующих ИМЁН ключей перед живым (не traceback);
    явный выбор судьи с дефолтом по типу цели;
§3  пресеты атакующего → верные существующие флаги; каталог по family + описание;
§4  --until-proven зовёт штатный campaign со stop_on_success и iterations (инъекция,
    без реального прогона); честный итог NOT_PROVEN;
§5  карточка «после» печатает путь открытия прогона в консоли.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console

from memnotsafe import selfserve
from memnotsafe.cli import build_parser, load_campaign
from memnotsafe.core.config import load_scenario
from memnotsafe.preflight import BLOCKER, Check, PreflightResult

REPO = Path(__file__).resolve().parents[1]
MOCK_SCENARIO = REPO / "scenarios" / "cross_user_bac.yaml"
LIVE_SCENARIO = REPO / "scenarios" / "cross-topic-smuggle-pilot.yaml"  # investment_stand :9702, SK_GENAI_1003


def _console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, force_terminal=False, no_color=True, width=200), buf


def _go_args(*extra: str):
    return build_parser().parse_args(["go", *extra])


def _clean_preflight(monkeypatch):
    monkeypatch.setattr(selfserve, "run_preflight",
                        lambda p: PreflightResult(scenario_id="x", scenario_path=str(p)))


# ------------------------------------------------------------------ §2 цель крупно
def test_goal_line_mock_is_smoke():
    sc = load_scenario(MOCK_SCENARIO)
    assert selfserve.is_live_target(sc) is False
    assert selfserve.target_goal_line(sc) == "MOCK (smoke)"


def test_goal_line_live_shows_url():
    sc = load_scenario(LIVE_SCENARIO)
    assert selfserve.is_live_target(sc) is True
    assert selfserve.target_goal_line(sc) == "ЖИВОЙ СТЕНД http://localhost:9702"


def test_target_override_mock_forces_smoke():
    sc = load_scenario(LIVE_SCENARIO)
    assert selfserve.is_live_target(sc, target_override="mock") is False
    assert selfserve.target_goal_line(sc, target_override="mock") == "MOCK (smoke)"


def test_before_card_goal_first_line():
    sc = load_scenario(LIVE_SCENARIO)
    card = selfserve.before_card(sc, repetitions=5)
    assert card["is_live"] is True
    assert card["goal"] == "ЖИВОЙ СТЕНД http://localhost:9702"


# ------------------------------------------------------- §2 подтверждение живого
def test_live_yes_without_ack_blocks(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SK_GENAI_1003", "present")  # ключи на месте — доходим до ack-гейта
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--no-judge", "--scenario", str(LIVE_SCENARIO),
                    "--output", str(tmp_path / "o"), "--no-color")
    console, buf = _console()
    calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: calls.append(ns) or 0,
                          campaign_command=lambda ns: calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 2
    assert calls == []  # прогон не стартовал
    assert "--live-ack" in buf.getvalue() and "Traceback" not in buf.getvalue()


def test_live_yes_with_ack_proceeds(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SK_GENAI_1003", "present")
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--no-judge", "--live-ack", "--scenario", str(LIVE_SCENARIO),
                    "--output", str(tmp_path / "o"), "--no-color")
    console, _ = _console()
    calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 0
    assert len(calls) == 1  # прогон пошёл после подтверждения


# ------------------------------------------------------- §2 блокер имён ключей
def test_missing_key_names_function():
    sc = load_scenario(LIVE_SCENARIO)
    args = _go_args("--no-judge")
    assert "SK_GENAI_1003" in selfserve.missing_key_names(sc, args, {})
    assert selfserve.missing_key_names(sc, args, {"SK_GENAI_1003": "x"}) == []


def test_live_missing_keys_blocks_without_traceback(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SK_GENAI_1003", raising=False)
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--no-judge", "--live-ack", "--scenario", str(LIVE_SCENARIO),
                    "--output", str(tmp_path / "o"), "--no-color")
    console, buf = _console()
    calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 1
    assert calls == []
    text = buf.getvalue()
    assert "[БЛОКЕР]" in text and "SK_GENAI_1003" in text and "Traceback" not in text


def test_mock_needs_no_keys_and_no_ack(monkeypatch, tmp_path):
    """Регресс: mock (smoke) не требует ни ключей, ни live-ack — сквозной go идёт."""
    monkeypatch.chdir(tmp_path)
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--scenario", str(MOCK_SCENARIO), "--output", str(tmp_path / "o"), "--no-color")
    console, _ = _console()
    calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 0 and len(calls) == 1


# ------------------------------------------------------------ §2 выбор судьи
def test_judge_default_on_for_live_off_for_mock():
    args = _go_args("--yes")
    selfserve._choose_judge(_console()[0], args, is_live=True, yes=True)
    assert args.judge is True
    args2 = _go_args("--yes")
    selfserve._choose_judge(_console()[0], args2, is_live=False, yes=True)
    assert args2.judge is False


def test_judge_explicit_flags_respected():
    args = _go_args("--yes", "--no-judge")
    selfserve._choose_judge(_console()[0], args, is_live=True, yes=True)
    assert args.judge is False  # --no-judge не переспрашивается и не включается
    assert selfserve.effective_judge_enabled(load_scenario(LIVE_SCENARIO), args) is False


# ------------------------------------------------------------ §3 пресеты атакующего
def test_attacker_presets_map_to_flags():
    for key in ("qwen", "yandexgpt", "deepseek"):
        args = _go_args("--yes")
        preset = selfserve.apply_attacker_preset(args, key)
        assert args.attacker_provider == "openai"
        assert args.attacker_model == preset.model and args.attacker_model.startswith("gpt://")
        assert args.attacker_base_url == "https://llm.api.cloud.yandex.net/v1"
        assert args.attacker_api_key_env == "ATTACKER_API_KEY"
    stub_args = _go_args("--yes")
    selfserve.apply_attacker_preset(stub_args, "stub")
    assert stub_args.attacker_provider == "stub"


def test_attacker_preset_manual_leaves_flags():
    args = _go_args("--yes", "--attacker-model", "my-model", "--attacker-base-url", "http://x/v1")
    selfserve.apply_attacker_preset(args, "manual")
    assert args.attacker_model == "my-model" and args.attacker_base_url == "http://x/v1"


def test_attacker_preset_unknown_raises_keyerror():
    with pytest.raises(KeyError):
        selfserve.apply_attacker_preset(_go_args("--yes"), "bogus")


def test_go_unknown_attacker_preset_returns_2(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    args = _go_args("--yes", "--scenario", str(MOCK_SCENARIO), "--attacker-preset", "bogus",
                    "--output", str(tmp_path / "o"), "--no-color")
    console, buf = _console()
    calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 2 and calls == []
    assert "bogus" in buf.getvalue()


# ------------------------------------------------------------ §3 каталог по family
def test_catalog_carries_description_and_groups_by_family():
    catalog = selfserve.build_catalog(REPO / "scenarios")
    by_id = {e.scenario_id: e for e in catalog}
    base = by_id["cross_user_bac"]
    assert base.description  # однострочное описание из metadata атаки
    families = selfserve.group_by_family(catalog)
    assert "cross_user_bac" in families
    assert all(e.family == "cross_user_bac" for e in families["cross_user_bac"])


def test_filter_by_adapter():
    catalog = selfserve.build_catalog(REPO / "scenarios")
    only_mock = selfserve.filter_by_adapter(catalog, "mock")
    assert only_mock and all(e.adapter == "mock" for e in only_mock)
    only_stand = selfserve.filter_by_adapter(catalog, "investment_stand")
    assert only_stand and all(e.adapter == "investment_stand" for e in only_stand)
    assert selfserve.filter_by_adapter(catalog, None) == catalog


# ------------------------------------------------------------ §4 кнопка «до проникновения»
def test_until_proven_routes_to_campaign_with_flags(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--until-proven", "--scenario", str(MOCK_SCENARIO),
                    "--output", str(tmp_path / "o"), "--no-color")
    console, buf = _console()
    run_calls: list = []
    camp_calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: run_calls.append(ns) or 0,
                          campaign_command=lambda ns: camp_calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 0
    assert len(camp_calls) == 1 and run_calls == []  # пошёл штатный campaign, не run
    ns = camp_calls[0]
    assert ns.stop_on_success is True
    assert ns.iterations == selfserve.UNTIL_PROVEN_REPETITIONS == 5
    assert f"попыток:    {selfserve.UNTIL_PROVEN_REPETITIONS}" in buf.getvalue()


def test_without_until_proven_routes_to_run(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--scenario", str(MOCK_SCENARIO),
                    "--output", str(tmp_path / "o"), "--no-color")
    console, _ = _console()
    run_calls: list = []
    camp_calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: run_calls.append(ns) or 0,
                          campaign_command=lambda ns: camp_calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 0 and len(run_calls) == 1 and camp_calls == []


class _FakeCampaign:
    def __init__(self, successes: list[bool]):
        self.attempts = len(successes)
        self.results = [type("R", (), {"success": s})() for s in successes]


def test_until_proven_summary_proven(tmp_path):
    (tmp_path / "campaign.json").write_text("{}", encoding="utf-8")
    console, buf = _console()
    selfserve._render_until_proven_summary(console, tmp_path, lambda d: _FakeCampaign([False, True]), 5)
    assert "SUCCESS на 2 из 5" in buf.getvalue()


def test_until_proven_summary_not_proven(tmp_path):
    (tmp_path / "campaign.json").write_text("{}", encoding="utf-8")
    console, buf = _console()
    selfserve._render_until_proven_summary(console, tmp_path, lambda d: _FakeCampaign([False, False]), 5)
    assert "NOT_PROVEN" in buf.getvalue()


# ------------------------------------------------------------ §5 путь в консоль
def test_console_open_hint_has_command_and_run_dir():
    hint = "\n".join(selfserve.console_open_hint(Path("runs") / "go-x"))
    assert "cd console && npm run dev" in hint
    assert str(Path("runs") / "go-x") in hint


def test_after_card_prints_console_path(tmp_path):
    console, buf = _console()
    selfserve._render_after_card(console, 0, "NOT PROVEN", tmp_path / "report" / "report.html",
                                 None, run_dir=tmp_path / "run")
    text = buf.getvalue()
    assert "cd console" in text and str(tmp_path / "run") in text
