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
                        lambda p, **kw: PreflightResult(scenario_id="x", scenario_path=str(p)))


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


# ------------------------------------------------------------ D1: пресет судьи мастера
# Дефект D1 (VERDICT-CLI-MEGA-UX): мастер, включая судью на сценарии БЕЗ блока
# judge:, оставлял дефолты JudgeSpec (OpenRouter/пустая модель) — блокер требовал
# OPENROUTER_API_KEY, а с ключом прогон падал на validate_judge_spec. Мастер должен
# заполнять рабочий пресет проекта (Yandex/PROVIDER_API_KEY); свой блок judge: — не трогать.
OWN_JUDGE_SCENARIO = REPO / "scenarios" / "direct_poisoning_live_judged.yaml"  # свой блок judge:
YANDEX_JUDGE_URI = "gpt://b1g0nvl5lgk8he84ckp8/deepseek-v4-flash/latest"        # буква l (A0 1d6e9aa)
YANDEX_BASE_URL = "https://llm.api.cloud.yandex.net/v1"


def test_judge_preset_fills_yandex_when_no_block():
    """Мастер включил судью, у сценария нет блока judge: → рабочий пресет (Yandex/
    PROVIDER_API_KEY) и в загруженный сценарий, и в args (команда перезагружает сценарий)."""
    sc = load_scenario(LIVE_SCENARIO)
    assert not sc.judge.model  # блока judge: нет — дефолт JudgeSpec (пустая модель)
    args = _go_args("--yes")
    args.judge = True
    selfserve._apply_default_judge_preset(sc, args)
    assert sc.judge.model == YANDEX_JUDGE_URI
    assert sc.judge.base_url == YANDEX_BASE_URL
    assert sc.judge.api_key_env == "PROVIDER_API_KEY"
    assert args.judge_model == YANDEX_JUDGE_URI
    assert args.judge_base_url == YANDEX_BASE_URL
    assert args.judge_api_key_env == "PROVIDER_API_KEY"


def test_judge_preset_leaves_own_judge_block():
    """Сценарий со своим блоком judge: не трогаем — ни модель, ни ключ, ни args."""
    sc = load_scenario(OWN_JUDGE_SCENARIO)
    assert sc.judge.model == "openai/gpt-4o-mini"  # собственный выбор сценария
    args = _go_args("--yes")
    args.judge = True
    selfserve._apply_default_judge_preset(sc, args)
    assert sc.judge.model == "openai/gpt-4o-mini"
    assert sc.judge.api_key_env == "OPENROUTER_API_KEY"
    assert getattr(args, "judge_model", None) is None


def test_judge_preset_respects_explicit_judge_model():
    """Оператор назвал --judge-model → пресет не перебивает его явный выбор."""
    sc = load_scenario(LIVE_SCENARIO)
    args = _go_args("--yes", "--judge-model", "gpt://custom/model/latest")
    args.judge = True
    selfserve._apply_default_judge_preset(sc, args)
    assert args.judge_model == "gpt://custom/model/latest"
    assert not sc.judge.model  # пресет не тронул сценарий


def test_go_live_default_judge_demands_provider_not_openrouter(monkeypatch, tmp_path):
    """ЗАМОК D1: go --yes по ЖИВОМУ (без --no-judge) с ключами стенда и PROVIDER_API_KEY,
    но БЕЗ OPENROUTER_API_KEY, проходит блокер ключей и доходит до live-ack — судья Yandex."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SK_GENAI_1003", "present")
    monkeypatch.setenv("PROVIDER_API_KEY", "present")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--scenario", str(LIVE_SCENARIO),
                    "--output", str(tmp_path / "o"), "--no-color")
    console, buf = _console()
    calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: calls.append(ns) or 0,
                          campaign_command=lambda ns: calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    text = buf.getvalue()
    assert rc == 2 and calls == []           # дошли до ack-гейта (--yes без --live-ack)
    assert "--live-ack" in text              # это ack-гейт, а не блокер ключей
    assert "OPENROUTER_API_KEY" not in text  # судья не OpenRouter
    assert "deepseek-v4-flash" in text       # карточка «до» обещает рабочего судью
    assert "Traceback" not in text


def test_go_live_judge_namespace_carries_yandex(monkeypatch, tmp_path):
    """Штатная команда получает пресет судьи через args (перезагружает сценарий):
    _apply_judge_overrides подхватит model/base_url/api_key_env Yandex."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SK_GENAI_1003", "present")
    monkeypatch.setenv("PROVIDER_API_KEY", "present")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    _clean_preflight(monkeypatch)
    args = _go_args("--yes", "--live-ack", "--scenario", str(LIVE_SCENARIO),
                    "--output", str(tmp_path / "o"), "--no-color")
    console, _ = _console()
    calls: list = []
    rc = selfserve.run_go(args, run_command=lambda ns: calls.append(ns) or 0,
                          load_campaign=load_campaign, console=console)
    assert rc == 0 and len(calls) == 1
    ns = calls[0]
    assert ns.judge is True
    assert ns.judge_model == YANDEX_JUDGE_URI
    assert ns.judge_base_url == YANDEX_BASE_URL
    assert ns.judge_api_key_env == "PROVIDER_API_KEY"


def test_apply_judge_overrides_applies_base_url_and_key_env():
    """cli._apply_judge_overrides применяет judge_base_url/judge_api_key_env из args
    (мастер их проставляет) — иначе URI Yandex ушёл бы на OpenRouter с чужим ключом."""
    from memnotsafe.cli import _apply_judge_overrides
    sc = load_scenario(LIVE_SCENARIO)
    args = _go_args("--yes")
    args.judge = True
    args.judge_model = YANDEX_JUDGE_URI
    args.judge_base_url = YANDEX_BASE_URL
    args.judge_api_key_env = "PROVIDER_API_KEY"
    _apply_judge_overrides(sc, args)
    assert sc.judge.enabled is True
    assert sc.judge.model == YANDEX_JUDGE_URI
    assert sc.judge.base_url == YANDEX_BASE_URL
    assert sc.judge.api_key_env == "PROVIDER_API_KEY"
