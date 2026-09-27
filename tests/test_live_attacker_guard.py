"""tests/test_live_attacker_guard.py — CARD-LIVE-COVERAGE Задача 2 («никогда больше»).

Замки против тихого статического атакера:
  - threat_report._attacker_status: online → LLM(model); иначе → СТАТИКА (не LLM);
    нет experiment.json → НЕИЗВЕСТЕН (тоже не «живой»);
  - шапка threat-report несёт строку «АТАКУЮЩИЙ: …»;
  - карточка «до» selfserve: живой стенд без --online → предупреждение СТАТИКА;
    mock (smoke) — без предупреждения; --online → строка LLM;
  - паковый драйвер pilot: без --online и без --allow-static → блокер rc=2.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from rich.console import Console

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from memnotsafe import selfserve  # noqa: E402
from memnotsafe.core.config import load_scenario  # noqa: E402
from memnotsafe.reporting.threat_report import attacker_status, render_html  # noqa: E402

SCENARIOS = SRC.parent / "scenarios"
LIVE = SCENARIOS / "scope_escalation_live.yaml"      # investment_stand (живой)
MOCK = SCENARIOS / "cross_user_bac.yaml"             # mock (smoke)


def _console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, force_terminal=False, no_color=True, width=200), buf


# ------------------------------------------------------------ _attacker_status
def test_attacker_status_static_online_missing(tmp_path: Path) -> None:
    # Английские строки: threat-report — англоязычный отчёт (замок no-cyrillic).
    assert attacker_status(tmp_path) == "UNKNOWN (no experiment.json)"
    (tmp_path / "experiment.json").write_text(
        json.dumps({"attacker": {"online": False, "provider": "stub", "model": "?"}}), encoding="utf-8")
    assert attacker_status(tmp_path) == "STATIC (not an LLM)"
    (tmp_path / "experiment.json").write_text(
        json.dumps({"attacker": {"online": True, "provider": "openai", "model": "gpt://f/qwen/latest"}}),
        encoding="utf-8")
    assert attacker_status(tmp_path) == "LLM (gpt://f/qwen/latest)"


# ------------------------------------------------------------ threat-report шапка
def test_threat_report_header_carries_attacker_line(tmp_path: Path) -> None:
    import test_threat_report as trt  # переиспользуем фикстуру настоящего mock-прогона

    run = trt._mock_run(tmp_path, "vuln")
    report = trt._build(trt._mod(), run)
    html = render_html(report)
    assert "ATTACKER:" in html  # строка статуса атакующего в шапке (Задача 2.2, англ. отчёт)


# ------------------------------------------------------------ карточка «до»
def test_before_card_warns_live_static() -> None:
    sc = load_scenario(str(LIVE))
    console, buf = _console()
    selfserve._render_before_card(console, sc, str(LIVE), repetitions=1, online=False)
    text = buf.getvalue()
    assert "СТАТИКА (не LLM)" in text and "ПРЕДУПРЕЖДЕНИЕ" in text


def test_before_card_live_online_shows_llm() -> None:
    sc = load_scenario(str(LIVE))
    console, buf = _console()
    selfserve._render_before_card(console, sc, str(LIVE), repetitions=1, online=True)
    text = buf.getvalue()
    assert "LLM" in text and "ПРЕДУПРЕЖДЕНИЕ" not in text


def test_before_card_mock_no_warning() -> None:
    sc = load_scenario(str(MOCK))
    console, buf = _console()
    selfserve._render_before_card(console, sc, str(MOCK), repetitions=1, online=False)
    text = buf.getvalue()
    assert "ПРЕДУПРЕЖДЕНИЕ" not in text  # mock smoke — статика штатна


# ------------------------------------------------------------ pilot-гейт
def test_pilot_blocks_static_without_flags(tmp_path: Path) -> None:
    from memnotsafe.cli import load_campaign
    from memnotsafe.pilot_pack import run_pilot

    console, buf = _console()
    rc = run_pilot(str(tmp_path / "nope.yaml"), str(tmp_path / "o"),
                   load_campaign=load_campaign, console=console,
                   online=False, allow_static=False)
    assert rc == 2
    text = buf.getvalue()
    assert "[БЛОКЕР]" in text and "--allow-static" in text and "--online" in text


def test_pilot_allow_static_passes_gate(tmp_path: Path) -> None:
    """С --allow-static гейт пройден: до блокера дело не доходит (дальше — обычная
    конфиг-ошибка на несуществующем pilot.yaml, но НЕ гейт-блокер статики)."""
    from memnotsafe.cli import load_campaign
    from memnotsafe.pilot_pack import run_pilot

    console, buf = _console()
    rc = run_pilot(str(tmp_path / "nope.yaml"), str(tmp_path / "o"),
                   load_campaign=load_campaign, console=console,
                   online=False, allow_static=True)
    assert rc == 2  # конфиг не найден
    assert "паковый прогон со СТАТИЧЕСКИМ" not in buf.getvalue()  # гейт НЕ сработал
