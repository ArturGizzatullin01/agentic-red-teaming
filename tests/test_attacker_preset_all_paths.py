"""tests/test_attacker_preset_all_paths.py — CARD-LIVE-COVERAGE Задача 5.

--attacker-preset переключает атакующую модель во ВСЕХ путях (run/campaign/generate),
не только в мастере go; тем же apply_attacker_preset. Неизвестный пресет —
управляемый отказ (reporter, exit 1), не traceback. Печать — забота helper'а.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.cli import (  # noqa: E402
    _apply_attacker_preset_or_report,
    _attacker_config_from_args,
    build_parser,
)
from memnotsafe.selfserve import ATTACKER_PRESETS  # noqa: E402


class _Rep:
    def __init__(self) -> None:
        self.errors: list[tuple[str, str]] = []

    def emit_error(self, *, command: str, message: str) -> None:
        self.errors.append((command, message))


def _args(cmd: str, *extra: str):
    return build_parser().parse_args([cmd, *extra])


def test_run_campaign_parser_accepts_attacker_preset() -> None:
    """RED до Задачи 5: run/campaign не знали --attacker-preset (SystemExit при разборе)."""
    for cmd in ("run", "campaign"):
        args = _args(cmd, "--scenario", "s", "--output", "o", "--attacker-preset", "deepseek")
        assert args.attacker_preset == "deepseek"


@pytest.mark.parametrize("preset", ["qwen", "yandexgpt", "deepseek"])
@pytest.mark.parametrize("cmd", ["run", "campaign", "generate"])
def test_preset_resolves_attacker_config_in_all_paths(cmd: str, preset: str) -> None:
    if cmd == "generate":
        args = _args(cmd, "--profile", "p.yaml", "--out", "o.yaml", "--attacker-preset", preset)
    else:
        args = _args(cmd, "--scenario", "s.yaml", "--output", "o", "--online", "--attacker-preset", preset)
    rep = _Rep()
    assert _apply_attacker_preset_or_report(args, rep, cmd) is True
    assert not rep.errors
    cfg = _attacker_config_from_args(args)
    assert cfg.provider == "openai"
    assert cfg.model == ATTACKER_PRESETS[preset].model and cfg.model.startswith("gpt://")
    assert cfg.base_url == "https://llm.api.cloud.yandex.net/v1"
    assert cfg.api_key_env == "ATTACKER_API_KEY"


def test_stub_preset_stays_offline() -> None:
    args = _args("run", "--scenario", "s", "--output", "o", "--attacker-preset", "stub")
    rep = _Rep()
    assert _apply_attacker_preset_or_report(args, rep, "run") is True
    assert _attacker_config_from_args(args).provider == "stub"


def test_unknown_preset_is_controlled_refusal() -> None:
    args = _args("run", "--scenario", "s", "--output", "o", "--attacker-preset", "bogus")
    rep = _Rep()
    assert _apply_attacker_preset_or_report(args, rep, "run") is False
    assert rep.errors and "bogus" in rep.errors[0][1]
