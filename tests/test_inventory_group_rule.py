"""tests/test_inventory_group_rule.py — карточка INV-RULE: замок группового правила mk-матриц.

Групповое правило (решение A0 2026-09-20): `*_mk_*`-сценарий НЕ получает строку
в EXPECTED_UNPAIRED, если все факторы инвентаря (target/actors/metrics — та же
проверка равенства, что у пар) равны факторам какого-то НЕ-mk сценария —
базового арма семейства. Семантика группы: одно семейство, варьируется ровно
одна величина (params.case_marker_style / require_case_marker), контрольный
двойник не нужен ПО ЗАМЫСЛУ; прецедент обоснования — 72bb6cf.

Два замка отсюда:
  1. правило реально покрывает существующие mk-матрицы: mk-сценарии убраны из
     явного списка, инвентарь на полном наборе зелёный;
  2. правило — НЕ зонтик для конфаундов: mk-имя с отличающимися факторами
     обязано оставаться непарным и без строки ожидания ронять inventory.

Проверки идут на копии scenarios в tmp (репозиторий не загрязняется) через
monkeypatch константы SCENARIOS в модуле инвентаря.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import test_control_factor_inventory as inv


def _tmp_scenarios(tmp_path: Path, monkeypatch) -> Path:
    dst = tmp_path / "scenarios"
    shutil.copytree(inv.SCENARIOS, dst)
    monkeypatch.setattr(inv, "SCENARIOS", dst)
    return dst


def _write_cfg(scenarios: Path, name: str, cfg: dict) -> None:
    (scenarios / f"{name}.yaml").write_text(
        yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )


def test_group_rule_covers_existing_mk_matrices(tmp_path: Path, monkeypatch) -> None:
    """Замок 1: mk-матрица, равная базовому арму по факторам, живёт БЕЗ строки
    в EXPECTED_UNPAIRED — её покрывает групповое правило, инвентарь зелёный."""
    _tmp_scenarios(tmp_path, monkeypatch)

    stems = {p.stem for p in inv.SCENARIOS.glob("*.yaml")}
    factors = {s: inv._factors(s) for s in sorted(stems)}
    mk_stems = tuple(sorted(s for s in stems if inv.MK_MARKER in s))
    assert mk_stems, "mk-сценариев в наборе нет — замок группы проверять не на чем"
    for s in mk_stems:
        assert s not in inv.EXPECTED_UNPAIRED, (
            f"{s} держится явной строкой в EXPECTED_UNPAIRED — карточка INV-RULE "
            f"убирает mk-сценарии из списка (их покрывает групповое правило)"
        )
        assert inv._group_base(s, factors) is not None, (
            f"{s} не покрыт групповым правилом: не найден базовый арм с равными "
            f"факторами (target/actors/metrics) — правило сломано"
        )

    # полный инвентарь на реальном наборе (через копию) обязан быть зелёным
    inv.test_control_factor_inventory()


def test_group_rule_rejects_mk_name_with_different_factors(tmp_path: Path, monkeypatch) -> None:
    """Замок 2 (карточка INV-RULE §3.4): правило — не зонтик.

    fake_mk_x: имя матчит шаблон группы, но target отличается от базового арма.
    Правило обязано НЕ покрывать его: сценарий остаётся непарным, и без строки
    в EXPECTED_UNPAIRED inventory роняется — конфаунд не спрячется за mk-имя.
    """
    scenarios = _tmp_scenarios(tmp_path, monkeypatch)

    cfg = yaml.safe_load(
        (scenarios / "cross_user_bac_c_mk_operand.yaml").read_text(encoding="utf-8")
    )
    cfg["id"] = "fake_mk_x"
    cfg["target"] = dict(cfg["target"])
    cfg["target"]["adapter"] = "fake-adapter-not-in-any-base-arm"
    _write_cfg(scenarios, "fake_mk_x", cfg)

    stems = {p.stem for p in inv.SCENARIOS.glob("*.yaml")}
    factors = {s: inv._factors(s) for s in sorted(stems)}
    assert inv._group_base("fake_mk_x", factors) is None, (
        "групповое правило проглотило mk-имя с отличающимся target — оно не зонтик "
        "для конфаундов (карточка INV-RULE §3.4)"
    )

    pairs = inv._pairs(stems)
    paired = {s for p in pairs for s in p}
    assert "fake_mk_x" in (stems - paired), "fake_mk_x обязан быть непарным"
    assert "fake_mk_x" not in inv.EXPECTED_UNPAIRED

    try:
        inv.test_control_factor_inventory()
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "inventory НЕ уронил неподшитый fake_mk_x — групповое правило "
            "проглотило конфаунд, замок сломан"
        )
