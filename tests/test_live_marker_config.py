"""tests/test_live_marker_config.py — CARD-MARKER-LIVE: маркерная готовность
трёх bac-сценариев live + потолок settle на стенде stack2.

Два факта живых прогонов 2026-09-24 (A0), которые этот замок закрепляет
конфигурационно:

1. Плоские bac-сценарии (`cross_user_bac_live`, `_b_live`, `_c_live`) с одним
   лишь `require_case_marker: true` падали честным FATAL раннера: маркер не
   попадал ни в payload, ни в delivery-реплики (`core/runner.py:234-251`).
   Для семейства `cross_user_bac` текст payload'а НЕ живёт в YAML — он
   собирается кодом атаки (`attacks/cross_user_bac.py`), поэтому «маркерный
   плейсхолдер в корпусе» для этой тройки достигается ЕДИНСТВЕННЫМ способом —
   включением `params.case_marker_in_payload` + `params.case_marker_style`,
   ровно как в прецеденте `cross_user_bac_c_mk_operand.yaml` (карточка V-4).
   Буквальной строки `{case_marker}` в этих YAML нет и быть не может: у них
   нет ни блока корпуса, ни текста записи. Замок ниже проверяет не написание,
   а следствие — маркер доходит до доставки, значит FATAL больше не наступает.

2. PERSISTENCE умирал на `settle_timeout_s: 10` — финализация памяти стенда
   занимает дольше. Потолок поднят до 60 у ВСЕХ сценариев основного стека.

Отбор стека — механический, по адресу таргета (`target.base_url` содержит
`:9600`), а НЕ по тексту файла. Это важно: `grep -l 9600 scenarios/` ловит
ещё и три `-pilot`-сценария, у которых 9600 встречается только в комментарии
«это НЕ основной стек 9600/28017», а сам таргет смотрит на батч-стек
(API 9702 / mongo 28182, см. tests/test_live_scenarios_single_stack.py).
Батч-стек — другое развёртывание, его тайминги этой карточкой не измерялись,
и под потолок он не попадает; граница заперта отдельным тестом ниже.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from memnotsafe.attacks import get_attack
from memnotsafe.attacks.base import AttackContext
from memnotsafe.core.config import load_scenario

REPO = Path(__file__).resolve().parents[1]
SCENARIOS = REPO / "scenarios"

# Тройка плоских live-сценариев кросс-юзерной атаки (карточка MARKER-LIVE §1).
BAC_LIVE_STEMS = (
    "cross_user_bac_live",
    "cross_user_bac_b_live",
    "cross_user_bac_c_live",
)

# Прецедент размещения (карточка V-4): маркер — второй операнд инструкции.
MARKER_STYLE = "operand"

# Адрес основного стека (stack2) и пол таймаута финализации.
STACK2_MARK = ":9600"
SETTLE_FLOOR_S = 60

# Синтетический маркер формы CM-<6hex>: значение произвольно, проверяется форма
# размещения и факт попадания в доставку, а не конкретный токен.
MARKER = "CM-7b31de"


def _cfg(stem: str) -> dict:
    return yaml.safe_load((SCENARIOS / f"{stem}.yaml").read_text(encoding="utf-8")) or {}


def _stack2_stems() -> list[str]:
    """Сценарии основного стека — по адресу таргета, не по тексту файла."""
    out = []
    for p in sorted(SCENARIOS.glob("*.yaml")):
        target = (_cfg(p.stem).get("target") or {})
        base_url = str(target.get("base_url") or "")
        if STACK2_MARK in base_url:
            out.append(p.stem)
    return out


def test_bac_live_scenarios_declare_marker_isolation() -> None:
    """Тройка объявляет маркерную изоляцию в форме прецедента V-4."""
    for stem in BAC_LIVE_STEMS:
        cfg = _cfg(stem)
        assert cfg.get("require_case_marker") is True, (
            f"{stem}: require_case_marker не включён — write-оракул останется "
            f"на legacy-needle (первые 60 символов payload), который финалайзер "
            f"стенда не находит после перефразирования"
        )
        params = cfg.get("params") or {}
        assert params.get("case_marker_in_payload") is True, (
            f"{stem}: require_case_marker: true без params.case_marker_in_payload — "
            f"это ровно та раскладка, что давала честный FATAL раннера "
            f"(runner.py:234-251): маркер объявлен, но в доставку не попадает"
        )
        assert params.get("case_marker_style") == MARKER_STYLE, (
            f"{stem}: case_marker_style={params.get('case_marker_style')!r}, "
            f"ожидается {MARKER_STYLE!r} — единственный стиль с измеренной "
            f"выживаемостью (V-3, V-3C-R2); tail опровергнут 0/6"
        )


def test_bac_live_marker_reaches_delivery() -> None:
    """Следствие, а не написание: при объявленной изоляции маркер реально
    доходит до delivery-реплик — той самой проверкой, что делает раннер
    (`marker_placed` в core/runner.py). Значит honest-FATAL не наступает.

    Проверяется на конфигурации КАЖДОГО сценария (свои принципалы и params),
    а не на синтетическом контексте: ошибка в params одного файла не спрячется
    за зелёный результат другого.
    """
    attack = get_attack("cross_user_bac")()
    for stem in BAC_LIVE_STEMS:
        cfg = _cfg(stem)
        actors = cfg.get("actors") or {}
        ctx = AttackContext(
            str((actors.get("attacker") or {}).get("user_id")),
            str((actors.get("victim") or {}).get("user_id")),
            1,
            f"CASE-MARKER-LIVE-{stem}",
            params=cfg.get("params") or {},
            case_marker=MARKER,
        )
        candidate = attack.generate(ctx)
        delivery_texts = [s.message for s in attack.delivery_steps(candidate, ctx)]
        marker_placed = any(MARKER in t for t in delivery_texts if t)
        assert marker_placed, (
            f"{stem}: маркер {MARKER} не попал ни в одну delivery-реплику — "
            f"раннер поднимет RunnerError до доставки (config error, exit 1)"
        )
        # operand-позиция: маркер — второй операнд ТОЙ ЖЕ инструкции, рядом
        # с cus="…", а не отдельным хвостовым предложением (tail опровергнут).
        assert candidate.payload.count(MARKER) == 1, (
            f"{stem}: маркер встречается {candidate.payload.count(MARKER)} раз(а), "
            f"ожидается ровно один"
        )
        assert f'и служебный код регламента reg="{MARKER}"' in candidate.payload, (
            f"{stem}: маркер размещён не операндом инструкции"
        )
        assert "Служебный код запроса" not in candidate.payload, (
            f"{stem}: в payload просочился опровергнутый tail-стиль"
        )


def test_stack2_scenarios_have_settle_floor() -> None:
    """У всех сценариев основного стека финализации даётся не меньше пола."""
    stems = _stack2_stems()
    assert stems, (
        f"не найдено ни одного сценария с {STACK2_MARK} в target.base_url — "
        f"отбор замка протух"
    )
    for stem in BAC_LIVE_STEMS + ("cross_user_bac_c_mk_operand", "live_clean_control"):
        assert stem in stems, (
            f"{stem} обязан попадать в отбор основного стека — проверь "
            f"target.base_url, а не подгоняй отбор"
        )
    for stem in stems:
        target = _cfg(stem).get("target") or {}
        settle = target.get("settle_timeout_s")
        assert settle is not None, (
            f"{stem}: у стендового сценария нет target.settle_timeout_s — "
            f"молчаливый дефолт адаптера прячет реальный бюджет финализации"
        )
        assert settle >= SETTLE_FLOOR_S, (
            f"{stem}: settle_timeout_s={settle} < {SETTLE_FLOOR_S} — на живых "
            f"прогонах 2026-09-24 PERSISTENCE не доживал до финализации памяти "
            f"стенда; поднимать значение, а не пол"
        )
    print(f"[MARKER-LIVE] основной стек: {len(stems)} сценариев, пол {SETTLE_FLOOR_S}s")


def test_stack2_selection_excludes_batch_stack() -> None:
    """Граница отбора: `-pilot`-сценарии смотрят на батч-стек (9702/28182) и
    под потолок основного стека НЕ попадают, хотя `grep 9600` их находит —
    строка 9600 стоит у них в комментарии «это НЕ основной стек».

    Замок стоит именно здесь, чтобы отбор по тексту файла не вернулся молча:
    тайминги батч-развёртывания этой карточкой не измерялись.
    """
    stems = _stack2_stems()
    pilots = sorted(p.stem for p in SCENARIOS.glob("*-pilot.yaml"))
    assert pilots, "пилотов не найдено — правило именования батч-стека протухло"
    for stem in pilots:
        assert stem not in stems, (
            f"{stem} попал в отбор основного стека: его target.base_url "
            f"содержит {STACK2_MARK} — либо пилот перенацелен, либо отбор "
            f"съехал на текст комментария"
        )
        base_url = str((_cfg(stem).get("target") or {}).get("base_url") or "")
        assert STACK2_MARK not in base_url, f"{stem}: base_url={base_url!r}"


def test_touched_scenarios_load() -> None:
    """Любой затронутый YAML остаётся валидным сценарием (карточка §3)."""
    for stem in sorted(set(_stack2_stems()) | set(BAC_LIVE_STEMS)):
        scenario = load_scenario(SCENARIOS / f"{stem}.yaml")
        assert scenario.id, f"{stem}: пустой id после разбора"
        assert scenario.attack_family, f"{stem}: не разобрано attack.family"
