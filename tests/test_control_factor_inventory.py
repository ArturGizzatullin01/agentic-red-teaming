"""tests/test_control_factor_inventory.py — карточка L (ПАЧКА 4): первый шаг W4.

Из чего на самом деле состоит каждое сравнение «атака ↔ контроль». W4 в реестре
утверждает, что арм и негативный контроль различаются не только атакой — но
КАКИМИ именно факторами различается каждая пара, нигде не измерено. Этот тест
строит перечень механически из scenarios/*.yaml и закрепляет его таблицей
ожиданий: изменение набора факторов у любой пары роняет тест.

Правило паринга (механическое, не на глаз):
  <имя> ↔ <имя>_protected и <имя> ↔ <имя>-protected  — оба разделителя
  встречаются в репозитории (cross_user_bac_protected — подчёркивание,
  direct_poisoning-protected — дефис);
  <имя> ↔ <имя>_live и <имя> ↔ <имя>-live;
  явная пара L1 ↔ L2: cross_user_bac_live ↔ live_clean_control.
Сценарий без пары по этому правилу попадает в список непарных — это тоже факт
(нет контрольного двойника), а не ошибка.

Факторы (значения извлекаются из YAML, absence — тоже значение):
  adapter         target.adapter;
  vulnerable      target.vulnerable (mock-трига);
  auth_mode       target.auth_mode (стенд-трига);
  principals      одно категорийное значение: none (нет атакующего — доставки
                  нет, драйвер L2 attack-секцию не исполняет) | self
                  (attacker == victim) | cross (attacker != victim).
                  Наличие доставки и наличие отдельного атакующего — одно
                  различие, а не два: доставка механически определяется
                  присутствием атакующего (владелец, карточка L);
  family          attack.family;
  repetitions     metrics.repetitions;
  stop_on_success metrics.stop_on_success;
  base_url        target.base_url.

Заметка о полноте: прочие поля target-блока (identities, mongo_uri, mongo_db,
settle_timeout_s) внутри каждой пары либо совпадают, либо их различие — строгое
следствие principals (identities у L2 = identities L1 минус строка атакующего).
Отдельными факторами они не объявлены; считать ли entangled-поля самостоятельными
факторами — решение A0, тогда это одноэлементная правка EXPECTED ниже.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"

FACTOR_KEYS = (
    "adapter", "vulnerable", "auth_mode", "principals",
    "family", "repetitions", "stop_on_success", "base_url",
)

# Явная пара L1 ↔ L2 (правило паринга её не выводит: имена не родственны).
EXPLICIT_PAIRS = (("cross_user_bac_live", "live_clean_control"),)

# Закреплённая таблица: pair -> отсортированный набор различающихся факторов.
# Пары, где факторов больше одного, — кандидаты W4 (в хендофе помечены отдельно).
EXPECTED_PAIR_DIFFS: dict[tuple[str, str], tuple[str, ...]] = {
    ("consent-laundering", "consent-laundering-protected"): ("vulnerable",),
    ("contact-supersede", "contact-supersede-protected"): ("vulnerable",),
    ("cross-lingual-insertion", "cross-lingual-insertion-protected"): ("vulnerable",),
    ("cross-topic-smuggle", "cross-topic-smuggle-protected"): ("vulnerable",),
    ("cross_user_bac", "cross_user_bac_protected"): ("vulnerable",),
    ("cross_user_bac", "cross_user_bac_live"): ("adapter", "auth_mode", "base_url", "repetitions", "vulnerable"),
    ("direct_poisoning", "direct_poisoning-protected"): ("vulnerable",),
    ("direct_poisoning", "direct_poisoning_live"): ("adapter", "auth_mode", "base_url", "repetitions", "stop_on_success", "vulnerable"),
    ("document-regulation-graft", "document-regulation-graft-protected"): ("vulnerable",),
    ("fake-shared-past", "fake-shared-past-protected"): ("vulnerable",),
    ("false_precedent", "false_precedent_live"): ("adapter", "auth_mode", "base_url", "repetitions", "stop_on_success", "vulnerable"),
    ("procedural-graft", "procedural-graft-protected"): ("vulnerable",),
    ("recommendation-hijack", "recommendation-hijack-protected"): ("vulnerable",),
    ("scope_escalation", "scope_escalation-protected"): ("vulnerable",),
    ("scope_escalation", "scope_escalation_live"): ("adapter", "auth_mode", "base_url", "repetitions", "stop_on_success", "vulnerable"),
    ("system-log-impersonation", "system-log-impersonation-protected"): ("vulnerable",),
    ("tool-error-echo", "tool-error-echo-protected"): ("vulnerable",),
    ("tool_argument_hijack", "tool_argument_hijack_protected"): ("vulnerable",),
    ("tool_argument_hijack", "tool_argument_hijack_live"): ("adapter", "auth_mode", "base_url", "repetitions", "stop_on_success", "vulnerable"),
    ("cross_user_bac_live", "live_clean_control"): ("principals",),
}

# Сценарии без контрольного двойника по правилу паринга.
EXPECTED_UNPAIRED: tuple[str, ...] = (
    "consent-laundering-marker",
    "cross-topic-smuggle-global",
    "cross-topic-smuggle-pilot",
    "direct_poisoning_live_judged",
    "document-regulation-graft-global",
    "document-regulation-graft-pilot",
    "document-regulation-graft-plain",
    "generated_escalation",
    "generated_support",
    "generated_support_agent2",
    "procedural-graft-marker",
    "system-log-impersonation-pilot",
)


def _factors(name: str) -> dict[str, object]:
    cfg = yaml.safe_load((SCENARIOS / f"{name}.yaml").read_text(encoding="utf-8"))
    target = cfg.get("target") or {}
    actors = cfg.get("actors") or {}
    metrics = cfg.get("metrics") or {}
    attack = cfg.get("attack") or {}
    attacker = actors.get("attacker")
    victim = actors.get("victim")
    if attacker is None:
        principals = "none"
    elif victim is not None and attacker.get("user_id") == victim.get("user_id"):
        principals = "self"
    else:
        principals = "cross"
    return {
        "adapter": target.get("adapter", "<absent>"),
        "vulnerable": target.get("vulnerable", "<absent>"),
        "auth_mode": target.get("auth_mode", "<absent>"),
        "principals": principals,
        "family": attack.get("family", "<absent>"),
        "repetitions": metrics.get("repetitions", "<absent>"),
        "stop_on_success": bool(metrics.get("stop_on_success", False)),
        "base_url": target.get("base_url", "<absent>"),
    }


def _pairs(stems: set[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for stem in sorted(stems):
        for twin in (stem + "_protected", stem + "-protected",
                     stem + "_live", stem + "-live"):
            if twin in stems:
                pairs.append((stem, twin))
    pairs.extend(EXPLICIT_PAIRS)
    return pairs


def test_control_factor_inventory() -> None:
    stems = {p.stem for p in SCENARIOS.glob("*.yaml")}
    pairs = _pairs(stems)
    paired = {s for p in pairs for s in p}
    unpaired = tuple(sorted(stems - paired))

    actual: dict[tuple[str, str], tuple[str, ...]] = {}
    for x, y in pairs:
        fx, fy = _factors(x), _factors(y)
        diff = tuple(sorted(k for k in FACTOR_KEYS if fx[k] != fy[k]))
        actual[(x, y)] = diff
        mark = " <== МНОГОФАКТОРНАЯ (кандидат W4)" if len(diff) > 1 else ""
        print(f"[INVENT] {x} <-> {y}: {', '.join(diff) if diff else '<идентичны>'}{mark}")
        for k in diff:
            print(f"[INVENT]   {k}: {x}={fx[k]!r} | {y}={fy[k]!r}")
    print(f"[INVENT] непарные (нет двойника по правилу): {', '.join(unpaired)}")

    assert set(actual) == set(EXPECTED_PAIR_DIFFS), (
        f"набор пар изменился: новые={set(actual) - set(EXPECTED_PAIR_DIFFS)} "
        f"исчезли={set(EXPECTED_PAIR_DIFFS) - set(actual)} — добавь/сними строку "
        f"ожидания осознанно (правило паринга в докстринге)"
    )
    for pair in pairs:
        assert actual[pair] == EXPECTED_PAIR_DIFFS[pair], (
            f"набор различающихся факторов пары {pair} изменился: было "
            f"{EXPECTED_PAIR_DIFFS[pair]}, стало {actual[pair]} — это сдвиг "
            f"дизайна сравнения (W4), обнови ожидание осознанно, а не молча"
        )
    assert unpaired == EXPECTED_UNPAIRED, (
        f"непарные сценарии изменились: {unpaired} — новые сценарии без "
        f"двойника тоже факт инвентаризации, закрепи их здесь"
    )


def test_protected_pairs_single_factor() -> None:
    """Замок W4 (карточка O): у КАЖДОЙ mock-пары `<имя> ↔ <имя>_protected` /
    `<имя>-protected` различие обязано быть ровно фактором `vulnerable`.

    Это и есть «арм отличается от контроля только атакой»: если в паре
    расползается что-то ещё (повторы, stop_on_success, адреса), разница исходов
    перестаёт читаться как эффект защиты — она может быть эффектом бюджета
    попыток. Пары `_live`/`-live` и явная пара L1↔L2 сюда НЕ входят: их
    многофакторность по устройству (другой адаптер, другой стек), это другой
    тип сравнения, а не конфаунд.

    Отбор пар — то же механическое правило `_pairs` с фильтром на protected-
    суффикс, не список имён: новая protected-пара попадает под замок сама.
    """
    stems = {p.stem for p in SCENARIOS.glob("*.yaml")}
    protected_pairs = [
        (x, y) for x, y in _pairs(stems)
        if y.endswith(("-protected", "_protected")) and (x, y) not in EXPLICIT_PAIRS
    ]
    print(f"[W4-LOCK] protected-пар под замком: {len(protected_pairs)}")
    for x, y in protected_pairs:
        fx, fy = _factors(x), _factors(y)
        diff = tuple(sorted(k for k in FACTOR_KEYS if fx[k] != fy[k]))
        print(f"[W4-LOCK] {x} <-> {y}: {', '.join(diff) if diff else '<идентичны>'}")
        extra = tuple(k for k in diff if k != "vulnerable")
        missing = ("vulnerable",) if "vulnerable" not in diff else ()
        assert diff == ("vulnerable",), (
            f"пара {x!r} <-> {y!r}: различаются факторы {diff}, а обязаны ровно "
            f"('vulnerable',) — лишнее: {extra or '—'}, отсутствует: {missing or '—'}. "
            f"Конфаунд вернулся: выровняй СЦЕНАРИИ (повторы/прочие поля контроля "
            f"должны совпадать с армом), а не подправляй это ожидание"
        )
    assert protected_pairs, (
        "protected-пары не отобраны вовсе — правило паринга протухло"
    )
