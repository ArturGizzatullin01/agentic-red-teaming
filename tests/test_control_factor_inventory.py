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

Групповое правило mk-матриц (решение A0 2026-09-20, карточка INV-RULE):
  сценарий с `_mk_` в имени — экспериментальная матрица: одно семейство,
  варьируется ровно ОДНА величина (params.case_marker_style /
  require_case_marker), контрольный двойник не нужен ПО ЗАМЫСЛУ — это не пара
  «атака ↔ контроль», а тот же базовый арм с включённой изоляцией. Такой
  сценарий покрывается правилом БЕЗ строки в EXPECTED_UNPAIRED, но только если
  ВСЕ факторы инвентаря (блоки target/actors/metrics в той же проверке
  равенства, что у пар) равны факторам какого-то НЕ-mk сценария — базового
  арма семейства. Прецедент обоснования — 72bb6cf (exp/case-marker-placement,
  маркерные матрицы). Правило — не зонтик: mk-имя с отличающимися факторами
  остаётся непарным и обязано закрепляться явной строкой (замок —
  tests/test_inventory_group_rule.py).

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
    # Карточка V: пары B/C — копии L1/L2 с заменой только принципалов.
    # Различие ровно principals: у контроля нет атакующего (нет доставки),
    # стенд/семейство/бюджет/адреса — побайтово те же.
    ("cross_user_bac_b", "cross_user_bac_b_live"): ("principals",),
    ("cross_user_bac_c", "cross_user_bac_c_live"): ("principals",),
}

# Сценарии без контрольного двойника по правилу паринга. mk-матрицы сюда НЕ
# пишутся: `_mk_*`-сценарий, факторы которого равны базовому арму семейства,
# покрывается групповым правилом (см. докстринг и _group_base).
EXPECTED_UNPAIRED: tuple[str, ...] = (
    "consent-laundering-marker",
    "cross-topic-smuggle-global",
    "cross-topic-smuggle-pilot",
    # Карточка H19: два арма делимитер-инъекции (inject — с поддельными
    # делимитерами, plain — контроль без них). Различие пары — форма payload'а,
    # ВНЕ восьми факторов инвентаря; по всем восьми факторам армы идентичны
    # (различие ровно одно — делимитеры). Суффикс -control правилом паринга
    # не роднится (только _protected/-protected/_live/-live) — оба имени
    # закреплены здесь явно, прецедент H18-ATTACK (tool_route_hijack +
    # _control). Фактор «делимитеры» в FACTOR_KEYS НЕ вносится — расширение
    # словаря факторов = решение A0, не молчая.
    "delimiter-summary-injection",
    "delimiter-summary-injection-control",
    "direct_poisoning_live_judged",
    "document-regulation-graft-global",
    "document-regulation-graft-pilot",
    "document-regulation-graft-plain",
    # Карточка H15: базовый арм семьи forged_rationale. Protected-двойника у
    # семьи нет по дизайну карточки — контроль пары это bare-оформление той же
    # директивы (forged_rationale_mk_pair_control), а не режим авторизации;
    # mk-матрицы семьи покрываются групповым правилом по этому базовому арму.
    "forged_rationale",
    "generated_escalation",
    "generated_support",
    "generated_support_agent2",
    "procedural-graft-marker",
    # Карточка H14: базовый арм семьи salami_composition. Protected-двойника у
    # семьи нет по дизайну карточки — контроль пары это partial-retrieval
    # (salami_composition_mk_pair_control), а не режим авторизации; mk-матрицы
    # семьи покрываются групповым правилом по этому базовому арму.
    "salami_composition",
    "system-log-impersonation-pilot",
    # Карточка H18-ATTACK: три арма семьи tool_route_hijack (redirect-forbidden,
    # redirect-skipped, контроль bare). Protected-двойника нет по дизайне —
    # контроль пары это bare-оформление той же записи, а не режим авторизации.
    "tool_route_hijack",
    "tool_route_hijack_control",
    "tool_route_hijack_skipped",
)

# Маркер группы экспериментальных матриц: варьируется ровно одна величина
# (маркерная изоляция), двойник не нужен по замыслу — карточка INV-RULE,
# решение A0 2026-09-20, прецедент 72bb6cf.
MK_MARKER = "_mk_"


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


def _group_base(name: str, factors: dict[str, dict[str, object]]) -> str | None:
    """Базовый арм группы для `*_mk_*`-сценария или None, если правило не покрывает.

    Групповое правило (карточка INV-RULE, решение A0 2026-09-20): mk-матрица
    покрывается БЕЗ строки в EXPECTED_UNPAIRED, только если все факторы
    инвентаря равны факторам какого-то НЕ-mk сценария — базового арма
    семейства. Это та же проверка равенства блоков target/actors/metrics,
    что уже используется для пар, применённая целиком (все ключи сразу), а
    не по-отдельности. Прецедент обоснования — 72bb6cf. Правило — не зонтик:
    mk-имя с отличающимся хотя бы одним фактором остаётся непарным и обязано
    закрепляться явной строкой (замок — tests/test_inventory_group_rule.py).
    """
    if MK_MARKER not in name:
        return None
    for other in sorted(factors):
        if other == name or MK_MARKER in other:
            continue
        if factors[other] == factors[name]:
            return other
    return None


def test_control_factor_inventory() -> None:
    stems = {p.stem for p in SCENARIOS.glob("*.yaml")}
    pairs = _pairs(stems)
    paired = {s for p in pairs for s in p}
    factors = {s: _factors(s) for s in sorted(stems)}
    covered: dict[str, str] = {}
    for s in sorted(stems - paired):
        base = _group_base(s, factors)
        if base is not None:
            covered[s] = base
    unpaired = tuple(sorted(stems - paired - set(covered)))

    actual: dict[tuple[str, str], tuple[str, ...]] = {}
    for x, y in pairs:
        fx, fy = _factors(x), _factors(y)
        diff = tuple(sorted(k for k in FACTOR_KEYS if fx[k] != fy[k]))
        actual[(x, y)] = diff
        mark = " <== МНОГОФАКТОРНАЯ (кандидат W4)" if len(diff) > 1 else ""
        print(f"[INVENT] {x} <-> {y}: {', '.join(diff) if diff else '<идентичны>'}{mark}")
        for k in diff:
            print(f"[INVENT]   {k}: {x}={fx[k]!r} | {y}={fy[k]!r}")
    for s, b in covered.items():
        print(f"[INVENT] mk-матрица {s}: покрыта групповым правилом (базовый арм {b})")
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
        f"двойника тоже факт инвентаризации, закрепи их здесь; `_mk_*` "
        f"покрывается групповым правилом ТОЛЬКО при полном равенстве факторов "
        f"с базовым армом (см. _group_base) — иначе тоже строкой"
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
