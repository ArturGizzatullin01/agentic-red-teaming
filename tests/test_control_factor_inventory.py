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
    # Карточка H2x: пара базовый арм (mock) <-> белый ящик (investment_stand).
    # repetitions совпадают (обе =1), поэтому набор факторов уже, чем у прочих
    # mock<->live пар. Многофакторность здесь — mock<->live дизайн, не W4-конфаунд.
    ("global_policy_injection", "global_policy_injection_live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
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
    # CARD-LIVE-COVERAGE (2026-09-27): 16 канонических live-вариантов семей на
    # stack2 (investment_stand). Различие пары base(mock)↔live — РОВНО стек:
    # adapter/auth_mode/base_url/vulnerable (mock vulnerable:true → live
    # auth_mode:vulnerable без поля vulnerable; base_url появляется). actors/
    # family/repetitions/stop_on_success зеркалятся из mock → в diff не входят.
    # Это mock↔live дизайн (другой адаптер/стек), не W4-конфаунд.
    ("consent-laundering", "consent-laundering-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("contact-supersede", "contact-supersede-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("cross-lingual-insertion", "cross-lingual-insertion-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("cross-topic-smuggle", "cross-topic-smuggle-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("deferred-payload", "deferred-payload-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("delimiter-summary-injection", "delimiter-summary-injection-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("document-regulation-graft", "document-regulation-graft-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("fake-shared-past", "fake-shared-past-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("forged_rationale", "forged_rationale_live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("generated_support", "generated_support_live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("h09_matrix", "h09_matrix_live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("procedural-graft", "procedural-graft-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("recommendation-hijack", "recommendation-hijack-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("salami_composition", "salami_composition_live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("tool-error-echo", "tool-error-echo-live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
    ("tool_route_hijack", "tool_route_hijack_live"): ("adapter", "auth_mode", "base_url", "vulnerable"),
}

# Сценарии без контрольного двойника по правилу паринга. mk-матрицы сюда НЕ
# пишутся: `_mk_*`-сценарий, факторы которого равны базовому арму семейства,
# покрывается групповым правилом (см. докстринг и _group_base).
EXPECTED_UNPAIRED: tuple[str, ...] = (
    "consent-laundering-marker",
    "cross-topic-smuggle-global",
    "cross-topic-smuggle-pilot",
    # Карточка H22: два арма first-request-only (deferred — пейлоад вторым,
    # first — контроль, пейлоад первым). Различие пары — ПОЗИЦИЯ ПЕЙЛОАДА,
    # ВНЕ восьми факторов инвентаря; по всем восьми факторам армы идентичны
    # (ожидаемо, карточка §2.2). Суффикс -control правилом паринга не роднится
    # — оба имени закреплены здесь явно, прецеденты H18-ATTACK и H19.
    # FACTOR_KEYS НЕ расширяется молча — расширение словаря = решение A0.
    # CARD-LIVE-COVERAGE: deferred-payload теперь парен с deferred-payload-live —
    # из непарных вышел; ниже остаётся только контроль (позиция пейлоада, вне 8 факторов).
    "deferred-payload-control",
    # Карточка H19: два арма делимитер-инъекции (inject — с поддельными
    # делимитерами, plain — контроль без них). Различие пары — форма payload'а,
    # ВНЕ восьми факторов инвентаря; по всем восьми факторам армы идентичны
    # (различие ровно одно — делимитеры). Суффикс -control правилом паринга
    # не роднится (только _protected/-protected/_live/-live) — оба имени
    # закреплены здесь явно, прецедент H18-ATTACK (tool_route_hijack +
    # _control). Фактор «делимитеры» в FACTOR_KEYS НЕ вносится — расширение
    # словаря факторов = решение A0, не молчая.
    # CARD-LIVE-COVERAGE: delimiter-summary-injection теперь парен с live (H19 —
    # семья live-only по построению); ниже остаётся только контроль (форма payload'а).
    "delimiter-summary-injection-control",
    # Карточка BB-CANON: чёрноящичный (tier-1, http_endpoint) канон-сценарий
    # response-семьи direct_poisoning для пилота (дизайн BB-VARIANTS, ACCEPT A0
    # 9/10). Двойника по правилу паринга нет (база *_bb не существует) — тот же
    # тип факта, что и global_policy_injection_bb_live: bb — не «атака <->
    # контроль», а тот же арм, наблюдаемый только через ответы (WRITE-триада
    # честно UNKNOWN). Single-user по канону семьи.
    "direct_poisoning_bb_live",
    "direct_poisoning_live_judged",
    "document-regulation-graft-global",
    "document-regulation-graft-pilot",
    "document-regulation-graft-plain",
    # Карточка BB-CANON: tier-1 канон-сценарий response-семьи false_precedent
    # для пилота (BB-VARIANTS, ACCEPT 9/10) — тот же тип факта (база *_bb не
    # существует, bb не контроль). Single-user по канону семьи.
    "false_precedent_bb_live",
    # CARD-LIVE-COVERAGE: forged_rationale (базовый арм H15) теперь парен с
    # forged_rationale_live — из непарных вышел; mk-матрицы семьи по-прежнему
    # покрываются групповым правилом по этому базовому арму.
    "generated_escalation",
    # generated_support теперь парен с generated_support_live (CARD-LIVE-COVERAGE);
    # прочие generated-армы (escalation/agent2) двойника не имеют.
    "generated_support_agent2",
    # Карточка H2x: чёрный ящик tier-1 (http_endpoint). Двойника по правилу
    # паринга нет (имя *_bb_live не родственно базе *_live), и это факт
    # инвентаризации: bb — не «атака <-> контроль», а тот же арм, наблюдаемый
    # через другой адаптер (без Mongo/трассы). Закреплён явной строкой.
    "global_policy_injection_bb_live",
    # Карточка COND-CANON: живой сценарий условного варианта семьи
    # global_policy_injection (params.variant=conditional). Двойника по правилу
    # паринга нет: не-live близнеца (global_policy_injection_conditional) не
    # существует — вариант меряется ТОЛЬКО live (на mock он честный MISS, замок
    # tests/test_global_policy_conditional_variant.py). Это факт инвентаризации
    # (нет контрольного двойника), закреплён явной строкой.
    "global_policy_injection_conditional_live",
    # CARD-LIVE-COVERAGE: h09_matrix (представитель семьи, наследник
    # global_policy_injection) теперь парен с h09_matrix_live — из непарных вышел.
    # Восемь ячеек матрицы лежат в scenarios/h09-matrix/ и нерекурсивным glob'ом
    # не сканируются.
    "procedural-graft-marker",
    # CARD-LIVE-COVERAGE: salami_composition (базовый арм H14) теперь парен с
    # salami_composition_live — из непарных вышел; mk-матрицы семьи по-прежнему
    # покрываются групповым правилом по этому базовому арму.
    "system-log-impersonation-pilot",
    # Карточка BB-CANON: tier-1 канон-сценарий response-семьи
    # system_log_impersonation для пилота (BB-VARIANTS, ACCEPT 9/10) — тот же
    # тип факта (база *_bb не существует, bb не контроль). Single-user.
    "system_log_impersonation_bb_live",
    # Карточка H18-ATTACK: tool_route_hijack (базовый арм) теперь парен с
    # tool_route_hijack_live (CARD-LIVE-COVERAGE) — из непарных вышел; контроли
    # остаются непарными (bare-оформление той же записи, не режим авторизации).
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
