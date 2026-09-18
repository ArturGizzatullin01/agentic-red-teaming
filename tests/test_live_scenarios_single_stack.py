"""tests/test_live_scenarios_single_stack.py — карточка N-2 (ПАЧКА 5, хвост):
замок «на живой стенд целится N групп, внутри каждой — один стек».

Карточка N закрепляла один стек для семи live-сценариев правилом «подстрока
"live" в имени». Приёмка нашла его слепое пятно: на адаптер investment_stand
нацелены ДЕСЯТЬ сценариев — три пилота (имена без «live») смотрят на второй,
батч-стек, и замком не видны вовсе. Решение владельца (2026-09-18):
развёртываний ДВА, сводить их в одно не надо.

Факт о развёртываниях (наблюдение приёмки, не свойство репозитория):
  - основной стек — задан в docker-compose.yml каталога стенда
    (тул хакатон\\genai-invest-agent-memory-stand-stack2): API 9600,
    mongo 28017; на 2026-09-18 работал (docker ps, слушающие порты);
  - батч-стек — задан в agentic-red-teaming-main\\.agent-work\\docker-compose.batch.yml
    через тег !override (замена списка портов, а не слияние с донорским):
    agent-api 9702->8600, mongo 28182->27017, плюс собственные redis, keycloak,
    invest-server, mcp-invest; на 2026-09-18 не был запущен. Назначение —
    батч-прогоны того же стека (второй экземпляр); подробнее в шапках пилотов.

Как работает замок:
  - отбор — механический, по адаптеру: под замок попадает КАЖДЫЙ сценарий с
    target.adapter == investment_stand, как файл ни назови;
  - распределение по группам — механическое правило по имени (суффикс
    -pilot -> батч-стек, остальное -> основной стек), не список имён: новый
    сценарий не требует ручной бухгалтерии. Проверка исчерпываемости требует,
    чтобы каждый сценарий попал ровно в одну группу: нераспознанный сценарий
    и пустая группа (протухшее правило) — красные;
  - внутри группы — один стек: {base_url} и {mongo_uri} имеют размер 1
    (размер множества, не литерал: смена портов всего стека целиком тест
    переживает, расползание адресов — нет);
  - между группами адреса не пересекаются: это и есть «развёртываний два,
    и они разные»; проверка стоит ДО проверки размеров, чтобы наведённый
    на чужой стек пилот падал с внятным текстом про пересечение.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import yaml

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
STAND_ADAPTER = "investment_stand"

# Группы: (имя, механическое правило по имени файла). Правила сейчас тотальные,
# но гарды ниже (ровно одна группа / непустая группа) обязаны остаться: при
# появлении третьего развёртывания правило забудут дописать — замок скажет.
GROUP_RULES: tuple[tuple[str, object], ...] = (
    ("основной стек", lambda stem: not stem.endswith("-pilot")),
    ("батч-стек", lambda stem: stem.endswith("-pilot")),
)


def test_all_stand_scenarios_grouped_single_stack_per_group() -> None:
    # 1. Отбор по адаптеру, не по имени файла.
    stand: dict[str, dict[str, object]] = {}
    for p in sorted(SCENARIOS.glob("*.yaml")):
        cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
        target = cfg.get("target") or {}
        if target.get("adapter") == STAND_ADAPTER:
            stand[p.stem] = {
                "base_url": target.get("base_url"),
                "mongo_uri": target.get("mongo_uri"),
            }

    assert stand, (
        "не найдено ни одного сценария с target.adapter == "
        f"{STAND_ADAPTER!r} — отбор замка протух"
    )

    # 2. Распределение по группам: ровно одна группа на сценарий.
    groups: dict[str, dict[str, dict[str, object]]] = {name: {} for name, _ in GROUP_RULES}
    for stem, addr in stand.items():
        matched = [name for name, rule in GROUP_RULES if rule(stem)]
        assert len(matched) == 1, (
            f"сценарий {stem!r} (adapter={STAND_ADAPTER!r}) подошёл под {len(matched)} "
            f"групп(ы): {matched or 'ни одной'} — каждый стендовый сценарий обязан "
            f"попасть ровно в одну группу; если это новое развёртывание, объяви "
            f"группу явным правилом в GROUP_RULES, а не правь адреса"
        )
        groups[matched[0]][stem] = addr

    # 3. Пустая группа — правило отбора протухло.
    for name, members in groups.items():
        assert members, (
            f"группа «{name}» пуста: правило отбора не находит ни одного "
            f"сценария — объяви группу заново или снеси её"
        )

    # 4. Сводка для упавшего прогона (без отладчика).
    for name, _ in GROUP_RULES:
        for stem, addr in sorted(groups[name].items()):
            print(f"[LIVE-LOCK] {name} | {stem}: base_url={addr['base_url']} mongo_uri={addr['mongo_uri']}")

    # 5. Непересечение групп (ДО проверки размеров: сдвиг адреса в чужую
    #    группу должен падать текстом про два развёртывания).
    for (name_a, a), (name_b, b) in itertools.combinations(list(groups.items()), 2):
        for key in ("base_url", "mongo_uri"):
            overlap = {x[key] for x in a.values()} & {x[key] for x in b.values()}
            assert not overlap, (
                f"адреса групп «{name_a}» и «{name_b}» пересекаются по {key}: "
                f"{sorted(str(x) for x in overlap)} — развёртываний два и они разные; "
                f"если стеки объединены сознательно, снеси группу батч-стека "
                f"целиком (решение владельца), а не правь адреса по одному файлу"
            )

    # 6. Внутри каждой группы — один стек (размер множества, не литерал).
    for name, members in groups.items():
        for key in ("base_url", "mongo_uri"):
            values = {x[key] for x in members.values()}
            assert None not in values, (
                f"в группе «{name}» есть сценарий без target.{key} — "
                f"стендовый таргет без адреса не бывает"
            )
            assert len(values) == 1, (
                f"группа «{name}» целится в РАЗНЫЕ стеки по {key}: "
                f"{sorted(str(v) for v in values)} — выровняй файлы группы на один "
                f"развёрнутый стек; расползание адресов обнаруживается только "
                f"сорванным прогоном"
            )
