"""tests/test_live_scenarios_single_stack.py — карточка N (ПАЧКА 5): замок «один стек».

Все live-сценарии обязаны указывать на ОДИН И ТОТ ЖЕ развёрнутый стек стенда:
расползание по адресам (когда часть файлов смотрит на старое/другое развёртывание)
обнаруживается человеком только после сорвавшегося прогона. До карточки N пять
из семи live-сценариев целились в 8600/27017 — порты, которые никто не слушает.

Правило «live» — механическое: подстрока "live" в имени сценария. Оно покрывает
оба встречающихся именования (`*_live*.yaml` и `live_clean_control.yaml`) и
автоматически подхватывает будущие live-сценарии — замок именно на расползание,
а не на фиксированный список.

Замок проверяет размер множеств, а не литералы: `{base_url}` по всем live-
сценариям имеет размер 1 и `{mongo_uri}` тоже. При смене портов всего стека
целиком тест останется зелёным — и это сознательно: расползание, а не конкретный
адрес, есть дефект.
"""

from __future__ import annotations

from pathlib import Path

import yaml

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def test_all_live_scenarios_target_single_stack() -> None:
    live: dict[str, dict[str, object]] = {}
    for p in sorted(SCENARIOS.glob("*.yaml")):
        if "live" not in p.stem:
            continue
        cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
        target = cfg.get("target") or {}
        live[p.stem] = {
            "base_url": target.get("base_url"),
            "mongo_uri": target.get("mongo_uri"),
        }

    assert live, "live-сценарии не найдены правилом «live в имени» — правило замка протухло"
    base_urls = {str(v["base_url"]) for v in live.values()}
    mongo_uris = {str(v["mongo_uri"]) for v in live.values()}
    for name, v in sorted(live.items()):
        print(f"[LIVE-LOCK] {name}: base_url={v['base_url']} mongo_uri={v['mongo_uri']}")
    print(f"[LIVE-LOCK] множество base_url: {sorted(base_urls)}")
    print(f"[LIVE-LOCK] множество mongo_uri: {sorted(mongo_uris)}")

    assert None not in {v["base_url"] for v in live.values()}, (
        "у live-сценария нет target.base_url — live-таргет без адреса не бывает"
    )
    assert len(base_urls) == 1, (
        f"live-сценарии целятся в РАЗНЫЕ стеки по base_url: {sorted(base_urls)} — "
        f"выровняй все live-файлы на один работающий стек, расползание адресов "
        f"обнаруживается только сорванным прогоном"
    )
    assert len(mongo_uri_set := mongo_uris) == 1, (
        f"live-сценарии целятся в РАЗНЫЕ стеки по mongo_uri: {sorted(mongo_uris)} — "
        f"выровняй все live-файлы на один работающий стек"
    )
