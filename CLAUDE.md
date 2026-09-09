# memnotsafe — контракт для Codex App и Claude Code Desktop

Пакет: `memnotsafe` (Python ≥ 3.11, src-layout).
CLI: `memnotsafe` → `src/memnotsafe/cli.py`.
Задача продукта: red teaming долговременной памяти LLM-агентов, не prompt→response одной реплики.
Канон на этой машине: `C:\Users\dota2\memnotsafe-integration\team-publish`
Волт: `C:\Users\dota2\AgentVault`
Соседние папки в `C:\Users\dota2\memnotsafe-integration\` не открывать и не править.

Этот файл кладётся как `AGENTS.md` и как `CLAUDE.md` в корень `team-publish`.

## Сначала прочитай

1. `MAP.md`
2. хвост `LOG.md`
3. при архитектурном вопросе — `PROJECT_OVERVIEW.md` и `.specify/memory/constitution.md`
4. при вопросе «как задумано в постановке» — не выдумывай. Спроси корпус NotebookLM / процитируй `description_interim.md`

## Роли ядра — не смешивать

```
Attack        ЧТО: payload, delivery, trigger, expected_effect
TargetAdapter КАК говорить со стендом
Runner        КОГДА / порядок стадий
Oracle        УДАЛАСЬ ЛИ
Reporter      КАК ПОКАЗАТЬ
```

Новая атака = новый файл в `src/memnotsafe/attacks/` + YAML в `scenarios/` и/или `attack_classes/`.
Ядро (`core/`, `cli.py`) не трогать, если задача — «добавить атаку» или «поправить сценарий».

## Канонические команды

```bash
pip install -e .
memnotsafe probe --target mock
memnotsafe run --scenario scenarios/cross_user_bac.yaml --output runs/demo
python3 -m pytest tests/ -q
```

Без живого стенда работай через `mock`.
`adapters/investment_stand.py` и pymongo — только если задача явно про live Mongo.

Коды выхода: ошибка раннера → 1; атака не пробилась → 0 + `NOT_EXPLOITABLE`. Не чини это «на успех».

## Что можно править без спроса

- тест в `tests/`
- сценарий YAML
- оракул / репорт, если ломается детерминированный mock-путь
- MAP/LOG

## Что нельзя

- класть ключи, cookie, дампы живой памяти клиентов в репо или в чат
- переносить правки в соседние копии (`agentic-red-teaming-main`, `tp-fix-dedup`, …)
- генерировать новые attack family «на глаз», без spec в `specs/` или постановки
- переписывать сразу Attack + Adapter + Oracle в одном диффе без нужды
- запускать live-target, если в задаче не сказано
- force-push / reset --hard

## Маршрут исполнителя

- узкий красный тест, один модуль, YAML-фик → Codex
- роли ядра, новый family, evidence/judge, много файлов → Claude Code
- бумага / MPBench / MITRE / постановка кейса → NotebookLM, затем заметка, потом код

## После работы

Допиши `LOG.md`. Если изменилась карта модулей — обнови `MAP.md`.
Покажи команду проверки, которую ты реально прогнал.
