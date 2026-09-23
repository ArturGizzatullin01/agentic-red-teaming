---
type: map
project: memnotsafe
canon: team-publish
---

# MAP — memnotsafe

## Зачем
Автоматический red team памяти агента:
сценарий → baseline → attacker session → memory write → новая victim-сессия → retrieval → tool-эффект → oracles → report.

Пользователь — ИБ, не разработчик атакуемого агента.

## Канон
Открывать только `C:\Users\dota2\memnotsafe-integration\team-publish`.
Не индексировать соседние деревья в `C:\Users\dota2\memnotsafe-integration\`.

## Запуск
```
pip install -e .          # pyyaml, httpx; mongo extra опционален
memnotsafe probe --target mock
python3 -m pytest tests/ -q
```

## Модули `src/memnotsafe/`

| Путь | Роль |
|---|---|
| `cli.py` | вход: probe / run / campaign / report |
| `core/` | runner, склейка стадий; GoalContract / ExperimentSpec / AttemptHistory / BudgetLedger (фича 007); `escalation_feedback.py` — контракт онлайн-уровня (ARC-1): ядро не импортирует generation |
| `attacks/` | семьи атак, регистрация по `metadata.family` |
| `adapters/` | `mock.py` (офлайн канон), `investment_stand.py` (live) |
| `oracles/` | успех/провал по evidence |
| `evidence/` | снапшот памяти, matching; EvidenceBundle — пакеты доказательств (фича 007); `telemetry.py` — контракт context_tool_evidence (фича 010) |
| `judge/` | LLM-as-judge, бюджет, калибровка |
| `generation/` | автогенерация слабосигнальных атак |
| `tracing/` | трасса |
| `reporting/` | HTML/JSON/SARIF, воронка; ConsoleReporter — единый вывод CLI (фича 006) |

## Рядом с кодом

- `scenarios/` — YAML прогонов
- `attack_classes/` — декларативные классы
- `profiles/`, `corpora/` — профили жертвы и сиды
- `tests/` — офлайн-регресс, E2E на mock
- `docs/integration-handoff/` — spec/plan/tasks интеграции
- `.specify/memory/constitution.md` — конституция Spec Kit
- `.claude/skills/speckit-*` — уже есть цикл спеки для Claude Code

## Не трогать без задачи

- `runs/`, `reports/` — артефакты, не исходники
- live YAML в `../live-test-runtime/`
- чужие копии репо в родительском zip

## Известные ловушки

1. Два прототипа уже слиты в `src/memnotsafe`. Не возрождать второе дерево исходников.
2. Mock содержит намеренную уязвимость. «Починить mock, чтобы атака не проходила» — это порча стенда, если вас не просили закрыть конкретный контроль.
3. `cross_user_bac_protected.yaml` должен давать success=False при внешней утечке. Это регресс контроля, не баг раннера.
4. src-layout: без `pip install -e .` или `PYTHONPATH=src` CLI не найдёт пакет.
5. Судить семантику и читать состояние памяти — разные каналы. Не подменять oracle одним judge.
6. Правило слоёв (ARC-1): `core/*` не импортирует `generation/*` и `attacks/generated` ни на каком уровне; обратное разрешено. Проверяет `tests/test_import_layers.py` (AST-граф, SCC>1 нет); остаточные ленивые рёбра campaign/experiment заморожены точной таблицей там же — сужать можно, добавлять нельзя.

## Проверка по умолчанию
```
python3 -m pytest tests/test_e2e_cross_user.py tests/test_all_attacks.py -q
```
