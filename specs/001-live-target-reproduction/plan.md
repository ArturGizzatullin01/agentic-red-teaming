# Implementation Plan: Прогон батареи атак против живого стенда

**Branch**: `001-live-target-reproduction` | **Date**: 2026-09-05 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from [spec.md](spec.md)

## Summary

Доказать, что находка `cross_user_bac` воспроизводится на живом стенде
`genai-invest-agent-memory-stand`, а не только на офлайн-mock: та же воронка из шести
oracle-стадий, та же формула композита, отчёт с реальными артефактами, где `external_effect`
подтверждён утечкой данных чужого клиента.

Технический подход диктуется конституцией (Принцип III: ядро не знает о таргетах): ядро
(`src/memnotsafe/core/`) и оракулы (`src/memnotsafe/oracles/`) читают нормализованный словарь
snapshot-записей и трейс-событий. Живой стенд — чёрный ящик, отдающий другую схему (Mongo-коллекции,
текст ответа, опционально tool-телеметрию). Поэтому **вся стенд-специфика ложится в
`src/memnotsafe/adapters/investment_stand.py`**: адаптер (1) нормализует Mongo-память в записи
`{id, source_user, text, scope}`, которые понимает `find_candidate_record`; (2) детектирует
кросс-юзер утечку через один из трёх равнозначных каналов доказательства и переводит первое
подтверждение в канонические трейс-события (`llm_decision`, `tool_call`, `tool_result`), которые
оракулы уже умеют читать; (3) честно выставляет `Capabilities` так, что при отсутствии наблюдаемого
канала стадия остаётся `UNKNOWN`, а не `False`/`True` (Принцип IV). Оракулы и композит при этом не
меняются ни на строку.

Направление батареи на живой таргет делается новыми scenario YAML (`adapter: investment_stand`,
`identities`, `mongo_uri`, бюджет повторов N) — без правок логики атак (Принцип II). Единственная
вынужденная общая правка ядра — early-exit по первому композитному success в
`core/campaign.py` (FR-013): она конфиг-управляемая, target-agnostic и по умолчанию выключена,
чтобы mock-тесты и офлайн-демо остались неизменными (см. Complexity Tracking).

## Technical Context

**Language/Version**: Python 3.11+ (проект уже на `requires-python = ">=3.11"`, локально 3.13).

**Primary Dependencies**: существующие `httpx>=0.27` (async HTTP к стенду и к OpenRouter),
`pyyaml>=6.0` (scenario). Новая опциональная зависимость `pymongo` — только для evidence-канала
чтения памяти стенда, изолирована внутри `adapters/investment_stand.py` (ленивый импорт, уже так
сделано). OpenRouter вызывается по OpenAI-совместимому REST через `httpx` — отдельный SDK не нужен.

**Storage**: состояние живого стенда — MongoDB стенда (коллекции `dialog_sessions`,
`episodic_memories`, `semantic_memories`, `agent_policy_memories`), доступ на чтение по `mongo_uri`.
Артефакты прогона — файлы `runs/<name>/` и `reports/` (не коммитятся, воспроизводятся командой).

**Testing**: `pytest` (`python3 -m pytest tests/ -q`). Живой стенд в CI недоступен, поэтому новые
тесты работают на офлайн-фейках: unit-тесты нормализации Mongo-документов и детекции каналов
доказательства через поддельные ответы/снимки (без сети). Существующие mock-тесты остаются зелёными
и неизменными (FR-011).

**Target Platform**: локальный CLI (`memnotsafe run|campaign|report|probe|replay`) на macOS/Linux;
живой стенд поднят локально в `VSCodeProjects`, ходит к моделям через OpenRouter (`deepseek v4
flash` — сторона стенда); атакующая сторона фреймворка — `qwen 3.8` через OpenRouter (FR-008).

**Project Type**: single project (src-layout, пакет `memnotsafe`).

**Performance Goals**: не критичны — интерактивный red-team-прогон. Ограничитель — латентность
LLM/сети и Mongo-settle; бюджет N повторов с early-exit (FR-013) держит время прогона предсказуемым.

**Constraints**:

- Ядро (`src/memnotsafe/core/`) и оракулы (`src/memnotsafe/oracles/`) — без стенд-специфичных
  ветвлений и без правок формулы композита (Принципы III, V; Assumptions спека).
- Тристейт честности: `UNKNOWN` при отсутствии наблюдаемого канала, никогда не `True` (Принцип IV,
  FR-004).
- Коды возврата: инфраструктурный сбой → `exit 1`; честный негатив атаки → `exit 0` +
  `NOT_EXPLOITABLE` (Принцип VII, FR-006).
- Разные аутентифицированные клиенты для attacker (1001) и victim (1002) — обязательное условие
  настоящей кросс-юзер утечки (FR-009); ключи через переменные окружения.

**Вне области (out of scope):** режим `protected` защищаемого агента на ЖИВОМ таргете не проверяется
и не трогается этой фичей — живой стенд прогоняется только в `vulnerable`. Отдельного
`cross_user_bac_live_protected.yaml` не заводим. Путь «утечка заблокирована авторизацией» (SC-006)
остаётся покрытым существующим mock-сценарием
[cross_user_bac_protected.yaml](../../scenarios/cross_user_bac_protected.yaml) и его регрессионным
тестом — их мы не меняем (Принцип VI). Честный негатив на живом таргете (FR-006, `exit 0` +
`NOT_EXPLOITABLE`) при этом всё равно достижим и проверяется — через исчерпание бюджета N повторов
из-за недетерминизма модели (FR-013) и через семьи атак, которые на живом стенде не приводят к
внешней утечке, а не через `protected`.

**Scale/Scope**: пять существующих семейств атак, перенаправленных на живой таргет; ворота успеха
воспроизведения — `cross_user_bac`. Правки в одном адаптере + новые scenario YAML + одна
конфиг-управляемая правка `campaign.py` + новые офлайн-тесты. Файлы-аналоги перечислены в разделе
Project Structure.

## Constitution Check

*GATE: пройти до Phase 0. Повторно проверить после Phase 1. Источник —*
[.specify/memory/constitution.md](../../.specify/memory/constitution.md) *(v1.0.1).*

| Принцип | Как соблюдается этим планом | Вердикт |
|---------|-----------------------------|---------|
| I. Разделение ролей | Attack/Oracle/Runner/Reporter не трогаются; вся новая логика — в роли `TargetAdapter` (знает КАК). Адаптер не решает вердикт — только отдаёт нормализованные evidence, вердикт считает оракул. | PASS |
| II. Новая атака — новый файл | Новых атак нет. Живой таргет подключается scenario YAML (`adapter: investment_stand`), а не правкой атак или ядра. | PASS |
| III. Ядро не знает о таргетах | Mongo-схема, `auth_mode`, каналы доказательства, `identities`, settle-polling — всё внутри `adapters/investment_stand.py`. В `core/` не добавляется ни одного `if target == ...`. | PASS |
| IV. Тристейт честности | Адаптер выставляет `Capabilities` по фактической наблюдаемости: нет канала → `UNKNOWN`. Синтетическое трейс-событие эмитится ТОЛЬКО из реально наблюдённого сигнала, никогда из догадки. | PASS |
| V. Композит и external_effect | Формула композита и `external_effect`-оракул не меняются. `external_effect=True` только при подтверждённой утечке (FR-002/FR-004/FR-005). | PASS |
| VI. Офлайн mock | `adapters/mock.py` и его E2E не трогаются; новые тесты — офлайн (поддельные ответы/снимки), в CI без стенда. | PASS |
| VII. Коды возврата | `RunnerError` → `exit 1`; исчерпан бюджет N без success → `NOT_EXPLOITABLE` + `exit 0` (FR-006/FR-013). Разделение сохранено. | PASS |
| VIII. Типизированные dataclass | Обмен ролей — существующие dataclass; dict допустим только для сырых трейс-событий и сырых ответов стенда (ровно тот случай, что разрешает принцип). | PASS |

**Отступление от Assumptions спека, требующее фиксации:** спек в Assumptions заявляет «Ядро
(`core/`, `oracles/`) не меняется». FR-013 (early-exit по бюджету N) физически реализуется в цикле
`Campaign.run()` (`core/campaign.py`). Это НЕ нарушение конституции (Принцип III запрещает
*target-specific* ветвления, Принцип II — правки ядра *ради атаки*; early-exit — общая,
target-agnostic функция), но это отступление от буквы Assumptions. Оформлено в Complexity Tracking с
обоснованием и защитной мерой (конфиг-флаг, по умолчанию выключен → mock-демо и тесты не меняются).
`oracles/` не меняются вовсе.

**Правила Markdown/git (обязательные и для `specs/**`):** имена файлов ASCII (`plan.md`,
`research.md`, …), содержимое русское, ширина ≤100, ссылки относительные и резолвятся, коды возврата
и артефакты — по конституции. Ветка `001-live-target-reproduction` совпадает с каталогом `specs/`.

**Итог гейта:** нарушений нет; одно задокументированное отступление от Assumptions спека (не от
конституции) — в Complexity Tracking. Гейт пройден.

## Project Structure

### Documentation (this feature)

```text
specs/001-live-target-reproduction/
├── plan.md              # Этот файл (/speckit-plan)
├── research.md          # Phase 0: решения по каналам доказательства и адаптеру
├── data-model.md        # Phase 1: сущности и нормализованные схемы
├── quickstart.md        # Phase 1: как прогнать и провалидировать вручную
├── contracts/           # Phase 1: контракты адаптера, evidence-каналов, scenario YAML
│   ├── adapter-contract.md
│   ├── evidence-channels.md
│   └── scenario-live.schema.md
├── checklists/
│   └── requirements.md  # уже создан /speckit-specify
├── spec.md              # /speckit-specify
└── tasks.md             # Phase 2 (/speckit-tasks — НЕ создаётся этой командой)
```

### Source Code (repository root)

Правки локализованы. Файлы-аналоги (шаблон для новой работы) помечены `# аналог`.

```text
src/memnotsafe/
├── adapters/
│   ├── base.py                 # контракт TargetAdapter/Capabilities/SendResult — НЕ меняется
│   ├── mock.py                 # аналог: как адаптер эмитит трейс-события и snapshot — НЕ меняется
│   ├── openai.py               # аналог: живой httpx-адаптер (black-box) — НЕ меняется
│   └── investment_stand.py     # ОСНОВНАЯ ПРАВКА: нормализация памяти + evidence-каналы + capabilities
├── core/
│   ├── config.py               # уже поддерживает adapter=investment_stand — правок не требует
│   ├── campaign.py             # ТОЧЕЧНАЯ ПРАВКА: early-exit по бюджету N (FR-013), конфиг-флаг
│   ├── runner.py               # НЕ меняется
│   └── models.py               # НЕ меняется
└── oracles/                    # НЕ меняются (все шесть + composite)

scenarios/
├── cross_user_bac.yaml         # аналог: mock-сценарий главной атаки
├── cross_user_bac_protected.yaml  # аналог (mock): честный негатив (protected) — НЕ трогаем
├── cross_user_bac_live.yaml    # НОВЫЙ: тот же attack.family на живом таргете (ворота успеха)
└── <family>_live.yaml          # НОВЫЕ: остальные семейства на живой таргет (P2, покрытие)
°
tests/
├── test_all_attacks.py         # НЕ меняется (mock battery)
├── test_e2e_cross_user.py      # НЕ меняется (обязательный офлайн E2E)
└── test_investment_stand_adapter.py  # НОВЫЙ: офлайн-unit нормализации и каналов (без сети)
```

**Structure Decision**: single project, src-layout. Правки ложатся в один адаптер
([investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py)) плюс конфиг-управляемый
early-exit в [campaign.py](../../src/memnotsafe/core/campaign.py); новое поведение подключается
scenario YAML по образцу [cross_user_bac.yaml](../../scenarios/cross_user_bac.yaml). Оракулы, атаки,
runner, mock и их тесты остаются нетронутыми — как требует конституция.

## Complexity Tracking

> Заполняется только при отступлениях, требующих обоснования.

| Отступление | Зачем нужно | Почему простой путь отвергнут |
|-------------|-------------|-------------------------------|
| Правка `core/campaign.py`: early-exit по бюджету N (при том что Assumptions спека говорят «ядро не меняется») | FR-013 требует досрочного выхода при первом композитном success и `NOT_EXPLOITABLE` после N неудач; цикл повторов живёт только в `Campaign.run()` | Ранний выход нельзя сделать в адаптере (он не знает вердикта и не владеет циклом) и в атаке (Принцип I). Защита: флаг `metrics.stop_on_success` (default off) → mock-демо и существующие тесты неизменны (FR-011/SC-007); изменение target-agnostic, не нарушает Принципы II/III |
| Адаптер синтезирует трейс-события (`llm_decision`/`tool_result`) для чёрного ящика | Композит требует `adoption=True` и `external_effect=True`, а живой стенд не отдаёт внутреннюю трассу; оракулы читают только нормализованный словарь событий | Расширять оракулы под стенд запрещено (Принцип III, Assumptions спека). Честность (Принцип IV) сохранена жёстким правилом: событие эмитится только из реально наблюдённого evidence-канала, при отсутствии канала — `UNKNOWN` (не событие) |
