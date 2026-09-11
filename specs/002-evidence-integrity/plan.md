# Implementation Plan: Достоверность evidence-конвейера

**Branch**: `002-evidence-integrity` | **Date**: 2026-09-06 |
**Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-evidence-integrity/spec.md`

## Summary

Исправить порядок lifecycle (finalize → settle → новая trigger-сессия), вынести
сопоставление evidence в общую утилиту вне ядра (`evidence/matching.py`), ограничить
adoption/tool/effect триггерной фазой правильного principal'а, добавить regression-набор
на все известные ложные исходы (A01–A08). Композит и шесть стадий не изменяются.

## Technical Context

**Language/Version**: Python >=3.11 (проверено на 3.14)
**Primary Dependencies**: PyYAML, httpx; pymongo — optional extra (только adapter)
**Storage**: N/A (офлайн); опционально Mongo за адаптером
**Testing**: pytest, офлайн fake-адаптеры и fake-события
**Target Platform**: Windows + Linux, CLI
**Project Type**: library + CLI (`memnotsafe`)
**Constraints**: без сети, Docker, ключей; композит не меняется
**Scale/Scope**: `core/runner.py`, `oracles/{base,adoption,external_effect,tool}.py`,
новый `evidence/matching.py`, `adapters/investment_stand.py`, `tests/`

## Constitution Check

| Принцип | Решение | Gate |
|---|---|---|
| I. Роли | matching — утилита, используется oracle'ами; runner управляет порядком фаз | Нет new роли в runner |
| II. Атаки ≠ core | Это инфраструктурная фича: правки `core/runner.py` и `oracles/*` допустимы только здесь, в отдельной ветке/фиче с этим обоснованием | Нет атаки в этом diff |
| III. Ядро ≠ таргеты | Знание Mongo остаётся в `adapters/investment_stand.py`; matching не знает про Mongo | grep `mongo` в `core/`/`oracles/` пуст |
| IV–V. Tristate/composite | Формула и таблица стадий не меняются; только источники значений | Truth-table тесты зелёные |
| VI. Mock | Все новые тесты — офлайн fake; live не нужен | pytest без сети |
| VII. Exit codes | Execution error → exit 1, честный negative → exit 0 | CLI subprocess-тест |
| VIII. Dataclass | `EvidenceObservation`, `StageResult` — типизированные dataclass; legacy dict → converter на границе | Contract tests |
| SDD/Git | Ветка `002-evidence-integrity`, PR с этим specs-каталогом | Перед реализацией |

Brownfield-заметка: `core/runner.py` и `oracles/*` существуют; правки — не
переспецификация, а исправление достоверности существующего pipeline по аудиту
A01–A08. Границы изменения перечислены в Project Structure; всё, что требует нового
контракта, попадает в эту фичу, а не в attack-port.

## Project Structure

Реальное распределение стадий по файлам (сверено с кодом 2026-09-06; доп-замечание
аудита о «WRITE/PERSIST/RETRIEVE в base.py» снято — в `base.py` только контекст и
хелперы):

```text
src/memnotsafe/
  core/runner.py              # порядок фаз (A01), finally-закрытие СЕССИЙ (R3),
                              # settle; клиент НЕ закрывает (владелец — CLI/Campaign)
  oracles/memory.py           # write-стадия (через matching)
  oracles/persistence.py      # persistence-стадия
  oracles/retrieval.py        # retrieval-стадия
  oracles/adoption.py         # adoption: trigger-only, exposure, judge-хук (R6)
  oracles/tool.py             # call/result по call_id
  oracles/external_effect.py  # эффект по типу; snapshot ≠ cross-user proof
  oracles/base.py             # EvaluationContext; find_candidate_record делегирует
                              # в matching (API сохраняется)
  evidence/matching.py        # НОВЫЙ: нормализация + сопоставление, вне ядра
  evidence/__init__.py        # НОВЫЙ
  adapters/investment_stand.py, adapters/mock.py  # привязка к полям хранилища
tests/
  test_runner_lifecycle.py    # НОВЫЙ
  test_evidence_integrity.py  # НОВЫЙ
```

Владение клиентом (R3): сегодня `run_attack` не закрывает клиент, `cli.py`
закрывает `target.aclose()` в `finally` после всей кампании — это правильная
граница, сохраняется. Runner добавляет только гарантированное закрытие СОЗДАННЫХ
ИМ сессий.

## Complexity Tracking

Риск: переписать композит «по пути». Ограничение: дифф фичи не касается
`oracles/composite.py` (проверка — тест на неизменность формулы); переносимое знание —
только сопоставление и порядок фаз. A06 (`policy_evicted` adoption-ветка) НЕ входит
сюда — это оракул фичи 004 (T004-8, см. [задачи](tasks.md)). R4: маркер записи —
не «магическая вставка в payload»: подстановка только через явный плейсхолдер
`{case_marker}` шаблона атаки; legacy-сценарии без маркера не меняются
(round-trip тест обязателен). Связи requirement → task → test и открытые вопросы —
[analyze.md](analyze.md).

## Дельта плана: FIX-01 (T002-5b)

Отбор событий по фазе и principal'у — общий, а не по копии в каждом оракуле.
Файл-аналог — `oracles/base.py::find_candidate_record`: там уже принято, что общий
для оракулов выбор доказательства живёт в `base.py`, а стадии его только читают.
Тем же способом добавляется `oracles/base.py::trigger_events`, и ADOPT/TOOL/EFFECT
переходят с `ec.all_events` на него. Остальные стадии (WRITE/PERSIST/RETRIEVE)
продолжают читать исходный `all_events`: их доказательство — снимок памяти и трасса
жертвы, а не фаза диалога. `None` вместо пустого списка нужен, чтобы «контекст фаз
не передан» не сливалось с «событий не было»: первое обязано давать UNKNOWN (IV).

## Дельта плана: FIX-02 (T002-5c)

Пара «вызов → его результат» строится там же, где живёт отбор фазы, —
`oracles/base.py`; файл-аналог тот же `trigger_events` из FIX-01: общий выбор
доказательства принадлежит `base.py`, стадии его только читают. Ключ пары —
`(session_id, call_id)` при совпадении имени инструмента: `call_id` уже кладут на
верхний уровень события оба адаптера, поэтому Adapter в этой ветке не меняется
(и придумывать корреляцию в нём прямо запрещено). Недостоверная корреляция
возвращается отдельным полем `unreliable`, а не пустым списком пар: «пару
доказать нечем» обязано давать UNKNOWN, тогда как «инструмент не вызывался» —
прежний наблюдаемый факт трассы (IV). TOOL получает то же правило, оставаясь
диагностикой вне формулы composite (V).
