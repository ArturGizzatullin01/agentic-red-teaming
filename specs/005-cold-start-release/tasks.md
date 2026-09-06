---

description: "Tasks for 005-cold-start-release"
---

# Tasks: Cold start и выпуск

**Input**: [plan.md](plan.md), [spec.md](spec.md). После основных T004-1…T004-6
фичи 004 (нумерация — [analyze.md](../analyze.md)).

## Phase 1: упаковка и документация

- [ ] T005-1 `pyproject.toml`: сверить метаданные для wheel (scripts entry point,
  optional extras); собрать `python -m build`; тест установки wheel в чистое venv
  вне src-checkout (Windows).
- [ ] T005-2 `README.md`: установка (Windows/Linux), опциональный Mongo extra,
  офлайн-демо команда, ENV-матрица (что требуется когда), поведение при missing ENV.
- [ ] T005-3 `.env.example` (имена с пустыми значениями) и live example scenarios
  (отдельный стенд, порты, identities 1001/1002, без секретов).

## Phase 2: история и чистота

- [ ] T005-4 исторический manifest/агрегат в `docs/historical/` (заявления источника,
  пометка о смешанных целях); findings → `reporting/findings.py` с сохранением
  historical status; fixtures очищены, raw не коммитится; секрет-скан поставки.

## Phase 3: проверка выпуска

- [ ] T005-5 чистая установка + пять основных сценариев; protected mode; UNKNOWN;
  report/replay без исходного донора (Windows; Linux — второе окружение).
- [ ] T005-6 live-протокол: отдельный локальный стенд, фиксированный профиль, n>=5 на
  каждую основную атаку; cross-user/flood n>=10 при включении в демонстрацию; агрегат
  по [acceptance.md](../../docs/integration-handoff/acceptance.md) (Wilson 95%).
- [ ] T005-7 GLM: итоговый аудит по приёмке; отчёт о readiness (offline-ready /
  live-ready / blockers), остаточных дефектах и фактически выполненных командах;
  PR после quality gate.

Экспериментальные T004-7…T004-9 (фича 004) не блокируют релиз и не объявляются
доказанными, если отложены.
