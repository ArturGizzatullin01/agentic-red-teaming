# Implementation Plan: Runtime-профили ролей и provenance

**Branch**: `003-runtime-profiles` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

## Summary

Типизированные профили ролей с precedence CLI → scenario → default; runtime-генерация
как отдельный async-сервис вне ядра; judge bridge со structured output; операторская
утилита смены target с recreate/readback/sanity/restore; provenance во всех форматах
отчётов. Инфраструктурная фича — правки `core/` допустимы здесь и только здесь до
attack-port.

## Technical Context

Дополнение 2026-09-06: [пресеты и локальная панель](contracts/launch-presets.md).
Сначала единый resolver и запуск профиля через CLI, затем тонкая локальная панель
с двумя селекторами, фиксированным DeepSeek-судьёй и карточками пресетов.
Модель стенда переключается существующим
wrapper; UI не реализует собственные атаки, судейство или Docker-операции.
Выбор UI-стека — после clarify/analyze; новых зависимостей на стадии плана нет.
Текущие T003-1/2/6/8 уточняются этим контрактом, задачи T003-9–12 добавлены ниже
в tasks. Совпадение модели в разных ролях не считается конфликтом ролей.

**Language/Version**: Python >=3.11; **Dependencies**: PyYAML, httpx (есть),
pymongo — optional; **Storage**: N/A; **Testing**: pytest, fake transports/process
runner; **Platform**: Windows/Linux CLI; **Type**: library + CLI;
**Constraints**: judge/target независимы от выбора attacker; без Docker-логики в core.

## Constitution Check

| Принцип | Решение | Gate |
|---|---|---|
| I. Роли | Генерация = сервис (роль Attack «ЧТО»); runner вызывает до доставки; утилита target — вне runner/adapter | Нет HTTP в AttackBase |
| II. Атаки ≠ core | Это инфраструктурная фича (обоснование в Complexity Tracking); attack-port после неё | Дифф не трогает attacks/ |
| III. Ядро ≠ таргеты | set_stand_target — операторская утилита (`scripts/`), Mongo/compose знание не попадает в `core/` | grep `docker\|compose` в src/memnotsafe/core пуст |
| IV–V. Tristate/composite | Judge bridge отдаёт структурированную оценку стадии; композит не меняется | Truth-table тесты |
| VI. Mock | Все тесты на fake transport/process runner; live не нужен | pytest офлайн |
| VII. Exit codes | Config/provider ошибки → exit 1 до reset/delivery | subprocess тест |
| VIII. Dataclass | `RoleProfile`, `RunProvenance`, `ResolvedConfig` — dataclass; legacy конвертер на границе чтения config | Contract tests |
| SDD/Git | Ветка `003-runtime-profiles`, PR вместе с specs/003-* | Перед реализацией |

## Project Structure

```text
src/memnotsafe/
  core/models.py      # RoleProfile, RunProvenance, ResolvedConfig (+ legacy converter)
  core/config.py      # загрузка profiles, precedence, validation
  core/runner.py      # точка подключения генерации (вызов сервиса, static fallback)
  generation/         # НОВЫЙ пакет: provider transport, attacker service
  oracles/adoption.py # judge bridge (structured output, retries)
  reporting/*.py      # provenance в json/html/metrics; report/replay
scripts/
  set_stand_target.py # операторская утилита: явный stand path, readback, restore
tests/
  test_role_profiles.py, test_target_switch.py, test_provenance.py
```

Аналог: существующие `core/models.py` и `reporting/` — расширение совместимо;
услуга генерации создаётся рядом, `AttackBase` не получает async методов.

## Complexity Tracking

Риск: спрятать runtime-LLM в sync `AttackBase.generate` (A10). Решение: сервис
вызывается runner'ом до шагов доставки; Attack остаётся описанием.
Риск 2: `set_stand_target` превратить в действие атаки. Решение: утилита вне пакета,
без runner-интеграции; wrapper-семантика «apply → readback → sanity → кампания →
restore в finally» (R2) — кампания реально идёт под новой моделью, состояние
восстанавливается после неё, включая падение кампании.
Риск 3: judge-зависимость вердикта. Решение (R6): одна async-фаза «judge
annotations» ДО sync `evaluate_all`; sync оракулы получают готовые аннотации через
существующий sync-хук; композит — единственное место success; timeout → UNKNOWN.
Риск 4: R5-нумерация. Канонические ID задач фичей — `T00N-M`; соответствие старым
ID handoff зафиксировано в [analyze.md](../analyze.md).
