# Implementation Plan: перенос без смешения слоёв

**Date**: 2026-09-06. **Spec**: [spec.md](spec.md).

## Summary

Сначала исправить достоверность общего pipeline, затем подключить runtime профили,
после этого переносить атаки на стабильные контракты. Это улучшение порядка исходного ТЗ.
Каждый этап проходит specify → clarify → plan → tasks → analyze → implement.
Данный документ не подменяет фактические результаты этих команд.

## Technical Context

Python >=3.11; текущие зависимости команды — PyYAML и httpx, Mongo — optional extra.
Сохраняются src-layout, asyncio runner, sync AttackBase, pytest, существующие reporters.
Новый web UI, LangChain и второе async-ядро не нужны.

## Constitution Check

| Принцип | Решение | Gate |
|---|---|---|
| I: роли | Attack описывает, adapter исполняет, runner упорядочивает | Проверять на каждом diff |
| II: атаки не меняют core | Инфраструктура отдельно, attack-port после неё | Запрет core diff в attack-port |
| III: target independence | Mongo и Docker остаются за адаптером/операторской утилитой | Нет target-specific runner веток |
| IV–V: tristate/composite | Формула неизменна; judge только вспомогательный | Truth-table и негативные тесты |
| VI: mock | Поведенческий offline mock, защищённый режим | CI без внешних сервисов |
| VII: exit codes | Ошибка 1, отрицательный verdict 0 | CLI subprocess tests |
| VIII: dataclass | Новые контракты типизированы, legacy conversion на границе | Contract tests |
| SDD/Git | Отдельные фичи и PR, без main | Проверка перед реализацией |

Абсолютный запрет правок ядра в attack-port соблюдается. Для инфраструктурной фичи
GLM должен зафиксировать применимость brownfield-правила и границы изменения.
Если требуется исключение, записать Complexity Tracking и отдельную поправку;
не объявлять gate зелёным автоматически. Поправка атрибуции GLM нужна до его коммитов.

## Project Structure

Предлагаемые каталоги Spec Kit; номера проверить в актуальном репозитории до создания:

```text
specs/002-evidence-integrity/
specs/003-runtime-profiles/
specs/004-port-working-attacks/
specs/005-cold-start-release/
```

Каждый содержит `spec.md`, `plan.md`, `tasks.md`, `research.md`, `data-model.md`,
`quickstart.md`, `contracts/`, `checklists/` по шаблонам команды.
Имена веток Spec Kit совпадают с каталогами согласно конституции команды.
В рабочей копии аналитика ветки и коммиты не создавались.

## Архитектурные решения

1. Аналог атаки — `src/memnotsafe/attacks/cross_user_bac.py`, `attacks/base.py`,
   `scenarios/*.yaml`, `tests/test_all_attacks.py`. Только порт payload/шагов,
   не копирование `core/` донора. Импорт модуля нужен для регистрации.
2. Изменения lifecycle общие: finalize delivery, bounded settle, trigger в новой сессии,
   закрытие всех созданных сессий и клиента в finally. Baseline также закрывается.
3. Сопоставление evidence — общая утилита вне ядра, например `evidence/matching.py`.
   Привязка к Mongo-полям — только `adapters/investment_stand.py`.
4. Runtime генерация — отдельный типизированный сервис вне AttackBase.
   Runner вызывает async сервис до доставки, затем передаёт готовый candidate в шаги.
   Статический путь использует текущий generate. Не применять asyncio.run внутри loop.
   Сервис реализует ответственность Attack «что», а не управляет таргетом.
5. CLI/config загружают role presets; новые типы — рядом с текущими models.
   Никакой Docker/Mongo логики в core. Общая точка подключения оформляется в 003.
6. Смена target — операторская утилита, не действие атаки. Утилита принимает путь к
   отдельному compose-проекту, проверяет исходную конфигурацию, применяет профиль,
   проверяет фактическую модель и восстанавливает исходное состояние после эксперимента.
7. Existing reporters расширяются provenance совместимо, включая report/replay.
   Отдельный формат «успеха донора» не становится вторым источником verdict.

## Complexity Tracking

Главный риск — превратить перенос атак в скрытую перестройку ядра. Ограничение:
общий pipeline и профили в 002/003, в 004 только атаки, сценарии, тесты и документация.
Типизированный ExpectedEffect вводится отдельно с legacy converter; массовая миграция
старых словарей, не нужных интеграции, не входит в работу.
