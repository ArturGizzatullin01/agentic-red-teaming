# Implementation Plan: Cold start и выпуск

**Branch**: `005-cold-start-release` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

## Summary

Собрать wheel, обеспечить чистый офлайн-запуск на mock (Windows/Linux), оформить
документацию и live example-профили, перенести исторические результаты как
manifest/агрегат, провести live-протокол на отдельном стенде и финальный аудит по
[acceptance.md](../../docs/integration-handoff/acceptance.md).

## Technical Context

**Language/Version**: Python >=3.11; **Dependencies**: setuptools build, без новых
runtime-зависимостей; **Testing**: pytest + subprocess CLI; **Platform**: Windows/Linux;
**Constraints**: офлайн-исполнение демо без сети/ключей; live — только отдельный стенд.

## Constitution Check

| Принцип | Решение | Gate |
|---|---|---|
| I–V | Нет кодовых изменений ядра/оракулов в этой фиче; только упаковка, доки, скрипты, fixtures | diff не трогает src/ логику |
| VI. Mock | Демо-сценарии используют поведенческий mock (vulnerable/protected) | Offline gate |
| VII. Exit codes | Документируются и тестируются через CLI subprocess | Acceptance |
| VIII. Dataclass | Прогон provenance в примерах отчётов | Пример report |
| SDD/Git | Ветка `005-cold-start-release`; generated runs/reports не коммитятся | git status |
| Git-атрибуция | Коммиты исполнителя — только после ратифицированной поправки атрибуции (см. [черновик](../../docs/amendments/agent-attribution-trailer.md)) | Перед первым коммитом |

## Project Structure

```text
pyproject.toml           # метаданные wheel (обновление, не переписывание)
README.md                # установка/запуск Windows+Linux, ENV-матрица
.env.example             # имена ENV с пустыми значениями
scenarios/*-live.yaml    # live-профили (порты, identities, без секретов)
docs/historical/         # manifest + агрегат донора (заявления источника)
tests/test_cli_exit_codes.py (если отсутствует)
```

## Complexity Tracking

Риск: «из коробки» засчитать по старому smoke-донора. Ограничение: чистая установка
воспроизводится заново в этой фиче; исторический smoke — заявление источника, не
доказательство. Риск: live-профиль поощряет общий reset БД. Ограничение: только
отдельный compose-проект; identity 1001/1002; восстановление по контракту 003.
