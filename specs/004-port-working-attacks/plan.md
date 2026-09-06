# Implementation Plan: Перенос рабочих атак донора

**Branch**: `004-port-working-attacks` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

## Summary

Порт пяти P1-атак и экспериментальных (P2) из донора на контракты команды: файл атаки
+ scenario YAML + тесты на поведенческом mock. Никаких правок `core/`; потребность в
новом контракте возвращается в SDD-инфраструктуру (фичи 002–003).

## Technical Context

**Language/Version**: Python >=3.11; **Dependencies**: без новых; **Testing**: pytest,
офлайн mock; **Platform**: Windows/Linux; **Type**: библиотека атак; **Constraints**:
sync AttackBase, регистрация по family, YAML-конфиг.

## Constitution Check

| Принцип | Решение | Gate |
|---|---|---|
| I. Роли | Атака описывает шаги; runner исполняет; oracle судит | Attack не импортирует adapter/runner |
| II. Атаки ≠ core | Абсолютный запрет core-диффа в этой фиче | `git diff --stat -- src/memnotsafe/core oracles` пуст |
| III. Ядро ≠ таргеты | Атаки не знают про Mongo/Docker; канал — через adapter контракт | grep стенд-имён в attacks/ пуст |
| IV–V. Tristate/composite | ExpectedEffect заполняется под существующий композит; success считает только composite | Тест: no direct success |
| VI. Mock | Поведенческий mock: уязвимый/защищённый режим для каждой техники | Protected-negative тесты |
| VII. Exit codes | negative → exit 0; ошибка → exit 1 | CLI тесты |
| VIII. Dataclass | ExpectedEffect — типизированные варианты (tool: argument/value); не dict-мешок | Contract tests |
| SDD/Git | Ветка `004-port-working-attacks`; одна атака — одно задание Flash + review GLM | Порядок T015–T023 |

## Project Structure

```text
src/memnotsafe/attacks/
  procedural_graft.py  consent_laundering.py  document_regulation_graft.py
  cross_topic_smuggle.py  tool_error_echo_poisoning.py
  cross_user_scope_global.py (P2)  policy_flood_eviction.py (P2)
  unicode_tag_smuggle.py (P2, zwsp)  conditional_risk_flag.py (P2)
scenarios/
  procedural-graft.yaml  consent-laundering.yaml
  document-regulation-graft.yaml (+ plain/global)
  cross-topic-smuggle.yaml (+ user/global)
  tool-error-echo-poisoning.yaml
tests/test_all_attacks.py (расширение)
```

Аналог (обязателен по конституции): `src/memnotsafe/attacks/cross_user_bac.py` +
`scenarios/cross_user_bac.yaml` + `tests/test_all_attacks.py` — шаблон структуры,
регистрации и тестов. Донорские pack.py — источник payload/шагов, не архитектуры.

## Complexity Tracking

Риск: дублировать донорскую архитектуру (стратегии, verdicts) внутри атак. Ограничение:
переносится только ЧТО (payload, шаги, маркеры, варианты); КАК (matching, lifecycle,
профили) живёт в командах 002–003. Donor-only механики (StaticPayloadStrategy,
RetrievalOptimizedStrategy, канареечная фабрика) не переносятся без потребности;
natural/natural2 варианты tool-echo — после основного direct-порта.
