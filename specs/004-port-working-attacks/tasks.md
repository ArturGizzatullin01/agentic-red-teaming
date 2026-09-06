---

description: "Tasks for 004-port-working-attacks"
---

# Tasks: Перенос рабочих атак донора

**Input**: [plan.md](plan.md), [spec.md](spec.md). После gate фичи 003. Одна атака —
одно задание Flash + review GLM. Запрещён core-дифф.

## Phase 1: P1-атаки (по одной)

- [ ] T004-1 `attacks/procedural_graft.py` + `scenarios/procedural-graft.yaml`
  (донор: attacks/procedural_graft/pack.py).
- [ ] T004-2 `attacks/consent_laundering.py` + `scenarios/consent-laundering.yaml`
  (донор: attacks/consent_laundering/pack.py; двухходовая эlicit-схема).
- [ ] T004-3 `attacks/document_regulation_graft.py` + сценарии document-as-message и
  plain (global — после основного).
- [ ] T004-4 `attacks/cross_topic_smuggle.py` + сценарии user/global.
- [ ] T004-5 `attacks/tool_error_echo_poisoning.py` + `scenarios/tool-error-echo-poisoning.yaml`
  (direct; natural/natural2 — после основного).
- [ ] T004-6 для каждого T004-1..5: импорт/регистрация в `attacks/__init__.py`,
  расширение `tests/test_all_attacks.py` (positive/negative/insufficient-observation
  на поведенческом mock), protected-negative, original/effective channel в metadata.

## Phase 2: P2-экспериментальные (после оракулов)

- [ ] T004-7 GLM: cross-user oracles и тесты по контракту (ответ отдельного principal);
  затем Flash: `attacks/cross_user_scope_global.py` (strong, обе направленности).
- [ ] T004-8 GLM: `policy_evicted` adoption/effect-ветка + контрольный baseline;
  затем Flash: `attacks/policy_flood_eviction.py` (experimental).
- [ ] T004-9 Flash: zwsp (`unicode_tag_smuggle`) и conditional_risk_flag — после
  проверки исходников в донорском `disabled_attacks/`; статус experimental в metadata.

## Phase 3: gate

- [ ] T004-10 полный baseline + новые suites зелёные; core-дифф пуст; описание канала
  и варианта в README фичи; review этапа.

Семантика ролей: донор victim → команда attacker; донор witness → команда victim.
Донорские источники payload'ов: `attacks/<name>/pack.py` прототипа «тул хакатон»
(передаются кодеру отдельно, в репозиторий команды не копируются).
