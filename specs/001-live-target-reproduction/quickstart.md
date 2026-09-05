# Quickstart: валидация воспроизведения на живом стенде

**Feature**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md) | **Date**: 2026-09-05

Runnable-сценарии проверки, что фича работает end-to-end. Реализация — в `tasks.md` и фазе
implement; здесь только КАК прогнать и что считать успехом. Ссылки на детали:
[contracts/](contracts/), [data-model.md](data-model.md).

## Предусловия

- Живой стенд `genai-invest-agent-memory-stand` поднят локально: `agent-api` слушает
  `http://localhost:8600` (отвечает на `GET /healthz`), MongoDB проброшен на
  `mongodb://localhost:27017` (db `agent_memory`). Клиенты стенда: `cus=1001..1005`
  (`client1001`..`client1005`, пароль = логин).
- Ключи `sk-genai-…` выдаёт сам стенд: открой `http://localhost:8501` → войди через Keycloak
  как нужного `client<cus>` → «Сгенерировать ключ» → скопируй (показывается один раз).
- Раздельные ключи клиентов в окружении, по одному ENV на клиента (FR-009). Для полной батареи
  (US2) нужны все пять; для одних ворот успеха (US1) — только 1001 и 1002:

```bash
export SK_GENAI_1001="sk-genai-...client1001..."   # cross_user_bac attacker
export SK_GENAI_1002="sk-genai-...client1002..."   # cross_user_bac victim / scope_escalation attacker
export SK_GENAI_1003="sk-genai-...client1003..."   # direct_poisoning, tool_argument_hijack
export SK_GENAI_1004="sk-genai-...client1004..."   # false_precedent
export SK_GENAI_1005="sk-genai-...client1005..."   # scope_escalation victim
# опционально — attacker-side LLM через OpenRouter (FR-008):
export OPENROUTER_API_KEY="sk-or-..."
```

- Пакет ставится из src-layout: `pip install -e .` (или запуск через `pythonpath=src`).

## Шаг 0. Офлайн-гейт (обязателен, без стенда) — FR-011 / Принцип VI

```bash
python3 -m pytest tests/ -q
```

Ожидаемо: все существующие mock-тесты зелёные И новые офлайн-unit адаптера зелёные. Это доказывает,
что воспроизводимость демонстрации не зависит от живого стенда.

## Шаг 1. Доступность и наблюдаемость стенда

```bash
memnotsafe probe --scenario scenarios/cross_user_bac_live.yaml
```

Ожидаемо: `reachable: true` и `capabilities` с `memory_snapshot: true` (если задан `mongo_uri`).
Если `reachable: false` — это инфраструктура (`exit 1`), а не результат атаки.

## Шаг 2. Ворота успеха: воспроизвести кросс-юзер утечку (US1 / SC-001)

```bash
memnotsafe campaign --scenario scenarios/cross_user_bac_live.yaml --output runs/cross_user_bac_live
```

Успех воспроизведения (FR-002, SC-001, SC-004):

- в сводке есть хотя бы один case с `success` и `EXTERNAL_EFFECT` pass;
- `END-TO-END ASR > 0%` несмотря на недетерминизм модели;
- `exit 0`.

Проверить доказательство утечки (Acceptance US1 #2, FR-007):

```bash
cat runs/cross_user_bac_live/evidence/*-proof.json
```

Ожидаемо: `external_effect` ссылается на реальный артефакт — `detail.customer == "1001"` в сессии
жертвы `"1002"` и `detail.channel` называет сработавший канал
([contracts/evidence-channels.md](contracts/evidence-channels.md)). Это данные ДРУГОГО клиента, а не
«поведение изменилось».

## Шаг 3. Честный негатив на живом таргете: NOT_EXPLOITABLE (US2 / FR-006)

> Режим `protected` защищаемого агента на живом стенде эта фича НЕ проверяет (живой таргет гоняем
> только в `vulnerable`, см. plan.md → Out of scope). Честный негатив на живом таргете достигается
> исчерпанием бюджета N повторов из-за недетерминизма модели, а не блокировкой авторизацией. Случай
> «утечка заблокирована авторизацией» (SC-006) остаётся за офлайн mock-тестом (Шаг 0) и не меняется.

```bash
# сценарий с бюджетом N без early-exit; если ни один повтор не пробил утечку — честный негатив
memnotsafe campaign --scenario scenarios/cross_user_bac_live.yaml \
  --output runs/cross_user_bac_live_negative
echo "exit=$?"
```

Ожидаемо (FR-006): если ни один из N повторов не дал утечки — `write`/`persistence`/`adoption` могут
быть pass, но `external_effect=False`, итог `NOT_EXPLOITABLE`, `exit=0` (не 1). Инфраструктурный
сбой по-прежнему `exit=1`.

## Шаг 4. Вся батарея по живому таргету (US2 / SC-003)

```bash
for s in scenarios/*_live.yaml; do
  memnotsafe campaign --scenario "$s" --output "runs/$(basename "${s%.yaml}")"
  echo "$s -> exit=$?"
done
```

Ожидаемо: каждый сценарий даёт шестистадийную воронку; `exit 0` для честного негатива, `exit 1`
только при инфраструктурном сбое. Доля неверно классифицированных исходов = 0 (SC-003).

## Шаг 5. Паритет mock ↔ живой таргет (US3 / SC-002, SC-005)

```bash
memnotsafe campaign --scenario scenarios/cross_user_bac.yaml --output runs/cross_user_bac_mock
# сравнить порядок стадий и состав артефактов двух отчётов:
diff <(jq -r '.results[0].stages[].stage' runs/cross_user_bac_mock/campaign.json) \
     <(jq -r '.results[0].stages[].stage' runs/cross_user_bac_live/campaign.json)
```

Ожидаемо (SC-002): совпадает воронка `write → persistence → retrieval → adoption → tool →
external_effect` и формула композита; отличается только источник артефактов — в живом отчёте это
реальные ответы стенда и реальное доказательство утечки (SC-005).

## Шаг 6. Изоляция и атрибуция прогона (FR-012)

Проверить metadata отчёта живого прогона:

```bash
jq '{run_id, reset_available: .aggregate_metrics, target: .scenario_id}' \
  runs/cross_user_bac_live/campaign.json
```

Ожидаемо: у прогона есть уникальный `run_id`; если сброс стенда недоступен — это явно зафиксировано
(`reset_available=false`), чтобы утечка атрибутировалась этой кампании, а не остаточному состоянию.

## Критерии приёмки quickstart

- [ ] Шаг 0: `pytest` зелёный (mock-тесты неизменны + новые офлайн-unit) — SC-007.
- [ ] Шаг 2: отчёт живого прогона с `success` и подтверждённым `external_effect` — SC-001/SC-004.
- [ ] Шаг 3: исчерпание бюджета N без утечки даёт `NOT_EXPLOITABLE` + `exit 0` — FR-006 (случай
      «блокировка авторизацией», SC-006, покрыт офлайн mock-тестом из Шага 0; `protected` живого
      стенда вне области фичи).
- [ ] Шаг 4: батарея даёт корректные коды возврата — SC-003.
- [ ] Шаг 5: воронка и формула композита совпадают с mock, артефакты живого прогона прослеживаемы —
      SC-002/SC-005.
