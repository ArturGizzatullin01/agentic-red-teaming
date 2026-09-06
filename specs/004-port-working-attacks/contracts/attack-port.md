# Контракт: attack-port (004)

**Created**: 2026-09-06. Источник — [контракты интеграции](../../../docs/integration-handoff/contracts.md),
раздел «Доставка атак».

## Форма атаки

- Класс в `src/memnotsafe/attacks/<name>.py`, наследник `AttackBase`: методы
  `generate`, `delivery_steps`, `trigger_steps`, `expected_effect`; регистрация по
  `metadata.family` через `__init_subclass__`; уникальные id/family, duplicate → error.
- Scenario YAML — чистый конфиг (КТО/КАКОЙ/СКОЛЬКО): target, scenario-параметры,
  вариант; логика в YAML не живёт.

## Соответствие каналов

| Донорский канал | На командной базе | metadata |
|---|---|---|
| user_query | user_message | effective_channel=user_message |
| document (текст в реплике) | user_message | original=document, effective=user_message |
| tool_output (эхо ошибки тула) | user_message (эмуляция) | original=tool_output, effective=user_message |
| memory / web | не портируется в P1 | — |

## Варианты релиза

| Семейство | Приоритет | Варианты |
|---|---|---|
| procedural_graft | P1 | базовый, новый trigger session |
| consent_laundering | P1 | базовый |
| document_regulation_graft | P1 | document-as-message, plain; global после |
| cross_topic_smuggle | P1 | user, global |
| tool_error_echo_poisoning | P1 | direct; natural/natural2 после |
| cross_user_scope_global | P2 | strong, 1001↔1002 |
| policy_flood_eviction | P2 | experimental после новых oracles |
| unicode_tag_smuggle | P2 | только zwsp |
| conditional_risk_flag | P2 | после проверки исходника |

## Запреты

- Payload/маркеры/шаги — из донорских pack.py; новые техники в порту не конструируются.
- Attack не вызывает adapter/HTTP/Docker/Mongo; `core/` не меняется.
- Ключи в YAML запрещены; провайдер-специфика — только через RoleProfile (003).
