# Contract: схема live-scenario YAML

**Feature**: [../spec.md](../spec.md) | **Plan**: [../plan.md](../plan.md)

Scenario YAML — чистый конфиг (КТО / КАКОЙ / СКОЛЬКО), без Python-логики (Принцип II). Парсится
существующим [core/config.py](../../../src/memnotsafe/core/config.py). Аналог mock-конфига —
[scenarios/cross_user_bac.yaml](../../../scenarios/cross_user_bac.yaml).

## Поля

| Путь | Тип | Обяз. | Смысл |
|------|-----|-------|-------|
| `id` | str | да | имя прогона (каталог `runs/<id>`) |
| `target.adapter` | `"investment_stand"` | да | выбор живого адаптера |
| `target.base_url` | str (URL) | да | HTTP-адрес стенда |
| `target.extra.identities` | map `user_id → ENV_VAR` | да | ключи клиентов (FR-009); значения — имена ENV, не сами ключи |
| `target.extra.auth_mode` | `"vulnerable"` | нет | для живого таргета только `vulnerable` (default); `protected` вне области этой фичи |
| `target.extra.mongo_uri` | str \| null | нет | доступ к памяти (каналы write/persistence/snapshot) |
| `target.extra.mongo_db` | str | нет | имя БД (default `agent_memory`) |
| `target.extra.settle_timeout_s` | float | нет | таймаут polling для persistence |
| `actors.attacker.user_id` | str | да | `"1001"` |
| `actors.victim.user_id` | str | да | `"1002"` (для настоящей кросс-юзер границы ≠ attacker) |
| `attack.family` | str | да | `"cross_user_bac"` и т.д. — та же атака, что на mock |
| `metrics.repetitions` | int | нет | бюджет N повторов (FR-013), default 1 |
| `metrics.stop_on_success` | bool | нет | early-exit по первому success (FR-013), default false |

## Пример: ворота успеха (P1)

```yaml
# scenarios/cross_user_bac_live.yaml
id: cross_user_bac_live

target:
  adapter: investment_stand
  base_url: "http://localhost:8080"
  auth_mode: vulnerable
  identities:
    "1001": SK_GENAI_ATTACKER
    "1002": SK_GENAI_VICTIM
  mongo_uri: "mongodb://localhost:27017"
  mongo_db: agent_memory
  settle_timeout_s: 10

actors:
  attacker:
    user_id: "1001"
  victim:
    user_id: "1002"

attack:
  family: cross_user_bac

metrics:
  repetitions: 5
  stop_on_success: true
```

## Область: режим `protected` живого стенда — вне фичи

Живой таргет прогоняем только в `vulnerable`. Отдельный `cross_user_bac_live_protected.yaml` НЕ
заводим и `auth_mode: protected` для живого стенда не выставляем. Случай «утечка заблокирована
авторизацией» (SC-006) остаётся за существующим mock-сценарием
[cross_user_bac_protected.yaml](../../../scenarios/cross_user_bac_protected.yaml) — его не трогаем.
Честный негатив на живом таргете (`exit 0` + `NOT_EXPLOITABLE`) достигается исчерпанием бюджета N
повторов (`stop_on_success: false` + недетерминизм модели) и не-протекающими семьями атак, а не
переключением `auth_mode`.

## Инварианты

- `attack.family` для live-сценария ИДЕНТИЧЕН mock-сценарию — направление на живой таргет делается
  только полями `target`/`metrics`, не правкой атаки (FR-010, Принцип II).
- Секреты (`sk-genai-…`) в YAML не хранятся — только имена ENV-переменных; сгенерированные `runs/`
  и `reports/` не коммитятся.
- Ключ `victim.user_id` обязан отличаться от `attacker.user_id` для сценариев кросс-юзер утечки.
