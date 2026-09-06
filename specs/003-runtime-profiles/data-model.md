# Data Model: 003-runtime-profiles

**Created**: 2026-09-06. Целевые контракты: [roles](contracts/roles-and-provenance.md),
[target-switch](contracts/target-switch.md).

## Сущности

### RoleProfile (dataclass)

`preset_id`, `role` (attacker | judge — ТОЛЬКО LLM-роли), `provider`, `model`,
`base_url`, `api_key_env`, `timeout_s`, `max_output_tokens`, `retry_limit`,
`provider_options` (явный белый список, напр. `reasoning_effort`), `active: bool`.
Static attacker и неиспользуемый judge → `active=False`.

### TargetProfile (dataclass) — выделен по замечанию аудита

Целевой стенд — не LLM-роль, поэтому не `RoleProfile`: `profile_id`,
`compose_project_path` (путь к отдельному compose-проекту), `requested_model`,
`readback_model: str | None` (None = readback недоступен — запрошенная модель НЕ
пишется как фактическая), `allowed_identities` (1001/1002), `port_plan`,
`auth_mode_ref`, `adapter` (имя адаптера команды). Источник значений — профиль
фичи 003 / сценарий, не секретный live-конфиг.

### ResolvedConfig (dataclass)

Итог конфигурации кампании: requested/resolved `RoleProfile` для attacker и judge,
`TargetProfile` для цели, effective channel, режим auth. Сравнение активных LLM-ролей
— по паре resolved provider/model, не по alias; target сверяется по readback.

### RunProvenance (dataclass)

`schema_version`, `source_revision`, `seed`, `variant`, `scenario_hash`,
`candidate_hash`, requested/resolved модели трёх ролей, `stand_revision`,
`effective_channel`, `auth_mode`, `evidence_capabilities`, времена (start/end),
`execution_status` (completed | execution_error | interrupted). Сериализуется во все
форматы отчётов и переживает replay без изменений.

### SwitchRecord (dataclass, утилита target)

`requested_model`, `readback_model | None`, `sanity_ok`, `restore_status`
(restored | failed с фактическим состоянием), `backup_path` (именованный),
`campaign_command` (argv), `campaign_exit_code: int | None` (None = кампания не
запускалась: readback/sanity блокировка), `errors: list[str]` (обе ошибки при
двух сбоях).

## Инварианты

- Смена attacker не меняет judge/target (проверяется в provenance тесте).
- Запрошенная модель не записывается как фактическая без readback.
- Ключи — только имена ENV; в provenance/отчётах значений нет.
