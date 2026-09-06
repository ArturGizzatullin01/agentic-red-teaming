# Data Model: 002-evidence-integrity

**Created**: 2026-09-06. Исправлено по аудиту R1 (2026-09-06): контракт
`StageResult` сохраняет существующий wire-формат команды; новые сущности вводятся
только converter'ом на границе. Окончательная сверка имён — с
`src/memnotsafe/core/models.py`.

## Существующие сущности (НЕ менять wire-формат)

### StageResult — как в `core/models.py`

- `stage: str` — нижний регистр, канонические имена: `write`, `persistence`,
  `retrieval`, `adoption`, `tool`, `external_effect` (ровно их читают композит и
  reporting).
- `success: StageVerdict` = `bool | None`; `None` = UNKNOWN. В JSON — `null`
  (строка "unknown" в wire ЗАПРЕЩЕНА: `campaign.json`/report и `replay` читают
  `success` как bool|null).
- `evidence: list[dict]` — сырые свидетельства (dict допустим по конституции VIII:
  сырые события/ответы).
- `confidence: float`, `reason: str` — сохраняются в dataclass. В wire
  (`_campaign_to_dict`) сейчас попадают только `stage/success/reason/evidence`;
  добавление `confidence` в wire — аддитивная правка сериализации, отдельной
  миграции схемы не требуется.
- **Round-trip тест обязателен**: `StageResult` → JSON (campaign.json) → `report`
  → повторное чтение (`cli.py cmd_report`) — для success = True, False и None
  (null не превращается ни в False, ни в "unknown").

### StageVerdict

Алиас `bool | None` уже существует в `core/models.py` — использовать его, не
вводить синонимы (`status`, `tristate` и т.п. запрещены).

## Новые сущности фичи (только через converter на границе)

### EvidenceObservation (dataclass)

Наблюдение одного свидетельства: `run_id`, `case_id`, `phase` (delivery | settle |
trigger), `principal: str | None` (None = unknown — не заполняется догадкой),
`session_id`, `source` (memory_diff | context | answer | tool_call | tool_result |
external_record), `record_id` или `call_id`, `observed_at`, `raw_value`,
`matched_value`, `match_method`. Попадает в `StageResult.evidence` через явный
`to_evidence_dict()` converter (сырой dict на границе — допустим).

### CaseMarker (dataclass)

`token: str` (непустой, формат `CM-<6 hex>` из case_id), `case_id`. Семантика и
передача — [контракт](contracts/evidence-and-verdict.md) и [спека](spec.md)
(замечание R4): producer — runner, подстановка — только через плейсхолдер
`{case_marker}` в шаблоне атаки; отсутствие маркера = legacy-путь (поведение не
меняется).

## Инварианты

- Композит (`oracles/composite.py`) не изменяется: `is_true()` по именам стадий,
  особый статус UNKNOWN только у `retrieval` (единственное UNKNOWN, допускаемое
  формулой success; остальные стадии тоже могут быть UNKNOWN — но формула их не
  пропускает).
- `raw_value` никогда не подменяется нормализованным; нормализованное — отдельное
  поле `matched_value`/`match_method`.
- Имена стадий в matching-утилите — те же строки lowercase, что и в существующих
  oracle-файлах (`oracles/memory.py`, `persistence.py`, `retrieval.py`,
  `adoption.py`, `tool.py`, `external_effect.py`).
