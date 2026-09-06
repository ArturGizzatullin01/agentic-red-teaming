# Feature Specification: 005-attack-integration (конкретный объём пакета 2026-09-06)

**Владелец**: Андрей · **Статус**: реализовано в объёме пакета, единое ревью впереди
**Input**: решение пользователя о двухчасовом самостоятельном пакете; draft
.agent-work/spec-realignment/005-attack-integration/; inventory прототипа.

## Scope пакета
- Очередь 1 (обязательная): document_regulation_graft (doc/plain/global),
  cross_topic_smuggle (user/global), tool_error_echo_poisoning (direct;
  natural/natural2 — blocked-by-tool-loop).
- Очередь 2: fake_shared_past, contact_supersede, cross_lingual_insertion,
  recommendation_hijack, system_log_impersonation.
- Каноническая матрица всех 28 + 2 набора мутаций + архив 17.
- Подготовка сценариев/телеметрии для будущего 006-benchmark (без запуска live).

## Requirements
- FR-1: перенос механизмов файлами AttackBase без core-диффа; payload/ходы
  донора сохраняются; роли donor victim→attacker, witness→victim.
- FR-2: отклонения от донора фиксируются в docstring атаки и матрице
  (порядок триггеров mock-NLU, case-marker в записываемой реплике, mock-модель).
- FR-3: offline-триада на каждую семью (positive / write-UNKNOWN без
  snapshot / negative на чистой памяти) + вариантная изоляция между кейсами.
- FR-4: матрица со стадиями статуса (изучен/портирован/registry+CLI/
  offline-триада/live/effect/blocker); 28 строк + 2 мутационных набора + 17 архива.
- FR-5: исторический ASR донора НЕ переносится в результаты main.
- FR-6: файл-фрейминг документа = original channel DOCUMENT, effective
  user_query — в metadata кандидата (A12).

## Acceptance (пакета)
- registry уникален; CLI run каждой семьи на mock: положительный прогон
  сохраняет candidate/transcript/family/StageResult; полный suite зелёный;
  core/composite/lifecycle не тронуты.
