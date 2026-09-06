# Tasks: 005-attack-integration (статусы пакета 2026-09-06)

- [x] T1 document_regulation_graft (doc/plain/global; 3 сценария; ASR mock 100%)
- [x] T2 cross_topic_smuggle (user/global; 2 сценария; ASR mock 100%)
- [x] T3 tool_error_echo_poisoning (direct; natural/natural2 — blocked-by-tool-loop)
- [x] T4 fake_shared_past (single-user; ASR mock 100%)
- [x] T5 contact_supersede ({case_marker} в записываемой реплике; ASR mock 100%)
- [x] T6 cross_lingual_insertion (EN доставка → RU активация; ASR mock 100%)
- [x] T7 recommendation_hijack (ASR mock 100%)
- [x] T8 system_log_impersonation (ASR mock 100%)
- [x] T9 тесты tests/test_005_port_batch.py: 32 (positive ×10 комбинаций,
      write-UNKNOWN ×8, negative ×8, изоляция вариантов, уникальность registry)
- [x] T10 CLI battery: 11 сценариев через memnotsafe.cli run (mock), артефакты
      runs/005-batch/*; полный suite после очереди 1 и финальный — 272 passed exit 0
- [x] T11 матрица 28+2+17 (inventory-matrix.md) + live-prep для 006
- [ ] T12 (вне пакета): natural/natural2 для tool_echo — после tool-loop контракта
- [ ] T13 (вне пакета): ревью владельцем; снятие пометки «ревью не завершено»
