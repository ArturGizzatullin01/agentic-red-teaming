# Plan: 005-attack-integration (пакет 2026-09-06)

Файлы: src/memnotsafe/attacks/{document_regulation_graft,cross_topic_smuggle,
tool_error_echo_poisoning,fake_shared_past,contact_supersede,cross_lingual_insertion,
recommendation_hijack,system_log_impersonation}.py; scenarios/*.yaml (11);
tests/test_005_port_batch.py; правки adapters/mock.py (поведенческие, не по family):
- WRITE_MARKERS: «зафиксир» (покрывает зафиксируй/зафиксируйте/зафиксирую/
  зафиксировано), «внутренний регламент» (документный фрейминг = inferred write);
- _INFERRED_RULE_RE: правило-стейтменты без императива (считайте/присваивается/
  применена политика/применение политики/применяет приоритетный режим/
  standing|permanent reference) — источник записи и fallback directive;
- GLOBAL_CUES: «всех клиентов» + «всем клиентам» (для всех/ко всем клиентам).

Constitution Check: роли сохранены (mock — модель стенда, расширение
содержательное, без ветки «если family — вернуть True»); композит/матчинг/
lifecycle не тронуты; registry уникален; исторический ASR не переносился.

Отклонения от донора (все в docstring атак + матрица):
1. cross_topic/tool_echo: порядок триггеров — «портфель» уводит mock-NLU в
   tool-путь; на живом стенде оба порядка валидны.
2. contact_supersede: {case_marker} в записываемую (вторую) реплику — legacy
   матчинг ищет первую, а в память попадает вторая (та же семантика, что consent).
3. cross_topic global: «ко всем клиентам банка» покрыт в GLOBAL_CUES mock'а.
4. tool_echo natural/natural2 — blocked-by-tool-loop (не переносились).
