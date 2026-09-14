# Tasks: 010 — P09-full offline

Allowlist: `specs/010-p09-full/*`, `specs/007-evidence-foundation/offline-install-gate.md`,
`src/memnotsafe/evidence/telemetry.py` (new), `src/memnotsafe/evidence/bundle.py`,
`src/memnotsafe/adapters/mock.py`, `src/memnotsafe/core/campaign.py`,
`src/memnotsafe/core/experiment.py`, `tests/test_p09_full_offline.py` (new),
`LOG.md`, `MAP.md`. Ядро (runner/oracles/composite) и cli.py — НЕ трогаются.

## Phase 1 — контракты и карточка

- [x] T1.1 Карточка 010 (spec/plan/tasks/checkpoint); C10=PASS зафиксирован в gate-доке
- [x] T1.2 `evidence/telemetry.py`: фазы, строгая схема v1, parse/build/proven_no_call/divergence + unit-тесты RED→GREEN

## Phase 2 — EvidenceBundle schema

- [x] T2.1 RED: манифест со слотом context_tool_evidence отвергается текущим читателем («неизвестный слот»)
- [x] T2.2 GREEN: BUNDLE_SLOTS_OPTIONAL; write/read/present-валидация; исторический пакет (без слота) читается, слот = absent
- [x] T2.3 write_bundle fail-fast на структурно неверный payload слота

## Phase 3 — adapter instrumentation

- [x] T3.1 mock: `tool_call_prepared` событие (тот же call_id, подготовленные args) до tool_call; поведение вызова не меняется
- [x] T3.2 mock: `context_tool_evidence()` — факты (effective context по сессиям, actual/prepared calls, tool_log_complete, heartbeat, stand_version, chat_prompt_revision=None)

## Phase 4 — кампания/replay

- [x] T4.1 campaign: сборка слота (фазы из транскрипта), сбой → unavailable + причина в provenance
- [x] T4.2 ExperimentSpec: stand_version в volatile (digest стабилен для той же конфигурации)
- [x] T4.3 replay: структурная проверка артефакта слота при verify; существующие проверки (mismatch/no-bundle/JSONL/tamper) не ослаблены

## Phase 5 — negative controls (10)

- [x] T5.1 clean run — маркера в effective_context нет
- [x] T5.2 fake call_id — не восстанавливается и не принимается как доказательство
- [x] T5.3 truncation tri-state: не выбрана / выбрана-обрезана / контекст недоступен
- [x] T5.4 cross-user isolation: attacker-only слой отсутствует в контексте жертвы
- [x] T5.5 missing telemetry → unavailable → UNKNOWN
- [x] T5.6 proven no-call только при полном логе + живом heartbeat
- [x] T5.7 intent mismatch: expected_effect ≠ effective_context, хранятся раздельно
- [x] T5.8 adapter/tool mismatch фиксируется явно по call_id
- [x] T5.9 историческая совместимость: старый bundle без слота + v1/v2 ExperimentSpec
- [x] T5.10 tamper нового слота/манифеста/JSONL обнаруживается

## Phase 6 — финал

- [x] T6.1 Профильный P09-suite зелёный
- [x] T6.2 ОДИН полный suite на финальном production SHA
- [x] T6.3 LOG/MAP/checkpoint/handoff владельцу стенда; live-бюджет — предложение (не утверждение)
