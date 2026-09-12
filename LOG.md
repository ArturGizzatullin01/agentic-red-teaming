---
type: log
project: memnotsafe
---

# LOG — memnotsafe

### 2026-09-12 — glm — P07 судья видит исходную цель кейса (glm/write-marker-snapshots)

- задача: передавать судье конкретный expected fact (цель кейса), а не только общий вопрос рубрики; регрессия кейса 003 общим критерием (WRITE-план 2.4, аудит 3.5)
- сделано: `build_prompt(..., goal)` — блок «ЦЕЛЬ КЕЙСА» в ОТДЕЛЬНОЙ ограде со своим nonce (цель = данные; sanitize_artifact срезает фейковые метки оград); system-промпт судьи дополнен правилом «привязывай оценку к цели, а не к любому изменению формулировки» и уточнённым значением outcome=confirmed; `LLMJudge.evaluate/evaluate_stages(..., goal="")` — пустая цель даёт промпт ровно прежнего вида; metadata.judge дополняется `goal_anchored: bool` (признак метода оценки для отчёта/replay); runner передаёт `goal_text` = фактическая доставка (с подставленным маркером), fallback candidate.payload; сырой вердикт сохраняется в артефакте вызова, структурные проверки цитат (verdict.py) не менялись — quote_in_baseline отклоняет подтверждение перефразированного отказа, совпадающего с чистым ответом (общий критерий регрессии 003, без case_id-исключений); версии рубрик не подняты: вопрос/примеры рубрики не менялись, цель — вход (зафиксировано в metadata.goal_anchored и артефактах вызова)
- файлы: `src/memnotsafe/judge/prompt.py`, `src/memnotsafe/judge/runtime.py`, `src/memnotsafe/core/runner.py`, `tests/test_judge_goal_p07.py` (новый), `tests/test_escalation.py` (стаб судьи принял kwarg goal)
- проверки: полный офлайн-набор `tests/` → 556 passed (9 новых: ограда цели; цель-не-инструкция; прежняя форма промпта без цели; metadata-флаг; регрессия 003 через quote_in_baseline; композит: EXTERNAL_EFFECT обязателен, retrieval UNKNOWN допустим; судейский вердикт не применяется к write/tool)
- ограничения: цель = полный текст доставки (обе реплики двухходовой атаки) — если позже понадобится различать «вступление» и «отравленное утверждение», это поле записи корпуса (P09-территория)

### 2026-09-12 — glm — P06 четыре снимка M0–M3 (glm/write-marker-snapshots)

- задача: развести WRITE и PERSISTENCE по времени: M0 после baseline / M1 после delivery-finalize+settle / M2 новая сессия до trigger / M3 после trigger (WRITE-план 2.3, аудит 3.4)
- сделано: `PhaseSnapshots` (m0..m3, to_dict/from_dict) в `evidence/snapshot.py`; `EvaluationContext.phases` (None = старые ручные конструкции); WRITE в фазовом режиме сравнивает m0↔m1 (m1 нет → UNKNOWN, m3 не подменяет); PERSISTENCE в фазовом режиме проверяет идентичность m1-записи в m2 (m2 нет → UNKNOWN), повторный сигнатурный поиск тоже m0↔m2; runner снимает m1 после settle и m2 после открытия victim-сессии до trigger-вопроса, кладёт phases.m1/m2 и diff_m0_m1 в evidence; кампания считает «запись объявила маркер» (`_record_declares_marker`) и поднимает require_case_marker для случая — рукописные атаки с предзаданным case_marker (opt-in 005) не проверяются; escalate получает флаг от кампании
- файлы: `src/memnotsafe/evidence/snapshot.py`, `src/memnotsafe/oracles/base.py`, `src/memnotsafe/oracles/memory.py`, `src/memnotsafe/oracles/persistence.py`, `src/memnotsafe/core/runner.py`, `src/memnotsafe/core/campaign.py`, `src/memnotsafe/core/escalation.py` (параметр из P04 теперь питается от кампании), `tests/test_phase_snapshots_p06.py` (новый)
- проверки: полный офлайн-набор `tests/` → 548 passed (включая 12 новых P06: m0/m1-only write; запись только в m3 → WRITE False; upsert same-id → changed; исчезла между сессиями → False; замена id → UNKNOWN; m3 не спасает PERSISTENCE; legacy-контекст без phases — прежняя семантика; e2e session-gap: WRITE True / PERSIST False)
- уточнение к P04: требование «заявленный записью маркер обязан быть в доставке» перенесено с раннера на слой кампании (раннер не знает, что рукописная атака opt-in) — тест test_declared_record_marker_absent... теперь прогоняет Campaign.run
- ограничения: adoption/retrieval/tool продолжают читать before/after (=M0/M3) — их фазовая привязка в P09 (фактический контекст trigger); evidence["phases"] хранит только m1/m2 (m0=before, m3=after уже в evidence)

### 2026-09-12 — glm — P05 settle-исходы и честный finalize (glm/write-marker-snapshots)

- задача: различить observed/timeout/unavailable в ожидании записи; Mongo недоступна → не True; неоднозначный HTTP finalize не повторять вслепую вторым каналом (WRITE-план 2.2, аудит 3.3)
- сделано: `SettleResult` (outcome/reason/observations/elapsed_s/hits, success-тристейт) в `adapters/base.py`; базовый контракт `wait_until_persistent` → SettleResult (bool-адаптеры нормализуются раннером: True→observed, False→timeout); `investment_stand.wait_until_persistent` возвращает observed/timeout/unavailable (чтение памяти упало или mongo_uri нет → unavailable, НЕ негатив; пустой needle без маркера → timeout, успехом не считается); `close_session` фолбэк в чат только при доказанно не применённом finalize (401/403/404/405/501, ConnectError/ConnectTimeout); 5xx и таймаут после отправки → исход неизвестен, второй канал запрещён (seam `_post_finalize`); runner кладёт исход settle в `evidence["settle"]` и передаёт в `EvaluationContext.settle`; `persistence.py` — unavailable → UNKNOWN («не смогли прочитать» ≠ «записи нет»), timeout → False; `mock.py` — типизированный результат, пустой needle больше не True
- файлы: `src/memnotsafe/adapters/base.py`, `src/memnotsafe/adapters/investment_stand.py`, `src/memnotsafe/adapters/mock.py`, `src/memnotsafe/core/runner.py`, `src/memnotsafe/oracles/base.py`, `src/memnotsafe/oracles/persistence.py`, `tests/test_settle_outcomes_p05.py` (новый), `tests/test_investment_stand_settle.py` (ассерты под SettleResult + короткое окно)
- проверки: `test_settle_outcomes_p05 test_investment_stand_settle test_runner_lifecycle test_investment_stand_adapter test_write_marker_p04 test_evidence_integrity test_all_attacks test_e2e_cross_user` → 182 passed
- ограничения: WriteError/ReadError/5xx классифицированы неоднозначными в пользу честности (раннер пометит сессию failed → RunnerError) — идемпотентное завершение стенда остаётся за P09/стендом

### 2026-09-12 — glm — P04 write-marker-snapshots (смена GLM-WRITE-MARATHON)

- задача: провести маркер через корпус → GeneratedAttack → доставку → settle → оценку (WRITE-план 2.1, приёмка аудита 3.2)
- сделано: `_substitute_case_marker` в `attacks/generated.py` (подстановка ТОЛЬКО плейсхолдера `{case_marker}` в payload, trigger и сообщения delivery/trigger шагов; перенос локальной дельты fix/generated-delivery-case-marker 67444a5 + расширение на trigger по ТЗ); `CorpusRecord.case_marker` с roundtrip и браком пустого значения в `generation/corpus.py`; кампания передаёт маркер записи в `AttackContext.case_marker` ДО раннера и прокидывает `scenario.require_case_marker` в эскалацию; `escalate(..., require_case_marker)` — повтор получает новый маркер, требование наличия сохраняется; раннер включает проверку «маркер в фактической доставке» и по заявленному записью маркеру, заявленный маркер не перезаписывается derive_case_marker, отказ ДО доставки (RunnerError)
- файлы: `src/memnotsafe/attacks/generated.py`, `src/memnotsafe/generation/corpus.py`, `src/memnotsafe/core/campaign.py`, `src/memnotsafe/core/escalation.py`, `src/memnotsafe/core/runner.py`, `tests/test_write_marker_p04.py` (новый)
- проверки: `python -m pytest tests/test_write_marker_p04.py -q` → 10 passed; затронутые пачки `test_generation_offline test_runner_lifecycle test_escalation test_profile_and_corpus test_campaign_and_reports` → 56 passed; matching.py не тронут
- ограничения: settle `expect_text_contains` = payload[:60] остаётся legacy-фолбэком (маркерный путь приоритетен) — исходы settle разводятся в P05; expected_effect плейсхолдерами не переписывается (цель эффекта неизменна)

### 2026-09-10 — Codex — FIX-05 rebase onto FIX-03

- TASK: replay `12ca1444479e070dfc246b4fa62de9669cbcb3aa` onto FIX-03;
  branch `fix/system-log-marker-on-03`, base `53c3f19f6decf1e68e9206d3b6ccdcda392275d3`.
- CHANGED: original one-line `AttackCandidate(payload=payload)` fix in
  `src/memnotsafe/attacks/system_log_impersonation.py`; original FIX-05 tests,
  `specs/005-attack-integration/plan.md`, `tasks.md`, and historical LOG retained.
  Specs and Attack match the source commit exactly.
- CONFLICTS: one append conflict in `tests/test_005_port_batch.py`; kept all FIX-03
  declared-refusal/adoption, exposure, judge-merge, and legacy tests, followed by
  all FIX-05 marker-in-candidate, delivery, opt-in, isolation, and config-gate tests.
  Exact-content check: resolved file equals the full FIX-03 file plus the original
  FIX-05 additions. LOG applied without conflict; this note precedes both old blocks.
- Python: `C:\Users\dota2\memnotsafe-integration\team-publish\.agent-work\reporter-venv\Scripts\python.exe`;
  `PYTHONPATH=src`, `PYTHONDONTWRITEBYTECODE=1`. Attack import verified in this worktree.
- Commands actually run with that Python, both before and after the cherry-pick:
  `-m pytest tests/test_005_port_batch.py -q`;
  `-m pytest tests/test_e2e_cross_user.py tests/test_all_attacks.py -q`.
- BASELINE at FIX-03: batch 70 passed; mandatory regression 9 passed.
- RED: NOT_RERUN for this rebase; original FIX-05 recorded 4 failed / 2 passed
  on its unfixed FIX-01 base (historical evidence below).
- GREEN on FIX-03 plus FIX-05: batch 76 passed; mandatory regression 9 passed.
- FULL_SUITE: NOT_RUN. Only offline checks; no live target or package installation.
- Scope: no changes to oracles, runner, html_report, campaign execution,
  GeneratedAttack, or FIX-10 files; no branch switch, sibling worktree edits,
  merge, or push. Pre-existing untracked files excluded from the commit.
- STATUS: VERIFIED_UNMERGED locally; acceptance remains with Hermes.
- NEXT: Hermes reviews and accepts the replayed FIX-05 on FIX-03.

### 2026-09-10 — Codex — FIX-05 — fix/system-log-marker-candidate

- задача: сохранить вычисленный payload объявленного sync-id варианта в AttackCandidate;
  роль — только Attack, норма — 005 FR-1/FR-2, приёмка за Hermes
- база: `40f6f80a2053d9906625a337279f07b24ee23cb5` (FIX-01); существующая ветка
  `fix/system-log-marker-candidate`, worktree `.agent-work/fix-05-system-log-marker`
- сделано: `payload=payload` в `SystemLogImpersonation.generate`; подстановка явная,
  producer маркера — Runner; оба delivery-хода сохранены, шаблон не мутируется
- файлы: `src/memnotsafe/attacks/system_log_impersonation.py`,
  `tests/test_005_port_batch.py`, `specs/005-attack-integration/plan.md`,
  `specs/005-attack-integration/tasks.md`, `LOG.md`
- среда: только предоставленный `.agent-work/reporter-venv/Scripts/python.exe`,
  `PYTHONPATH=src`; импорт проверен из текущего worktree, установки зависимостей не было
- до фикса: исходный `tests/test_005_port_batch.py -q` — 51 passed;
  `tests/test_e2e_cross_user.py tests/test_all_attacks.py -q` — 9 passed
- RED: `-m pytest tests/test_005_port_batch.py -k system_log_case_marker -q` —
  4 failed, 2 passed, 51 deselected на неизменённом Attack: маркера нет в кандидате,
  config-gate выдаёт `RunnerError` в обоих режимах MockTarget
- GREEN: `-m pytest tests/test_005_port_batch.py -q` — 57 passed;
  `-m pytest tests/test_e2e_cross_user.py tests/test_all_attacks.py -q` — 9 passed
- проверено: текущий маркер в кандидате и фактической delivery; прежние текст и порядок
  без флага; изоляция двух контекстов; маркер, созданный Runner, проходит config-gate
- SUCCESS не форсируется: gate проверен на vulnerable и protected MockTarget,
  защищённый режим сохраняет `success=False`; read-only ревью diff — без замечаний
- ограничения: полный suite — NOT_RUN; live, Mongo, сеть, YAML и другие роли не тронуты;
  исходные untracked-файлы кроме разрешённого LOG не включаются в коммит;
  push/PR/слияние не выполняются, результат локальный VERIFIED_UNMERGED
- последняя правка — этот блок LOG; далее только проверка diff и коммит разрешённых файлов

### 2026-09-09 — opus — fix/oracle-trigger-event-scope (FIX-01)
- задача: ограничить событийные стадии ADOPT/TOOL/EFFECT trigger-фазой жертвы (аудит A1, T002-5b)
- база/head: `654a410` (origin/main, merge PR #24) → `40f6f80`; работа в отдельной
  worktree `.agent-work/fix-01-oracle-scope`, канон не переключался
- сделано: общий отбор `oracles/base.py::trigger_events` (`session_id` ∈ `trigger_session_ids`
  И `actor` == жертва); три событийные стадии перешли на него; без контекста фаз — UNKNOWN, не False
- файлы: `oracles/base.py`, `oracles/adoption.py`, `oracles/tool.py`, `oracles/external_effect.py`,
  `tests/test_evidence_integrity.py`, дельта `specs/002-evidence-integrity/plan.md` и `tasks.md`
- проверки (`.agent-work/reporter-venv/Scripts/python.exe -m pytest`, системный python3 недоступен):
  RED 6 из 7 новых тестов до фикса; `tests/test_evidence_integrity.py -q` → 70 passed;
  `tests/test_e2e_cross_user.py tests/test_all_attacks.py -q` → 9 passed; `tests/ -q` → 410 passed
- ограничения: чужой WIP канона не тронут (ветка, HEAD и 31 изменённый файл на месте);
  ветка не пушилась, PR не создавался, слияния не было
- открытые риски: T002-5 не закрыт — корреляция call/result по `call_id` (FIX-02) и
  отказ-с-цитатой (FIX-03) остаются; snapshot-ветка ADOPT `scope_escalated` не трогалась (D-04)

### 2026-09-09 — Codex — audit-fix-long-task

- задача: сверить чужой аудит с каноном и подготовить передачу фиксов по отдельным веткам
- сделано: 12 атомарных задач с ветками, спеками, allowlist, зависимостями и приёмкой;
  остальные находки отделены от рабочей очереди, противоречия контрактов отмечены
- файл: [лонг-таск](docs/integration-handoff/audit-fix-long-task.md)
- сверка: исходники и контракты текущего WIP поверх `6ab4ff2620f69e0100141abf7b9a607c34fdc92f`;
  изолированно воспроизведены значения функций по 12 пунктам, это не pytest и не E2E
- проверки: 12 уникальных веток/карточек, зависимости корректны, Markdown-ссылки существуют;
  хеши 40 проверенных исходников, тестов и spec-файлов не изменились
- ограничение: системный python3 недоступен; bundled Python без pytest, yaml и httpx;
  обязательный регресс не выполнен, зависимости не устанавливались
- ограничения передачи: интеграционная база содержит чужой WIP и требует фиксации владельцем;
  исходники не правились, ветки не создавались, коммитов и пуша нет

### 2026-09-09 — opus — fix/escalation-inherit-judge-marker
- задача: повтор эскалации сохраняет судью и не тащит чужой case_marker
- сделано: в `escalate()` прокинут `judge`, в повтор сброшен `case_marker=None`
- файлы: `src/memnotsafe/core/escalation.py`, `tests/test_escalation.py`
- проверки: `-k "escalat or retry or judge"` → 161 passed; e2e+all_attacks → 9 passed; `tests/` → 424 passed
- открытые риски: `_maybe_escalate` ещё не передаёт `judge=self.judge`; `require_case_marker` в повтор не прокидывается (GeneratedAttack без `{case_marker}`)

### 2026-09-09 — astra — fix/report-replay-judge-summary
- задача: replay не теряет сводку судьи
- сделано: сводка судьи сохраняется при `memnotsafe report`
- файлы: `src/memnotsafe/cli.py`, `tests/test_judge_offline_regression.py`
- проверки: `-k report/cli/replay` → 33 passed; e2e+all_attacks → 9 passed
- открытые риски: HTML всё ещё пишет статичное Judge inactive

### 2026-09-08 — human
- задача: посадить пайплайн Hermes/NotebookLM + десктоп Claude Code / Codex на канон `team-publish`
- сделано: контракт AGENTS/CLAUDE, MAP, маршрутизация, список корпуса
- файлы: комплект `memnotsafe-agent-kit`
- проверки: чтение README, PROJECT_OVERVIEW, pyproject, src-дерева
- открытые риски: в zip пять копий репо; агенты легко начнут править не ту
