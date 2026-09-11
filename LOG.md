---
type: log
project: memnotsafe
---

# LOG — memnotsafe

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
