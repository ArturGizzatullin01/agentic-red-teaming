---

description: "Tasks for 002-evidence-integrity"
---

# Tasks: Достоверность evidence-конвейера

**Input**: [plan.md](plan.md), [spec.md](spec.md). Каноническая нумерация фичи —
`T002-N`; состав текущего пакета — в [analyze.md](analyze.md). После gate фичи: baseline 35 passed.

## Phase 1: matching-утилита (вне ядра)

- [x] T002-1 `src/memnotsafe/evidence/matching.py` (+ `evidence/__init__.py`):
  нормализация (NFKC; дефисы U+2010, U+2011, U+2012, U+2013, U+2014, U+2015,
  U+2212, U+FF0D поимённо; ZWSP U+200B; ANSI CSI `ESC[...letter`), raw рядом с
  нормализованным; пустой marker → `ValueError` (config error, exit 1).
  Тесты: U+2011, U+FF0D, ZWSP, ANSI, обычный `-` не портится, ISIN/URL не
  нормализуются.
  **Выполнено 2026-09-06 (GLM Flash)**: `normalize_text(text)` (NFKC →
  поимённая таблица дефисов/ZWSP → CSI-регекс) и `match_marker(marker,
  evidence)` → frozen `TextMatch(marker_raw, evidence_raw,
  marker_normalized, evidence_normalized, matched, method)`; экспорт в
  `__init__` не понадобился (все пакеты держат его пустым). Факты NFKC
  закреплены тестами по кодовым точкам: U+2011 NFKC сводит к U+2010,
  U+FF0D — к ASCII, остальные поимённые дефисы не трогает, поэтому таблица
  содержит оба конца U+2011-цепочки и порядок NFKC/таблицы не влияет на
  результат. CSI — один проход, три ветки: полная последовательность,
  opener-отменённый-следующим-ESC (lookahead), одиночный ESC перед ESC;
  оборванный opener в конце/перед не-финальным байтом остаётся как есть и
  хвост не поглощает. RED — честная collection error (ModuleNotFound);
  во время реализации фаззинг (500k случайных триалов ESC/ZWSP/дефисов)
  нашёл неидемпотентность варианта «одна ветка + цикл до фикспоинта» и
  варианта без ветки одиночного-ESC (голый ESC склеивал `[` выжившего
  текста в новый opener) — кейсы добавлены в регрессию. Проверено:
  `python -m pytest tests/test_evidence_matching.py -q` → 52 passed;
  полный `python -m pytest tests/ -q` → 108 passed, exit 0.
  **Доработано по ревью 2026-09-06 (порядок нормализации)**: обнаружено два
  дефекта порядка NFKC-первым: (a) удаление ZWSP/CSI склеивает разорванные
  combining-последовательности (`e`+ZWSP+U+0301), которым нужен повторный
  NFKC до `é`; (b) NFKC ДО удаления CSI приклеивает диакритику к финальной
  букве последовательности (`e\x1b[31m\u0301` → `e\x1b[31ḿ` — CSI ломался и
  выживал мусором). Фикс: проход переупорядочен в CSI → поимённая таблица →
  NFKC и повторяется до фикспоинта — тем самым normalize идемпотентна по
  построению (выход = строка, на которой проход ничего не меняет);
  завершимость: после первого прохода NFKC-выход стабилен, CSI/translate
  только удаляют (NFKC не производит ESC/'['/ZWSP/дефисы). Регрессии
  rework: e+ZWSP/CSI+acute → `é` (нормализация и match с precomposed `é`),
  идемпотентность glued-кейсов, fullwidth-CSI `ESC ［ 31 m` (NFKC сводит
  U+FF3B к '[' только со второго прохода). RED — 4 failed (все новые
  тесты), повторный фаззинг 500k триалов с диакритикой/fullwidth/CSI —
  0 нарушений идемпотентности, цикл завершается. Проверено:
  `tests/test_evidence_matching.py` → 60 passed; полный suite → 116 passed,
  exit 0.
  **Финальное ревью-замечание F2 2026-09-06 (документация, алгоритм не
  менялся)**: обоснование завершимости в докстринге переписано — прежнее
  содержало три ложных утверждения (NFKC «не производит '['» — опровергается
  тестом fullwidth-CSI; «не производит поимённые дефисы» — U+2011→U+2010;
  translate «только удаляет») и не исключало циклов одинаковой длины.
  Новое обоснование: тождественность CSI-sub и таблицы в проходе ⇒ выход
  NFKC(s)=s по теореме замыкания Unicode (NFKC(NFKC(x))==NFKC(x), от версии
  таблицы не зависит); всякое нетождественное срабатывание потребляет
  конечный ресурс — ESC/ZWSP не производит ни один шаг (для NFKC проверено
  полным перебором code points, Unicode 16.0.0, способ перепроверки указан),
  а поимённые дефисы и '[' возникают только из не-стабильных источников
  (U+2011/U+207B/U+208B/U+FE31/U+FE32/U+FE58 и U+FE47/U+FF3B; перечень —
  тем же перебором), которые по замыканию ничем не производятся. Тесты:
  вступление модуля про «одиночный проход» обновлено под фикспоинт;
  `test_fullwidth_nfkc_handled_before_table` переименован в
  `test_fullwidth_hyphen_reduced_by_nfkc_itself`; добавлена симметричная
  проверка контракта (decorated marker ZWSP+CSI ⇄ precomposed evidence,
  raw обеих строк побайтно; прошла на текущем коде, RED не выдумывался).
  Проверено: профильный набор → 61 passed; полный suite → 117 passed,
  exit 0. Реализация готова к повторному ревью.
- [x] T002-2 `evidence/matching.py`: record-матчинг — новая/изменённая запись по
  case-маркеру в диффе; ownerless (без автора) матчится маркером; legacy-путь
  (без маркера) — текущая семантика payload-подстроки + `source_user == attacker`;
  конкурентные записи/дубли маркера → UNKNOWN. Тесты: старая запись, ownerless,
  чужая запись в окне, два case с разными маркерами, дубли.
  **Выполнено 2026-09-06 (GLM Flash, пакет с T002-4)**: `match_candidate_record`
  → frozen `RecordMatch` (matched True/False/None=UNKNOWN, state, reason, record
  as-is, record_id, layer, method, evidence). Маркерный путь: before/after
  напрямую (fallback-id diff'а не принимается), маркер в before → UNKNOWN,
  дубликаты id (after и before), id в двух слоях, чужой source_user, записи без
  стабильного id/читаемого text → UNKNOWN; ownerless — автор не приписывается,
  изоляция документирована как протокол эксперимента (из снимков не выводима).
  Legacy: raw-подстрока + source_user==attacker, after-only; баг пустой
  подстроки исправлен (payload="" → not-found, text="" → не совпадает); выбор
  при мультивыборе детерминированный. Проверки сопоставления и oracle-стадий —
  [test_evidence_integrity.py](../../tests/test_evidence_integrity.py). Проверено: профильный
  набор 102 passed; полный 158 passed, exit 0.
  **Доработка F1/F2 2026-09-06 (ревью Codex)**: F1 — любая непрочитанная
  запись before (не-dict или без читаемого text) → UNKNOWN «нельзя исключить
  маркер до доставки» (пример ревьюера раньше давал True; отдельный блокер
  «before-версия без text» поглощён и удалён). F2 — политика id: только
  непустая строка из (id, mem_id, fact_id, memory_id), пустая/пробельная и
  нестроковые значения невалидны без str()-коэрции, fallback на следующий
  ключ; нет валидного id → UNKNOWN. Типы сигнатур: SystemSnapshot | None.
  RED 11 failed (все новые F-тесты) на коде ревизии 1, затем GREEN.
  **F5 2026-09-06 (ревью Codex, ревизия 3)**: malformed-записи (не-dict) в
  after — честный UNKNOWN во всех путях (маркерный: guard в id_counts до
  обращения к полям; legacy: non-dict собирается в unreadable → UNKNOWN, не
  игнор/AttributeError); `find_record_by_identity` → типизированный
  `IdentityLookup` (см. T002-4/F4).

## Phase 2: lifecycle раннера (НЕ зависит от Phase 1 — R5)

- [x] T002-3 `src/memnotsafe/core/runner.py`: (a) порядок finalize-фазы адаптера →
  settle → НОВАЯ trigger-сессия — сегодня `wait_until_persistent` вызывается до
  `close_session` (runner.py:82–85), при финализации в close_session это даёт ложный
  persistence; (b) владение (R3): runner трекает созданные им сессии и закрывает их
  в `finally` ровно один раз (сегодня закрытие не в `finally`: строки 85, 100 —
  утечка при исключении), НЕ закрывает клиент (владелец — `Campaign`/`cli.py`,
  `target.aclose()` в `cli.py:76–77`), не финализирует повторно финализированное;
  cleanup не маскирует первичную ошибку (raise ... from). Тесты
  `tests/test_runner_lifecycle.py`: порядок вызовов, исключение адаптера (сессии
  закрыты, ошибка видна), settle-таймаут, два case на одном target (первый падает —
  второй получает живой target), aclose вызван только владельцем.
  **Выполнено 2026-09-06 (GLM Flash)**; доработано по ревью F1–F3 и финальному
  ревью отмены: `_SessionBook` с явными терминальными состояниями
  (`_attempted` до await + closed/failed/interrupted; KeyboardInterrupt/SystemExit
  попадают в attempted, повторный close невозможен при любом исходе),
  `saw_cancellation` передаётся явно (не парсингом строк); отмена — отдельный
  исход во ВСЕХ фазах, включая delivery-finalize: настоящая task.cancel() при
  finalize → наружу CancelledError, task.cancelled()=True, settle/trigger не
  начинаются, RunnnerError финализации не маскирует отмену (становится
  __cause__); CancelledError/KeyboardInterrupt/SystemExit сохраняют тип;
  finalize всех delivery-сессий до settle, trigger в новой сессии, baseline
  через общий book, cleanup-ошибки наблюдаемы (add_note/сообщение), сообщения
  RunnerError — только фаза/тип/id (секреты не попадают), сырая причина в
  __cause__. Cleanup последовательный, без собственного таймаута —
  завершаемость зависит от bounded-операций адаптера (задокументировано).
  Проверено: RED-1 — 10 failed (A01-порядок, утечки, отсутствие cleanup,
  маскирование); RED-2 — 11 failed (F1 ретрай [1,2,1], RunnerError вместо
  CancelledError, F2 baseline-close подменяет primary, F3 секрет в сообщении);
  RED-3 (настоящая task.cancel через create_task+events) — 3 failed
  (finalize-отмена → RunnerError, task.cancelled()=False; KI-close ретрай
  attempts=2); после фикса — `python -m pytest tests/test_runner_lifecycle.py
  -q` → 21 passed; полный `python -m pytest tests/ -q` → 56 passed, exit 0.

## Phase 3: oracle'ы на matching + trigger-only (после T002-2)

- [x] T002-4 `oracles/memory.py` (write) и `oracles/persistence.py`: WRITE через
  matching (маркер в диффе; legacy — как сегодня), PERSIST — запись живёт в after
  после границы сессии; `oracles/base.py::find_candidate_record` делегирует в
  matching (API сохраняется).
  **Выполнено 2026-09-06 (GLM Flash, пакет с T002-2)**: WRITE передаёт тристейт
  matcher'а без схлопывания (нет bool(record)); PERSIST — зависимость
  write=None→None / False→False, повторный matcher на after после границы,
  различение settle=False / запись исчезла / неоднозначность (None);
  `find_candidate_record` делегирует, сигнатура record|None сохранена;
  `EvaluationContext.case_marker: str | None = None` — аддитивная ВРЕМЕННАЯ
  граница до producer/propagation (R4/T002-7): «алгоритм и oracle-путь готовы,
  producer и сценарии НЕ подключены». Устаревший комментарий persistence о
  порядке «wait ДО close» заменён на фактический порядок T002-3. Проверено:
  полный suite 158 passed, exit 0.
  **Доработка F3 2026-09-06 (ревью Codex)**: PERSISTENCE проверяет
  ИДЕНТИЧНОСТЬ подтверждённой WRITE записи (record_id+layer из write evidence,
  новый публичный `evidence.matching.find_record_by_identity`), а не
  пере-выбирает запись с маркером: замена id/смена слоя при наличии другой
  сигнатурной записи → UNKNOWN; чистое исчезновение → False; WRITE без
  доказанной идентичности → UNKNOWN; зависимости write=None/False и
  settle=False → False сохранены. Задокументировано ограничение одного
  after-снимка в текущем runner. RED 11 → GREEN: полный suite 170 passed,
  exit 0.
  **F4/F5 + L1/L2 2026-09-06 (ревью Codex, ревизия 3)**: F4 — идентичности
  мало: `find_record_by_identity` → типизированный `IdentityLookup(found|
  not-found|ambiguous)` (дубль id → UNKNOWN, первый элемент не выбирается);
  для found требуется читаемый text (иначе UNKNOWN) и выжившая сигнатура —
  маркер (нормализованное вхождение T002-1) или legacy raw-подстрока;
  контейнер жив / сигнатура удалена → False «персистентность отравления не
  подтверждается». F5 — guard не-dict до обращения к полям во всех путях
  (маркерный id_counts, legacy → UNKNOWN, identity-lookup): malformed-запись
  не даёт AttributeError. RED 7 failed → GREEN: полный suite 179 passed,
  exit 0. L1/L2 — live-smoke-plan.md переписан: эффект reset по коду
  (delete_many({}) по 4 коллекциям = память всех клиентов; smoke только на
  выделенном согласованном хранилище; подмена только mongo_db адаптера
  запрещена), команды PowerShell, report --input/--output, обещания
  уникальности маркера и полной наблюдаемости lifecycle сняты.
- [~] T002-5a (2026-09-07, Codex по запросу Андрея): дедуп расщеплённой канарейки в
  `evidence/matching._match_by_marker` — несколько записей с НАШИМ case-marker и
  различными id = одна логическая запись (финалайзер дробит ход / мульти-слой
  global+user), matched=True с детерминированной основной; UNKNOWN оставлен для
  настоящей неоднозначности (id-коллизия слоёв, дубль id, чужой автор). Контракт
  evidence-and-verdict.md обновлён, тест заменён, 6 сценариев политики зелёные.
  Дефект LIVE-10 п.2; flips graft_marker WRITE UNKNOWN→True → первый композит.
- [ ] T002-5 `oracles/adoption.py`, `oracles/external_effect.py`,
  `oracles/tool.py`: trigger-only (principal+session+phase); отказ/предупреждение с
  цитатой маркера ≠ принятие (exposure); call/result по call_id в одной
  trigger-сессии; несвязанные успехи не объединяются (UNKNOWN); глобальный snapshot
  не закрывает cross-user EFFECT.
- [ ] T002-6 `adapters/investment_stand.py` (+ `adapters/mock.py` при нужде):
  привязка к полям хранилища (ownerless, коллекции) остаётся здесь; используют
  matching, не дублируют нормализацию.
- [ ] T002-7 типизированный `ExpectedEffect` (R4/A11): dataclass с типизированными
  вариантами (tool: argument/value и т.п.) + legacy converter dict → dataclass на
  границе `AttackCandidate`; чтение в oracle'ах переводится на тип; композит не
  меняется. Contract-тесты: round-trip, неизвестный type → UNKNOWN.

## Phase 4: regression-набор и gate

- [ ] T002-8 `tests/test_evidence_integrity.py`: old marker, install-only echo,
  неизвестный author, чужой principal, несвязанные call/result, missing telemetry
  (RETRIEVE=UNKNOWN; остальные — честные False/UNKNOWN по формуле), отказ-с-цитатой,
  Unicode-дефисы, пустой marker (config error), конкурентная запись, старый сценарий
  без маркера (backward compat).
  **Частично выполнено 2026-09-06 (GLM Flash)**: создан файл с 41 тестом
  record-матчинга и WRITE/PERSISTENCE (старый маркер, ownerless, чужой автор,
  два маркера, дубли, слои, пустой/невидимый marker, Unicode с raw, порядок,
  legacy-совместимость, tristate-проводка, settle/исчезновение/неоднозначность).
  НЕ выполнено и T002-8 не закрывает: install-only echo, отказ-с-цитатой,
  несвязанные call/result, чужой principal (это T002-5), truth-table/wire
  round-trip (T002-9).
- [ ] T002-9 Тест неизменности `oracles/composite.py` (truth-table fixture);
  round-trip StageResult→JSON→report (True/False/None, R1); полный baseline
  `python -m pytest tests/ -q` зелёный; review этапа.

Зависимости: T002-2 после T002-1; Phase 3 после T002-2; T002-8 после T002-4–6;
T002-9 замыкает. Phase 2 (T002-3) независим от Phase 1 и может идти параллельно.
Запрещено трогать `oracles/composite.py` и добавлять атаки в этом diff.
