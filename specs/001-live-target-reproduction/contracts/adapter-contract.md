# Contract: InvestmentStandAdapter

**Feature**: [../spec.md](../spec.md) | **Plan**: [../plan.md](../plan.md)

Контракт того, что `InvestmentStandAdapter` обязан реализовать поверх
[TargetAdapter ABC](../../../src/memnotsafe/adapters/base.py), чтобы шесть оракулов дали корректную
воронку на живом стенде БЕЗ правок ядра. Аналог реализации трейс-словаря —
[adapters/mock.py](../../../src/memnotsafe/adapters/mock.py); аналог живого httpx-адаптера —
[adapters/openai.py](../../../src/memnotsafe/adapters/openai.py).

## Методы контракта

### `probe() -> ProbeResult`

- `reachable=True` при `GET /healthz == 200`.
- `capabilities` заполняются по фактической наблюдаемости (см. ниже), а не константами.
- транспортная ошибка → `reachable=False` (CLI `probe` вернёт 1).

### `new_session(user_id) -> str`

- резолвит Bearer-ключ через `identities[user_id]` → ENV; нет записи → `KeyError`; пустой ключ →
  `RuntimeError` (оба поднимутся как `RunnerError` → `exit 1`).
- `session_id` уникален per-прогон (`memnotsafe-<user_id>-<uuid>`), не опирается на сброс стенда.

### `send(session_id, message) -> SendResult`

- POST `/v1/chat/completions` с Bearer соответствующего клиента; `raise_for_status()` → любой сбой в
  `RunnerError`.
- `content` — текст ответа агента.
- `events` — канонические трейс-события, синтезированные ТОЛЬКО из реально наблюдённого сигнала
  (Принцип IV). Для victim-триггера сюда попадают `memory_retrieval`/`llm_decision`/`tool_call`/
  `tool_result`, если сработал канал доказательства (см.
  [evidence-channels.md](evidence-channels.md)).
- `raw` — сырой JSON ответа стенда (для канала tool-телеметрии и артефактов отчёта).

### `wait_until_persistent(evidence) -> bool`

- override базового no-op: polling Mongo до `settle_timeout_s`, пока текст payload не виден в памяти
  клиента-источника или в global-слое.
- нет `mongo_uri` → возвращает `True` без ожидания только если запись подтверждена иным наблюдаемым
  каналом; иначе стадия persistence останется UNKNOWN через отсутствие snapshot.

### `snapshot() -> SystemSnapshot | None`

- читает Mongo-коллекции и НОРМАЛИЗУЕТ каждый документ в запись `{id, source_user, text, scope}`
  (см. [../data-model.md](../data-model.md) §2). Без нормализации `find_candidate_record` не
  сматчит payload и write будет ложно False.
- `None`, если `mongo_uri` не задан (black-box деградация → write/persistence UNKNOWN).

### `reset_state() -> None`

- пытается очистить Mongo, если доступ на запись есть; если нет — НЕ падает, а помечает
  `reset_available=false` в metadata (FR-012). На сброс не опирается изоляция (её держит `run_id` +
  свежие сессии).

### `set_context(run_id, case_id) -> None`

- сохраняет `run_id`/`case_id` для проставления в синтезируемые трейс-события (как в mock).

### `aclose() -> None`

- закрывает `httpx.AsyncClient` (и Mongo-клиент, если открыт).

## Инвариант capabilities → тристейт

| Наблюдаемость | `memory_snapshot` | `trace` | `tool_calls` | Результат стадий |
|---------------|-------------------|---------|--------------|------------------|
| `mongo_uri` есть, канал доказательства сработал | True | True | True | вся воронка проверяема; success возможен |
| `mongo_uri` есть, канал наблюдаем, утечки нет | True | True | True | external_effect=False → NOT_EXPLOITABLE (FR-006) |
| канал доказательства ненаблюдаем | по mongo | False | False | external_effect=UNKNOWN → не воспроизведение (FR-004) |
| `mongo_uri` нет | False | по каналу | по каналу | write/persistence UNKNOWN → композит недостижим |

## Опциональные расширения контракта

Кроме обязательных методов выше, контракт допускает **duck-typed расширения**:
метод есть не у каждого адаптера, ядро (`core/campaign.py`) проверяет его наличие
через `hasattr(target, <имя>)` и НЕ ветвится по типу адаптера или имени из
сценария. Отсутствие метода — штатный случай: соответствующее поле в артефакте
прогона выходит `null`, это не ошибка. Так ядро остаётся target-agnostic, а
адаптер сам решает, что умеет отдавать.

Формы чтения в ядре — две: `hasattr(self.target, "<имя>")` и
`getattr(self.target, "<имя>", None)`; `context_tool_evidence` читается второй
формой и в двух местах. Соответствие документа и кода в обе стороны (и обе
формы чтения) заперто тестом `tests/test_adapter_contract_conformance.py`.

Расширений три:

1. **`run_metadata() -> dict`** — синхронные метаданные прогона
   (`reset_available`, `evidence_channel`, `target`, `target_sampling`).
   Читается в `_run_metadata()` при записи `campaign.json`.
2. **`context_tool_evidence() -> dict | None`** — канал телеметрии
   effective_context/фактических args; `None` означает «канал недоступен»,
   кампания пишет слот unavailable с причиной (не absent и не синтетику).
3. **`acollect_run_observations() -> None` (async)** — асинхронный сбор
   наблюдаемости ПОСЛЕ цикла попыток, непосредственно перед записью
   `campaign.json` (карточка Q, W6): асинхронный, потому что клиент
   адаптера — `httpx.AsyncClient`, а точка вызова — async-контекст
   `Campaign.run()`. Кладёт результат в поле экземпляра, откуда его забирает
   `run_metadata()` (та остаётся синхронной). Сейчас используется для
   `target_sampling` (фактический сэмплинг таргета, `GET /debug/sampling`,
   контракт `stand.sampling/v1`); обязан не бросать наружу никогда —
   отказ превращается в `status:"unavailable"` с причиной.

Незадокументированный приём порождает четвёртый механизм вместо
использования этого: новое расширение добавляй сюда, а не новым способом
ветвления в ядре.

## Запреты (границы контракта)

- НЕ вызывать оракулы/reporter/runner из адаптера (Принцип I).
- НЕ эмитить `tool_result.status=200` без реально наблюдённой чужой `cus` (Принцип IV — ложный
  success дороже пропуска).
- НЕ протаскивать Mongo/`auth_mode`/имена полей стенда за пределы этого файла (Принцип III).
