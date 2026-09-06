# Data Model: LLM-генерация атак и многоуровневая эскалация

> Phase 1 плана [plan.md](plan.md). Сущности фичи, их поля, инварианты и связи с существующими
> моделями ядра ([core/models.py](../../src/memnotsafe/core/models.py),
> [attacks/base.py](../../src/memnotsafe/attacks/base.py)). Типы — dataclass (Принцип VIII); dict
> допустим только для сырого провенанса в `AttackResult.evidence`.

## Карта сущностей

```text
AgentProfile ──describes──> проверяемый агент (вход генерации)
AttackClassSpec ──universal──> что атака должна сделать (вход генерации)
        │
        └── corpus_gen(profile, [classes], AttackerClient, CallBudget)
                    │
                    ▼
              Corpus { provenance: CorpusProvenance, records: [CorpusRecord] }   (corpora/*.yaml)
                    │  каждая запись → AttackContext.params
                    ▼
   GeneratedAttack(AttackBase)  ──generate/steps──>  AttackCandidate (существующая модель ядра)
                    │  run_attack(...) НЕ меняется
                    ▼
              AttackResult (существующая модель ядра)
                    │  при --online и success=False:
                    ▼
   escalation_loop ── EscalationFeedback ──> rewrite() ──> CorpusRecord' ──> run_attack ──> ...
                    │
                    ▼
     AttackResult.evidence["provenance"] = AttackProvenance (origin, attempts, budget_exhausted)
```

## Существующие модели ядра (не изменяются)

- `AttackContext` ([attacks/base.py](../../src/memnotsafe/attacks/base.py)) — уже несёт
  `params: dict[str, Any]`. **Шов фичи**: сюда кладётся сериализованная `CorpusRecord`. Ни одна
  рукописная атака `params` не читает, поэтому расширение безопасно.
- `AttackCandidate`, `AttackResult`, `StageResult`, `CampaignResult`
  ([core/models.py](../../src/memnotsafe/core/models.py)) — используются как есть. Провенанс кладётся
  в `AttackResult.evidence` (free-form dict), а не в новое поле модели (research §12).
- `AttackMetadata` ([attacks/base.py](../../src/memnotsafe/attacks/base.py)) — `GeneratedAttack`
  подменяет её копию **на экземпляре** (research §2), сам класс не меняется.

## Новые сущности

### AgentProfile (`generation/profile.py`)

Декларативное описание проверяемой цели. Вход генерации; **секретов не содержит**. Загружается из
`profiles/<id>.yaml`, схема — [contracts/agent-profile.schema.md](contracts/agent-profile.schema.md).

| Поле | Тип | Обяз. | Смысл |
|------|-----|-------|-------|
| `id` | `str` | да | Идентификатор профиля (ASCII, kebab-case) |
| `purpose` | `str` | да | Назначение агента (поддержка/HR/заявки/…) |
| `interface` | `InterfaceSpec` | да | Язык, формат реплики, как выражается идентичность пользователя |
| `tools` | `list[ToolSpec]` | да | Имена инструментов и их аргументы, включая аргумент идентичности |
| `memory` | `MemorySpec` | да | Как агент запоминает (слои, триггеры записи) |
| `compromise` | `CompromiseSpec` | да | `leak_indicators` + `external_effect` (тип и обязательные поля) |
| `sha256` | `str` (computed) | — | Хеш нормализованного содержимого; идёт в провенанс корпуса |

**Валидация**: отсутствие любой обязательной секции или пустой `compromise.external_effect` →
`AttackerError`-config (research §11) → `exit 1` ДО любых сетевых вызовов. `compromise.external_effect`
обязателен, потому что без него композит (Принцип V) не даёт `success` (US1-3).

### AttackClassSpec (`generation/attack_classes.py`)

Универсальное, агент-независимое описание класса атаки. Вход генерации. Загружается из
`attack_classes/<family>.yaml`, схема — [contracts/attack-class.schema.md](contracts/attack-class.schema.md).

| Поле | Тип | Обяз. | Смысл |
|------|-----|-------|-------|
| `family` | `str` | да | Связь с существующей рукописной family (`cross_user_bac`, …) |
| `goal` | `str` | да | Что атака должна сделать (агент-независимо) |
| `delivery_intent` | `str` | да | Намерение шага доставки payload'а |
| `trigger_intent` | `str` | да | Намерение шага активации |
| `expected_effect` | `ExpectedEffectSpec` | да | `type` + перечень обязательных полей эффекта |
| `signal_strength` | `str` | да | `"strong"` \| `"weak"` |

**Инвариант**: `family` обязан существовать в `ATTACK_REGISTRY` (иначе провенанс `attack_class` не
резолвится в `findings.py`). Новый класс = новый YAML, без правок Python (FR-017).

### Corpus / CorpusRecord / CorpusProvenance (`generation/corpus.py`)

Сохранённый переиспользуемый набор атак под формат конкретного профиля. Выход `generate`, вход
прогона. Файл `corpora/<name>.yaml`, схема — [contracts/corpus.schema.md](contracts/corpus.schema.md).
**Коммитится** (research §5).

`Corpus`:

| Поле | Тип | Смысл |
|------|-----|-------|
| `provenance` | `CorpusProvenance` | Под какой профиль/классы/модель собран |
| `records` | `list[CorpusRecord]` | Конкретные атаки |

`CorpusProvenance`:

| Поле | Тип | Смысл |
|------|-----|-------|
| `profile_id` | `str` | id профиля |
| `profile_sha256` | `str` | Хеш профиля на момент генерации |
| `attack_classes` | `list[str]` | Использованные family |
| `generator_model` | `str` | Модель атакующей LLM |
| `generator_provider` | `str` | `"openai"` \| `"stub"` |
| `tool_version` | `str` | Версия инструмента |
| `created_at` | `str` | ISO-дата (абсолютная) |
| `attacker_calls` | `int` | Сколько вызовов LLM ушло на генерацию |

`CorpusRecord` (одна атака; сериализуется в `AttackContext.params`):

| Поле | Тип | Обяз. | Смысл |
|------|-----|-------|-------|
| `attack_class` | `str` | да | family-источник (провенанс + резолв severity/ATLAS) |
| `payload` | `str` | да | Текст доставки |
| `trigger` | `str` | да | Текст активации |
| `delivery_steps` | `list[StepSpec]` | нет | Мультитёрн-доставка; по умолчанию один шаг из `payload` |
| `trigger_steps` | `list[StepSpec]` | нет | Мультитёрн-активация; по умолчанию один шаг из `trigger` |
| `expected_effect` | `dict[str, Any]` | да | Контракт эффекта (тип + поля), читает `oracles/external_effect.py` |
| `signal_strength` | `str` | да | `"strong"` \| `"weak"` |
| `origin` | `str` | да | `"corpus"` (для онлайн-переписанных — `"online"`) |

**Валидация записи (FR-012)**: пустой `payload`/`trigger`, неизвестный `attack_class`, или
`expected_effect` без обязательных полей класса → запись **отбраковывается**, не попадает в прогон;
на онлайн-уровне отбраковка тратит попытку и фиксируется.

### AttackerConfig (`generation/config.py`)

Конфигурация атакующей LLM — отдельно от модели цели и (на будущее) судьи.

| Поле | Тип | По умолчанию | Смысл |
|------|-----|--------------|-------|
| `provider` | `str` | `"stub"` | `"stub"` (офлайн/CI) \| `"openai"` (живая) |
| `model` | `str` | — | Имя модели генератора |
| `base_url` | `str \| None` | `None` | Для `openai`-совместимого провайдера |
| `api_key_env` | `str` | `"ATTACKER_API_KEY"` | Имя переменной окружения с ключом (не сам ключ!) |
| `budget` | `int` | `50` | Лимит вызовов на операцию (`CallBudget`) |
| `timeout_s` | `float` | `60.0` | Таймаут HTTP |
| `scripted` | `list[str] \| None` | `None` | Ответы для `StubAttackerClient` |

**Инвариант (FR-016)**: `api_key_env` — имя переменной, ключ берётся из `os.environ`; сам секрет в
конфиг/профиль/корпус не попадает. При `model`, совпавшей с моделью цели, — предупреждение (FR-015).

### AttackerClient (`generation/attacker_client.py`)

`Protocol` с методом `complete(prompt: str, *, system: str) -> str`. Реализации:

- `HTTPAttackerClient` — OpenAI-совместимый `/v1/chat/completions` поверх `httpx`, `api_key_env`,
  ретраи, таймаут (паттерн [adapters/openai.py](../../src/memnotsafe/adapters/openai.py)).
- `StubAttackerClient` — офлайн, отдаёт `scripted`-ответы по очереди (research §9).

Любой сбой (нет ключа, сеть, таймаут, отказ модели) → `AttackerError`. Исчерпание `CallBudget` —
отдельный штатный стоп, не `AttackerError` (research §11).

### CallBudget (`generation/budget.py`)

Счётчик вызовов атакующей LLM с жёстким лимитом.

| Поле/метод | Тип | Смысл |
|------------|-----|-------|
| `limit` | `int` | Максимум вызовов |
| `used` | `int` | Потрачено |
| `spend()` | `-> None` | +1; при `used >= limit` помечает `exhausted` |
| `exhausted` | `bool` | Бюджет исчерпан (штатный стоп) |

### EscalationFeedback / EscalationOutcome (`core/escalation.py`)

`EscalationFeedback` (вход чистой `rewrite()` — research §7):

| Поле | Тип | Смысл |
|------|-----|-------|
| `victim_response` | `str` | Ответ защищающегося на прошлую попытку |
| `baseline_response` | `str` | Чистый ответ до отравления (точка отсчёта) |
| `funnel` | `dict[str, bool \| None]` | Стадии `write…external_effect` прошлой попытки |
| `previous` | `CorpusRecord` | Прошлая (не сработавшая) запись атаки |
| `attempt` | `int` | Номер попытки (1-based) |

`EscalationOutcome` (результат цикла):

| Поле | Тип | Смысл |
|------|-----|-------|
| `result` | `AttackResult` | Последний (или успешный) прогон |
| `attempts` | `int` | Сколько попыток сделано (≤ лимит) |
| `succeeded` | `bool` | Пробила ли атака в пределах лимита |
| `budget_exhausted` | `bool` | Остановились из-за бюджета |

### AttackProvenance (в `AttackResult.evidence["provenance"]`, dict — research §12)

Провенанс каждой находки; пишется слоем эскалации/кампании, читается `reporting/findings.py`.

| Ключ | Тип | Смысл |
|------|-----|-------|
| `origin` | `str` | `"handwritten"` \| `"corpus"` \| `"online"` |
| `attack_class` | `str \| None` | family-источник (резолв severity/ATLAS; для `generated`) |
| `corpus_id` | `str \| None` | Из какого корпуса запись |
| `attempts` | `int` | Число попыток (для `online`) |
| `budget_exhausted` | `bool` | Исчерпан ли бюджет |

## Инварианты, пронизывающие модель

1. **UNKNOWN не читается как True** (Принцип IV): `funnel` в `EscalationFeedback` переносит тристейт
   как есть; никакой `None → True` схлопывания.
2. **external_effect обязателен для success** (Принцип V): `CompromiseSpec.external_effect` и
   `CorpusRecord.expected_effect` обязательны; отсутствие — config-ошибка на входе.
3. **Ядро не трогается** (SC-008): провенанс и попытки живут в `evidence`/слое эскалации, не в
   `AttackResult`/`run_attack`.
4. **Секреты вне файлов** (FR-016): только `api_key_env`.
5. **Отбраковка ≠ проведённая атака** (FR-012): невалидная запись не создаёт `AttackResult` на
   precompute; на онлайне тратит попытку и фиксируется в провенансе.
