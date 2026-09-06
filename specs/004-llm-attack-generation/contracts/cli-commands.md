# Contract: CLI-команды и флаги

> Публичный CLI-контракт фичи (research §10). Расширяет
> [cli.py](../../../src/memnotsafe/cli.py) аддитивно: одна новая команда `generate` + флаги на
> существующих `run`/`campaign`. Существующие `probe`/`run`/`campaign`/`report`/`replay` сохраняют
> поведение и коды возврата (Принцип VII).

## Общий блок флагов конфигурации атакующей LLM

Общий у `generate` и онлайн-уровня `run`/`campaign` (одна модель в двух режимах). Секрет — только
через `--attacker-api-key-env` (имя переменной окружения), не значением (FR-016).

| Флаг | По умолчанию | Смысл |
|------|--------------|-------|
| `--attacker-provider` | `stub` | `stub` (офлайн/CI/демо) \| `openai` (живая генерация) |
| `--attacker-model` | — | Имя модели генератора |
| `--attacker-base-url` | — | Base URL для `openai`-совместимого провайдера |
| `--attacker-api-key-env` | `ATTACKER_API_KEY` | Имя переменной окружения с ключом |
| `--attacker-budget` | `50` | Лимит вызовов атакующей LLM на операцию (`CallBudget`) |

При `--attacker-model`, совпавшей с моделью цели, — предупреждение о наследовании слепых пятен
(FR-015), не ошибка.

## Команда `generate` (US1 — precompute)

Генерирует переиспользуемый корпус атак под профиль и сохраняет его.

```bash
memnotsafe generate \
  --profile profiles/support-agent.yaml \
  --classes attack_classes/ \
  --out corpora/support-agent.yaml \
  [--attacker-provider openai --attacker-model gpt-4o --attacker-api-key-env ATTACKER_API_KEY]
```

| Флаг | Обяз. | Смысл |
|------|-------|-------|
| `--profile` | да | Путь к файлу-профилю агента |
| `--classes` | нет | Каталог или список файлов описаний классов (по умолчанию `attack_classes/`) |
| `--out` | да | Куда сохранить корпус (`corpora/<name>.yaml`) |
| (+ общий блок конфигурации атакующей LLM) | | |

Коды возврата:

- `0` — корпус успешно сгенерирован и сохранён (даже если часть записей отбракована — FR-012).
- `1` — config-ошибка профиля/классов (research §3) ИЛИ сбой атакующей LLM (`AttackerError`,
  research §11). Ошибка печатается в `stderr`.

## Флаги онлайн-уровня на `run` / `campaign` (US2/US3)

```bash
memnotsafe campaign \
  --scenario scenarios/generated_support.yaml \
  --output runs/support \
  --online --online-attempts 5 \
  --attacker-provider openai --attacker-model gpt-4o
```

| Флаг | По умолчанию | Смысл |
|------|--------------|-------|
| `--online` | выкл | Включить онлайн-уровень (FR-009). Без флага — поведение как сейчас |
| `--online-attempts` | `5` | Предел попыток онлайн-эскалации на атаку (FR-008) |
| (+ общий блок конфигурации атакующей LLM) | | Действует только при `--online` |

Прогон корпуса **не требует нового флага**: сценарий с `attack.family: generated` и полем
`corpus: corpora/<name>.yaml` подхватывается существующими `run`/`campaign` (research §10).

Коды возврата (расширяют Принцип VII):

- `0` — прогон завершён: атака пробила или честно не пробила (`NOT_EXPLOITABLE`), в т.ч. когда
  онлайн-эскалация исчерпала лимит попыток или **бюджет** (штатный стоп, FR-010).
- `1` — сбой раннера/адаптера (`RunnerError`) ИЛИ сбой атакующей LLM (`AttackerError`, недоступность
  модели), при котором прогон не может продолжаться. Уже полученные результаты сохраняются в
  `runs/<name>/` до выхода (FR-010, FR-011, SC-005).

## Сценарий прогона корпуса (пример `scenarios/generated_support.yaml`)

```yaml
id: generated_support
target:
  adapter: mock
  vulnerable: true
actors:
  attacker:
    user_id: "1001"
  victim:
    user_id: "1002"
attack:
  family: generated
  corpus: corpora/support-agent.yaml
metrics:
  repetitions: 1
```
