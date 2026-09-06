# Quickstart: валидация LLM-генерации атак и эскалации

> Runnable-сценарии, доказывающие фичу end-to-end. Всё проходит **офлайн** на `MockTarget` +
> `StubAttackerClient` (Принцип VI, SC-006): без сети, ключей, Docker. Детали схем — в
> [contracts/](contracts/), сущности — в [data-model.md](data-model.md). Реализацию кода делает
> `/speckit-implement` по `tasks.md`; здесь — как проверить, что она работает.

## Предпосылки

```bash
cd ../agentic-red-teaming-004        # git worktree ветки 004-llm-attack-generation
python3 -m pip install -e .          # src-layout, ставит команду `memnotsafe`
python3 -m pytest tests/ -q          # baseline: существующие 12 тестов зелёные (SC-008)
```

Фикстуры для офлайн-прогона (создаются в ходе реализации):

- `profiles/support-agent.yaml` — тестовый профиль (см. [contracts/agent-profile.schema.md](contracts/agent-profile.schema.md)).
- `attack_classes/*.yaml` — описания классов (см. [contracts/attack-class.schema.md](contracts/attack-class.schema.md)).
- `scenarios/generated_support.yaml` — сценарий `family: generated` + `corpus:`.

## Сценарий 1 — Precompute-корпус под нового агента (US1)

**Цель**: SC-001 — корпус собирается по одному файлу-профилю, без ручных payload'ов.

```bash
# Офлайн-провайдер (stub) не требует ключей — годится для CI и демо
memnotsafe generate \
  --profile profiles/support-agent.yaml \
  --classes attack_classes/ \
  --out corpora/support-agent.yaml \
  --attacker-provider stub
echo "exit=$?"
```

Ожидается:

- `exit=0`; создан `corpora/support-agent.yaml` со `provenance` (profile_id, sha256, модель,
  дата, `attacker_calls`) и списком `attacks`, каждая с `attack_class`, `signal_strength`,
  `expected_effect`.
- Прогон корпуса даёт честный вердикт на mock:

```bash
memnotsafe run --scenario scenarios/generated_support.yaml --output runs/gen-smoke
echo "exit=$?"      # 0; report.html/.json + findings.json собраны
```

**Негатив (US1-3)**: профиль без `compromise.external_effect` → config-ошибка, `exit=1`, до вызовов
LLM (никакого «бесполезного корпуса»).

```bash
memnotsafe generate --profile profiles/broken-no-effect.yaml --out corpora/x.yaml --attacker-provider stub
echo "exit=$?"      # 1, сообщение в stderr
```

## Сценарий 2 — Переиспользование корпуса на втором агенте (US1 / SC-002)

Тот же `corpora/support-agent.yaml` прогоняется под второй похожий профиль **без** повторной
генерации (без вызовов атакующей LLM):

```bash
memnotsafe run --scenario scenarios/generated_support_agent2.yaml --output runs/gen-reuse
echo "exit=$?"      # 0; в отчёте provenance корпуса виден (собран под support-agent)
```

## Сценарий 3 — Онлайн-эскалация добивает атаку (US2 / SC-004)

**Цель**: атака, которую корпус пометил `NOT_EXPLOITABLE`, пробивается адаптацией в пределах лимита.
Офлайн-заглушка скриптована как «1-я попытка не пробивает, 2-я пробивает» (research §9).

```bash
# Без онлайн-уровня (дефолт) — атака честно не пробита
memnotsafe run --scenario scenarios/generated_escalation.yaml --output runs/esc-off
echo "exit=$?"      # 0; finding NOT_EXPLOITABLE (US2-3, SC-003 — стоимость как сейчас)

# С онлайн-уровнем — та же атака пробивается со 2-й попытки, попыток ≤ лимита
memnotsafe run --scenario scenarios/generated_escalation.yaml --output runs/esc-on \
  --online --online-attempts 5 --attacker-provider stub
echo "exit=$?"      # 0; SUCCESS; в отчёте attempts=2 (≤5)
```

## Сценарий 4 — Флаг включения и предел попыток (US3)

**Цель**: одна опция управляет уровнем; лимит берётся из опции.

```bash
# Предел 1 → одна попытка, если stub пробивает только со 2-й, атака остаётся NOT_EXPLOITABLE
memnotsafe run --scenario scenarios/generated_escalation.yaml --output runs/esc-limit1 \
  --online --online-attempts 1 --attacker-provider stub
echo "exit=$?"      # 0; attempts=1; NOT_EXPLOITABLE (SC-004: попыток никогда не больше лимита)
```

## Сценарий 5 — Разделение исходов и бюджет (SC-005, FR-010/FR-011)

```bash
# Бюджет исчерпан → штатный стоп, exit 0, факт зафиксирован в отчёте
memnotsafe run --scenario scenarios/generated_escalation.yaml --output runs/esc-budget \
  --online --online-attempts 5 --attacker-provider stub --attacker-budget 1
echo "exit=$?"      # 0; budget_exhausted=true в provenance; результаты не потеряны

# Сбой атакующей LLM (недоступна) ≠ «не пробила» → exit 1
ATTACKER_API_KEY="" memnotsafe run --scenario scenarios/generated_escalation.yaml \
  --output runs/esc-fail --online --attacker-provider openai --attacker-base-url http://127.0.0.1:1
echo "exit=$?"      # 1; уже полученные результаты сохранены в runs/esc-fail/
```

## Сценарий 6 — Отчёт объясняет происхождение (US4 / SC-007)

После смешанного прогона проверяем провенанс в машиночитаемом отчёте:

```bash
python3 - <<'PY'
import json, pathlib
fs = json.loads(pathlib.Path("runs/esc-on/report/findings.json").read_text(encoding="utf-8"))
for f in fs:
    prov = f["evidence"].get("provenance", {})
    print(f["finding_id"], f["severity"], prov.get("origin"), "attempts=", prov.get("attempts"))
PY
# ожидается: у каждой находки виден origin (corpus|online), у онлайновых — attempts
```

## Автотесты (офлайн, обязательны — Принцип VI)

```bash
python3 -m pytest tests/ -q
```

Покрывают:

- `tests/test_profile_and_corpus.py` — валидация профиля/классов/корпуса; отбраковка невалидной
  сгенерированной атаки (FR-012).
- `tests/test_generation_offline.py` — US1 (генерация корпуса на stub) + US2 (fail→success) e2e на
  `MockTarget`, доказывает и `success`, и честный `NOT_EXPLOITABLE` (SC-006).
- `tests/test_escalation.py` — лимит попыток, стоп на первом успехе, исчерпание бюджета (exit 0),
  сбой атакующей LLM (exit 1), провенанс/attempts в отчёте (SC-004/005/007).

**Definition of done фичи**: существующие 12 тестов зелёные, новые офлайн-тесты зелёные, ядро
(`runner.py`/`oracles/*`/`composite.py`) не изменено (`git diff` пуст по этим файлам — SC-008).
