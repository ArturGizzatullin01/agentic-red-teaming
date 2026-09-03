# Agentic Memory Red Teaming Tool — ядро

CLI-инструмент для автоматизированного red teaming атак на долговременную память
ИИ-агента (см. `CLAUDE.md`, `project-context.md` — полный контекст кейса).

## Быстрый старт

```bash
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt

# Без живого стенда — дымовой тест на фейках (секунды, ничего не поднимать):
./.venv/Scripts/python.exe scripts/smoke_test_all.py

# Что подхватилось из attacks/:
./.venv/Scripts/python.exe cli.py list

# Против живого стенда (см. HANDOFF_2026-09-03.md — как поднять):
cp config.example.yaml config.yaml   # вписать свои ENV-имена ключей
./.venv/Scripts/python.exe cli.py run <attack_id>
./.venv/Scripts/python.exe cli.py run-all
```

## Структура
```
core/               — target-agnostic ядро (target/evidence/judge/runner/report/tracer)
adapters/            — стенд-специфика (сейчас: genai-invest-agent-memory-stand, Mongo)
attacks/             — pluggable attack-паки (killer feature — просто дропнуть файл)
attacks_loader.py    — автоподхват паков
cli.py               — list / run / run-all / reload
config.example.yaml  — профиль запуска (скопировать в config.yaml, не коммитить)
scripts/             — smoke_test.py, smoke_test_all.py — self-check без Docker
```

Подробности по каждому модулю — `core/CLAUDE.md`, `attacks/CLAUDE.md` (инварианты,
на что наступать не надо). Состояние сессии/что заблокировано — `HANDOFF_2026-09-03.md`.

## Текущая батарея атак (4, из 3 классов MPBench)
| id | класс | канал | сигнал | evidence-цель |
|---|---|---|---|---|
| `cross_user_scope_global_strong_v1` | explicit_command_insertion | user_query | strong | `agent_policy_memories` |
| `cross_user_scope_global_weak_v1` | inferred_write_memory | user_query | weak (retrieval-optimized) | `agent_policy_memories` |
| `conditional_risk_flag_v1` | conditional_command_insertion | user_query | strong | `semantic_memories` |
| `salience_compaction_flood_v1` | salience_compaction_poisoning | user_query | weak | `episodic_memories` |

Не покрыто (нет attacker-controlled канала на ЭТОМ стенде — см. `attacks/CLAUDE.md`):
`inferred_write_tool_output`, `inferred_write_web`.

## Принципы (не нарушать без обсуждения — см. корневой CLAUDE.md)
- **Evidence-first**: находка засчитывается только при diff памяти И trace_ref.
- **Target-agnostic core**: стенд-специфика — только в `adapters/` и `config.yaml`.
- **Пак = файл**: новая атака не требует правок `core/`, только новый класс в `attacks/`.
- **Self-check перед "готово"**: `scripts/smoke_test_all.py` должен быть зелёным.
