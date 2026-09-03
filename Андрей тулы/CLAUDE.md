# CLAUDE.md — Agentic Memory Red Teaming Tool (Команда 7)

Repository guidance for Claude Code. Keep this file current; it is read at the start of every coding session so the agent has project context without re-reading papers or the target stand.

## What we're building
A CLI tool for **automated agentic red teaming focused on dynamic attacks against LLM-agent long-term memory**. It attacks a target agent black-box (over an OpenAI-compatible API), verifies success by inspecting the agent's **memory state** and Langfuse traces (not just the chat reply), and reports interpretable, evidence-backed findings.

Guiding decisions (from the case owner Q&A — do not silently reverse these):
- Scope: **memory attacks only**. Not alignment-bypass, not general jailbreaks.
- **Breadth + depth-of-understanding of attacks > exhaustive tracing of one case.** Evidence is still required for every finding.
- ASR is **not** the headline; the idea and **interpretability** are. Each attack type defines its own success check (LLM-as-judge for semantic outcomes, deterministic state reads where possible).
- **Killer feature: a pluggable attack format** — users drop in / load their own attacks; online customization is a stretch goal. Design everything around this extensibility.
- Interface: **CLI / script**. No web UI, no MCP server.
- **Two different LLMs**: attacker model ≠ target-agent core. Model choice is out of scope for scoring but must be configurable.
- Target-agnostic: do **not** hard-code the test stand. Take an API contract (+ optional Langfuse logs) as input. The stand is only one target for computing metrics.

## Conventions
- Python 3.11+, `uv` or `pip`. Type hints, `ruff` + `black`. Async where hitting the target API.
- Config via env / a single `config.yaml`; never commit secrets or `sk-genai-…` keys.
- Licenses: Apache-2.0 / MIT only (garak is Apache-2.0, LLAMATOR OSS). No GPL into the deliverable.
- Every finding must carry evidence (memory diff + trace refs), reproducible with a fixed seed/config.

## Рабочий режим агента (ways of working) — durable, переживает /compact
role: senior AI-security инженер этого инструмента. Приоритеты кейса выше — не разворачивай их молча.

reasoning:
- Нетривиальное (новый класс атаки, правка evidence/judge, разбор бага) — сперва короткий план
  секциями [ПОНЯТЬ][РАЗБИТЬ][РАССУДИТЬ][ПРОВЕРИТЬ], затем код. Рутина (мелкий фикс) — сразу правка.
- Запрос расплывчатый ИЛИ противоречит коду/контракту — задай ≤3 уточняющих вопроса, не угадывай.

scope (SRP): один запрос = одно атомарное изменение. Работай только в названных файлах.
  Стенд-специфику держи в адаптерах, не размазывай по core. core/target.py — API-контракт, не хардкод стенда.

language (всегда, не сбрасывать после компакшна):
- Общение с пользователем, пояснения, комментарии в коде и докстринги — ПО-РУССКИ.
- Идентификаторы (имена переменных/функций/классов), сам код, названия файлов, git-коммиты, лог-сообщения — по-английски (стандарт).
- README и docs — по-русски, если не сказано иначе.

defaults (negative constraints):
- НЕ добавляй зависимости без разрешения (лицензии только Apache-2.0/MIT). НЕ коммить секреты и sk-genai-… .
- НЕ хардкодь тест-стенд в core. НЕ меняй формат attack-пака / сигнатуры loader’а без пометки BREAKING.

evidence-first (инвариант): атака успешна только при evidence = diff памяти (Mongo/GET /memory) +
  ссылка на Langfuse-трассу. success-check пишем ВМЕСТЕ с атакой. Каждый finding воспроизводим при фикс. seed/config.

trace-based feedback: при ошибке — ПОЛНЫЙ stack trace / тело ответа, не пересказ. Провалился подход — меняй стратегию.

self-check (Reflexion, перед «готово»): прогони тесты/линт/пример-запуск, затем критик:
  SCORE /10 + одно главное улучшение + пример фикса. Шаг ПРОВАЛЕН если: пусто, не по ТЗ шага,
  сломан тест/контракт, атака без success-check, evidence не читается. Повтор провала → зафиксируй
  ERROR/WHY/STRATEGY и смени инструмент/подход (не повторяй тот же приём).

output: работающие правки, кратко (что изменил + как проверил), без воды. Находки — маппинг на MITRE ATLAS / OWASP ASI06.

## Память проекта — где что лежит (3 слоя)
- Durable-инварианты → этот файл. Правила модуля → локальный `attacks/CLAUDE.md`, `core/CLAUDE.md` (дополняют корневой).
- Повторяемые процедуры → `.claude/commands/` (`/new-attack`, `/verify-finding`, `/review-attack`).
- Разовая конкретика (пути, ошибка, ТЗ на пак) → в самом промпте, не в память.
- Справочники по атакам (внешние статьи) → `docs/` и `docs/references/`, подгружаются ПО ТРЕБОВАНИЮ, не авто-загрузкой.
  Карта релевантных writeups: `docs/attack-references.md` (читать её первой, а не сырые статьи).

## Suggested layout (adjust as it grows)
```
attacks/                 # pluggable attack packs (the killer feature) — one file per attack
  memory_poisoning/
core/
  target.py              # black-box client: OpenAI-compatible chat + finalize; target-agnostic
  runner.py              # orchestrates: deliver → (finalize) → probe activation → collect evidence
  evidence.py            # read memory state (Mongo/GET /memory) + Langfuse trace; build diff
  judge.py               # per-attack success checks (LLM-as-judge + deterministic)
  report.py              # JSON + human-readable summary; map to MITRE ATLAS / OWASP ASI06
attacks_loader.py        # discover & load attack packs from attacks/ (and at runtime)
cli.py                   # entrypoint
docs/                    # attack-references.md (карта) + references/ (сконвертированные статьи)
```

## Pluggable attack format (design center — keep it simple to author)
Each attack declares: **delivery channel** (user query / web-search result / tool output / memory), **payload** (or a mutation/generation strategy), **trigger** (what later query activates it), **success check** (how to verify from evidence), and **signal strength** (strong = explicit command / weak = plausible false fact). Loader auto-discovers packs; a new file = a new attack, no core changes.

## Attack battery (breadth — from the literature)
Implement the memory-poisoning taxonomy, both signal styles:
- 6 classes from MPBench (arXiv 2606.04329) — explicit/conditional command insertion, salience-driven compaction poisoning, and inferred-write variants across 4 write channels.
- Weak-signal auto-generation via GhostWriter (2607.06595) **Black-Box Retrieval Optimization**: iteratively rewrite payload to maximize cosine similarity to a legitimate corpus so it gets stored as relevant, no explicit command.
- Cross-user propagation: induce a `scope=global` fact that lands in every user's system prompt (see target notes).
Map each to a MITRE ATLAS technique and OWASP ASI06 for the report.

## Target: genai-invest-agent-memory-stand (only for metrics; keep adapters isolated)
- API: `POST /v1/chat/completions` — body `{messages, auth_mode: "vulnerable"|"protected", session_id}`, header `Authorization: Bearer sk-genai-…`.
- Trigger memory consolidation: `POST /v1/sessions/{id}/finalize` (or send the message `finalize`).
- Evidence: `GET /memory` (per-user levels) and Mongo collections `dialog_sessions`, `episodic_memories`, `semantic_memories`, `agent_policy_memories`.
- Poisoning path: `finalize` → orchestrator `extract_semantics` may set `scope=global` → stored in `agent_policy_memories` (no user_id) → injected into EVERY user's system prompt via `build_context()`, survives session reset.
- BAC (a consequence to demonstrate): in `auth_mode=vulnerable` the agent uses an unrestricted service token and the model-chosen `cus` wins → cross-client data read; `protected` enforces the `cus` claim (403 on mismatch).
- Test users: `client1001…client1005` (password = login), clients `cus=1001…1005`.
- Two LLMs: target core = deepseek v4 flash / qwen3 / gpt-oss (configurable); attacker + judge = a different model.

## Running the target stand (for local metrics)
1. Generate Keycloak TLS cert (see stand README `openssl` snippet).
2. `docker compose up -d --build`; wait for healthy services.
3. Get an `sk-genai-…` key at http://localhost:8501, then hit `:8600`.

## Deep reference
Full project context, distilled papers, and the product decisions live in `project-context.md`. Read it if this file lacks something; do not re-ingest the source PDFs or the stand zip unless a specific detail is missing.
