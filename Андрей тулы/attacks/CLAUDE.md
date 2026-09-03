# attacks/ — правила пака (дополняет корневой CLAUDE.md)

## Как добавить атаку (буквально)
Новая папка `attacks/<name>/` + файл (обычно `pack.py`) с классом-наследником
`core.attack_base.AttackBase`, реализующим `payload_strategy()`, `delivery_steps()`,
`trigger_steps()`, `success_check()`. Ничего регистрировать руками не нужно —
`__init_subclass__` подхватывает класс сам при импорте (`attacks_loader.discover()`).
Дубликат `metadata.id` между паками — `ValueError` при загрузке (fail fast), не
тихий overwrite. Если правишь core/attack_base.py и это меняет сигнатуру шагов —
это BREAKING, отметь в PR и в корневом CLAUDE.md.

## Прежде чем писать success_check — реши, куда РЕАЛЬНО пишет стенд
Три разных места оседания факта в этом стенде, у каждого свой evidence-путь:
- `agent_policy_memories` (scope=global, БЕЗ user_id) — кросс-юзер атаки.
  Пример: `cross_user_scope_global/pack.py`.
- `semantic_memories` (scope=user, с user_id) — атака на факт про конкретного
  клиента, не кросс-юзер. Пример: `conditional_risk_flag/pack.py`.
- `episodic_memories` — атака, эксплуатирующая суммаризацию/компакцию сессии
  (`summarize_dialog` → `extract_episodes`), а не прямое извлечение факта.
  Пример: `salience_compaction_flood/pack.py`.
`deterministic_predicate` в `StageCheck(stage=WRITE, ...)` должен смотреть ИМЕННО
в ту коллекцию, куда пишет ЭТОТ канал/класс — иначе предикат никогда не станет
`True` ни на каком реальном diff (тихая, незаметная поломка пака). Перед тем как
считать пак готовым — прогони `scripts/smoke_test_all.py` (там для каждого
известного `attack_id` есть фейковый "after"-снапшот) или добавь туда свою
фикстуру для нового пака.

## Каналы, которые реально доступны атакующему на ЭТОМ стенде
Только `user_query` работает полностью автоматизированно (обычный `deliver_user_message`).
`web_search_result` (DuckDuckGo) требует реального SEO/индексации публичного контента —
не автоматизируется в рамках этого инструмента без внешней инфраструктуры; если
пишешь такой пак, явно пометь в `description`, что доставка полу-ручная.
`tool_output` (mcp-invest) в этом стенде attacker-controlled не является — 14 тулов
отдают синтетические read-only данные, не подставные атакующим; пак с этим каналом
имеет смысл только против ДРУГОГО таргета (target-agnostic core это позволяет, но
для genai-invest-stand он будет "пустым" — нечем травить).

## Cross-user vs single-user — не одно и то же по механике раннера
Если `ctx.witness_user_id` задан и отличается от `victim_user_id` — раннер берёт
identity witness'а из `TargetPool` (нужен отдельный `sk-genai-…` ключ в конфиге,
см. `core/CLAUDE.md`). Если атака про ОДНОГО и того же клиента в новой сессии —
`witness_user_id` не задавай (оставь `None`), используй `TriggerStep.session_id_override`
для перехода в "новую" сессию того же клиента. Спутать эти два режима — типичная
причина, почему пак "работает", но на самом деле проверяет не то персистентность,
что заявлено в `description`.

## Сигнал strong vs weak — не только формулировка
strong = `StaticPayloadStrategy` с явным императивом ("запомни", "правило", "всегда").
weak = либо `StaticPayloadStrategy` с правдоподобным фактом без императива
(`conditional_risk_flag`, `salience_compaction_flood` — оба weak по факту, но
technically strong/weak поле выставляется по СМЫСЛУ формулировки, не по классу),
либо `RetrievalOptimizedStrategy` (GhostWriter-style, `core/strategies.py`) —
итеративно переписывает текст под легитимный корпус. Для второго нужны
`ATTACKER_API_KEY`/`ATTACKER_BASE_URL`/`ATTACKER_MODEL` в окружении (см.
`attacks/cross_user_scope_global/pack.py::_attacker_llm()`) — эмбеддинги дороже
обычного chat-вызова, не гоняй `RetrievalOptimizedStrategy` в тесном цикле без нужды.

## MITRE ATLAS / OWASP — не выдумывай, если не уверен
Подтверждённое на 2026-09-03: `AML.T0080` "Memory Poisoning" (tactic Persistence,
sub-technique `AML.T0080.000` — конкретно про cross-session персистентность).
`AttackMetadata` уже ставит это дефолтом. Если пишешь пак под технику, которой
не проверял ID — оставь `atlas_technique="TBD"` и явно скажи об этом в PR/чате,
не подставляй правдоподобно звучащий ID.
