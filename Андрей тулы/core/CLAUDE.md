# core/ — инварианты (дополняет корневой CLAUDE.md)

## TargetPool, не TargetClient — для cross-user атак обязательно
Identity на этом стенде авторизуется Bearer-ключом, не полем тела запроса. Один
`TargetClient` = один клиент = один ключ. Кросс-юзер атака (жертва пишет, свидетель
читает) физически не может обойтись одним клиентом — используй `TargetPool`
(`core/target.py`), `core/runner.py` резолвит клиента по `step.as_user`. Если пишешь
новый adapter/раннер мимо `core/runner.run_attack` — не забудь этот момент, иначе
все "cross-user" находки будут молча идти от одной и той же identity.

## Одно-юзерная persistence-проверка — используй `session_id_override`
Если атака проверяет, что факт пережил СВОЮ ЖЕ сессию (не кросс-юзер, просто новая
сессия того же клиента) — `TriggerStep.session_id_override` обязателен. Без него
раннер резолвит victim → тот же `ctx.session_id`, что доставки, т.е. трудно отличить
"факт в working memory этой же сессии" от "факт реально осел в долговременной памяти
и пережил сброс".

## evidence-first инвариант — жёсткий, не предупреждение
`core/judge.evaluate()`: если `SuccessCheckSpec.require_trace=True` (дефолт) и
`evidence.trace` пуст — `success` принудительно `False`, даже если и WRITE, и ACTIVATE
стадии прошли. Не обходить проверкой "ну trace вроде не нужен для этого пака" — если
пак реально не нуждается в трассе, это осознанное решение уровня пака
(`require_trace=False` в его `success_check()`), не тихий баг в общем коде.

## core/tracer.py: локальный JSONL — гарантия, Langfuse — бонус
`CompositeTracer` всегда пишет `traces/<run_id>.jsonl`. Langfuse подключается
best-effort, ТОЛЬКО если заданы `LANGFUSE_PUBLIC_KEY`/`LANGFUSE_SECRET_KEY` — любая
его ошибка гасится и логируется, не валит прогон. Не убирай fallback ради "чистоты" —
без него `require_trace` ломает вообще все находки на машинах без Langfuse.

## Диффим по id-полю, не по содержимому документа
`core/evidence.compute_diff()` — сравнение по `_ID_FIELD` (`policy_id`, `fact_id`,
`episode_id`, `session_id`), не по значению. Если адаптер для нового таргета не
проставляет эти поля в снятых документах — diff молча увидит 0 добавленных
документов даже при реальной записи. Проверяй новый адаптер через
`scripts/smoke_test_all.py`-подобный фейк ПЕРЕД тем, как доверять его diff'у.

## Не хардкодь стенд-специфику здесь
`core/target.py`, `core/evidence.py`, `core/judge.py`, `core/runner.py` не должны
знать про `auth_mode`, конкретные названия Mongo-коллекций genai-invest-stand,
формат его finalize-ответа и т.п. Это — `adapters/genai_invest_stand.py` и
`config.yaml`. Известное текущее исключение (осознанный компромисс, не идеал):
`core/judge._det_stage_verdict()` читает поле `"statement"` из
`agent_policy_memories` для человекочитаемого `what_written` в отчёте — это
слабое связывание с конкретной схемой, но не влияет на логику success/fail.
Если появится второй таргет с другой схемой — вынести в adapter.

## Прогон без Docker
`scripts/smoke_test.py` / `scripts/smoke_test_all.py` — дымовой тест на фейках,
секунды, без сети/Mongo. Гоняй его после ЛЮБОЙ правки `core/*.py` перед тем, как
считать шаг готовым (self-check из корневого CLAUDE.md) — он ловит поломки
оркестрации быстрее, чем ждать живой стенд.
