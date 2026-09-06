# Research: 003-runtime-profiles

**Created**: 2026-09-06. Источники: [аудит](../../docs/integration-handoff/audit.md)
A09–A11, [контракты ролей](../../docs/integration-handoff/contracts.md), донорские
пресеты (не секретный live-конфиг).

## Решения

1. **Профили из донорских примеров, не из live-конфига.** Default attacker — static;
   runtime-пресеты qwen/glm описываются в публичных scenario-примерах. Реальные model
   ID/endpoint проверяются probe; handoff-описание не гарантирует доступность.
   Judge-профиль сохраняет `deepseek-v4-flash` как заявленную конфигурацию источника,
   без молчаливой замены.
2. **A09 (смена target).** Sanity без readback не доказывает модель; `.env.bak`,
   перетираемый каждым переключением, — потеря исходного состояния. Решение:
   именнованный бэкап профиля, recreate сервиса, readback из конфигурации стенда без
   секретов, restore в finally, отдельная ошибка restore с фактическим состоянием.
3. **A10 (async в sync generate).** Поднимать runtime-LLM внутрь sync
   `AttackBase.generate` запрещено. Решение: runner резолвит candidate через async
   сервис до шагов доставки; static путь не меняется; Attack остаётся описанием (роль I).
4. **A11 (долг dict-типов).** Новые контракты — dataclass; существующие
   `expected_effect`/`params` конвертируются на границе чтения конфигурации; массовая
   миграция не входит в работу.
5. **reasoning_content (донорский факт).** GLM-flash возвращает content=None при
   малом max_tokens; фолбэк на reasoning_content в доноре работал. Решение: content —
   основной output; фолбэк — явно включённая совместимость (флаг профиля), результат
   валидируется, в provenance ставится пометка fallback; пустой output после retry —
   ошибка.
6. **Judge.** LLM-судья даёт структурированную оценку стадии с основанием в trigger
   evidence; не выставляет composite success и не компенсирует WRITE=False/UNKNOWN
   (принципы IV–V). Детерминированные проверки идут первыми.
