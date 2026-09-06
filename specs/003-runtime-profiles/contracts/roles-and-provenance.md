# Контракты: роли и provenance (003)

**Created**: 2026-09-06. Источник — [контракты интеграции](../../../docs/integration-handoff/contracts.md),
разделы «Роли и конфигурация», «Смена target и восстановление».

## Роли и конфигурация

- `RoleProfile`: preset_id, provider, model, base_url, api_key_env, timeout,
  ограничения output/retry, разрешённые provider options. Без «универсального мешка».
- `RunProvenance`: schema_version, source_revision, seed, variant, scenario hash,
  candidate hash, requested/resolved модели трёх ролей, stand revision,
  effective_channel, режим auth, evidence capabilities, времена, статус исполнения.
- Default attacker — static. Runtime-пресеты qwen/glm — из публичных примеров донора;
  model ID/endpoint проверяются probe. Judge сохраняет `deepseek-v4-flash` как
  заявленную конфигурацию источника.
- Модели активных ролей сравниваются по resolved provider/model, не по alias.
  Static attacker и неиспользуемый judge — `inactive`, не фиктивная модель.
- Неизвестный preset, конфликт ролей, отсутствие ключа → ошибка до reset/delivery.
- Смена attacker не меняет judge/target. Смена target требует readback; sanity без
  readback не доказывает идентичность; запрошенная модель не пишется как фактическая.

## Output-политика

- `content` — основной output. `reasoning_content` — отдельная явно включённая
  совместимость: валидация результата + пометка fallback в provenance.
- Пустой/невалидный output — ограниченный retry, затем ошибка (exit 1).
- LLM judge: структурированная оценка стадии с основанием в trigger evidence;
  composite success не выставляет, WRITE=False/UNKNOWN не компенсирует.

## Смена target и восстановление

- Отдельный compose project; identities 1001/1002; порты — проверка до запуска.
- Не переносить Mongo URI/пароли в generic core.
- Операции: сохранить профиль → применить → пересоздать agent-api → readback без
  секретов → health → непустой sanity → запуск → restore в finally.
- Сбой restore — отдельная ошибка; отчёт содержит фактически оставшееся состояние.
- Именнованные бэкапы профиля; общий `.env.bak` не перетирается.
- Глобальный reset общей БД запрещён; reset только отдельного тестового стенда.
