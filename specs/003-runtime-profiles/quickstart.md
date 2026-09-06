# Quickstart: 003-runtime-profiles

**Created**: 2026-09-06

Разработка и проверка фичи — офлайн:

```bash
python -m pytest tests/test_role_profiles.py tests/test_target_switch.py tests/test_provenance.py -q
python -m pytest tests/ -q
```

Пример целевого CLI (появляется по мере реализации; команды записывать в quickstart
только после фактического прогона):

```bash
# сценарий с runtime-пресетом аттакера
memnotsafe run --target mock --scenario scenarios/procedural-graft.yaml \
  --attacker-preset qwen --output runs/demo-qwen

# смена цели + кампания под новой моделью (wrapper, R2): restore после кампании
python scripts/set_stand_target.py oss20 \
  --stand-path ../genai-invest-agent-memory-stand-stack2 -- \
  memnotsafe campaign --target http://localhost:9600 \
    --scenario scenarios/procedural-graft-live.yaml --iterations 5 \
    --output runs/live-oss20
```

Gate фичи: fake-транспорт подтверждает, что смена preset реально меняет исходящий
запрос генерации; judge/target в provenance неизменны.
