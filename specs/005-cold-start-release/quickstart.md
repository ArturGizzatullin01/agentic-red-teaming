# Quickstart: 005-cold-start-release

**Created**: 2026-09-06

Чистый офлайн-запуск (целевой вид; команды обновить по факту реализации):

```bash
# чистое окружение вне src-checkout
python -m venv .venv-demo && .venv-demo/Scripts/activate   # Windows
# Linux: source .venv-demo/bin/activate
pip install dist/memnotsafe-*.whl

memnotsafe run --target mock --scenario scenarios/procedural-graft.yaml --output runs/demo
memnotsafe report --input runs/demo --output reports/demo
```

Live-протокол (только отдельный стенд; после offline gate):

```bash
memnotsafe campaign --target investment-stand --scenario-dir scenarios/live \
  --profile live-oss20 --n 5 --output runs/live-$(date +%Y%m%d)
```

Признаки готовности: offline gate acceptance.md полностью закрыт на двух ОС;
live gate — по протоколу с provenance; readiness-статус записан аудитором.
