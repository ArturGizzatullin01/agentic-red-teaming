# Quickstart: 004-port-working-attacks

**Created**: 2026-09-06

После порта каждой атаки:

```bash
python -m pytest tests/test_all_attacks.py -q
python -m pytest tests/ -q
```

Целевые команды (записывать по факту реализации):

```bash
memnotsafe run --target mock --scenario scenarios/procedural-graft.yaml --output runs/demo
memnotsafe run --target mock --scenario scenarios/cross-topic-smuggle-global.yaml --output runs/demo-xt
memnotsafe report --input runs/demo --output reports/demo
```

Признак готовности: пять P1-атак доступны в реестре, mock даёт positive на vulnerable
и честный negative на protected, unknown family даёт понятную ошибку, core-дифф пуст.
