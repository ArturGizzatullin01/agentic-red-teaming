# Quickstart: 002-evidence-integrity

**Created**: 2026-09-06

Проверка фичи локально, офлайн:

```bash
# окружение (однократно)
python -m venv .venv-integration
.venv-integration/Scripts/python.exe -m pip install -e ".[mongo]" pytest   # Windows
# Linux: .venv-integration/bin/python -m pip install -e ".[mongo]" pytest

# baseline + новые suites
python -m pytest tests/ -q                       # всё зелёное
python -m pytest tests/test_runner_lifecycle.py -q
python -m pytest tests/test_evidence_integrity.py -q
```

Признак готовности фичи: baseline остаётся зелёным, новые suites проходят без сети,
Docker, ключей; `python -m pytest tests/test_evidence_integrity.py -q` ловит все
регресс-кейсы из [tasks.md](tasks.md).

Команды записаны по факту исполнения на 2026-09-06 для baseline (35 passed);
команды новых suites появляются здесь только после фактического прогона кодером.
