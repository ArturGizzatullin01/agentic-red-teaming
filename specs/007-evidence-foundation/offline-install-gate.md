# Offline-проверка установки CLI (предварительная, C10-preview) — состояние

Дата: 2026-09-14 · Кандидат: `evidence/foundation` @ `4ee868a`+ · Блок: Evidence Foundation

## Вердикт: BLOCKED (объективный блокер среды, не дефект пакета)

## Что требуется для gate (C10-предварительный)

1. **Сборка wheel** — PEP 517 backend `setuptools>=68` (`pyproject.toml [build-system]`).
   На машине setuptools ОТСУТСТВУЕТ во всех интерпретаторах:
   - `.venv-integration` (3.14.7) — нет setuptools;
   - `pythoncore-3.14-64` (3.14) — нет setuptools;
   - `Python313` (3.13) — pip 26.2.1 есть, setuptools/wheel нет.
   Сборка через build-isolation или `uv build` требует сетевого bootstrap backend'а —
   без разрешения на сеть запрещено. `pip cache`: пусто. uv 0.12.12 установлен,
   но проблему offline-bootstrap не снимает.
2. **Колёса зависимостей для `--no-index`** — локально не представлены. Точный список
   wheelhouse (по `pip show`/метаданным установленного окружения):
   `memnotsafe` (наш), `pyyaml`, `httpx`, `h11`, `anyio`, `certifi`, `idna`,
   `rich`, `markdown-it-py`, `mdurl`, `pygments`.

## Команды для исполнителя с сетевыми правами (снять блокер, не менять код)

```bash
# 1) wheelhouse (одна сетевая сессия)
PY=<venv-integration python>
"$PY" -m pip download -d wheelhouse/ . pyyaml httpx "rich>=13.9,<15"
# 2) сборка нашего wheel
"$PY" -m pip wheel . --no-deps -w wheelhouse/
# 3) чистое окружение ВНЕ исходников
"$PY" -m venv "%TEMP%\clean-cli-venv"
"%TEMP%\clean-cli-venv\Scripts\python.exe" -m pip install --no-index \
    --find-links wheelhouse/ memnotsafe-*.whl
"%TEMP%\clean-cli-venv\Scripts\python.exe" -m pip check
# 4) smoke ИЗ "%TEMP%\smoke-cwd" без PYTHONPATH (unset проверять командой set PYTHONPATH)
```

## Smoke-чеклист после установки (выполнен будет отдельной карточкой/gate)

- [ ] `memnotsafe.__file__` указывает в site-packages чистого venv (не в src/);
- [ ] `memnotsafe --help` → exit 0, stdout;
- [ ] `probe --target mock` human/json/quiet: JSON — один объект, stderr пуст, 0 ANSI-байт;
- [ ] `run cross_user_bac_protected` → exit 0 + NOT_EXPLOITABLE (честный негатив);
- [ ] `report --input missing` → exit 1, [FATAL] в stderr (human) / JSON-ошибка в stderr (--json);
- [ ] неизвестный аргумент → exit 2, usage в stderr, stdout пуст;
- [ ] UNKNOWN-стадия в JSON → null; `report` replay собранного runs/ без target;
- [ ] `evidence/foundation`-артефакты (experiment.json/bundles/attempts.jsonl/ledger)
      пишутся и верифицируются установленным CLI.

## Что сделано вместо заблокированного (не закрывает C10)

- Воспроизводимость suite закрыта: 746→752 passed ×2 с разными basetemp, окружение
  зафиксировано (Python 3.14.7, pytest 9.1.1, rich 14.3.4, PyYAML 6.0.3, httpx 0.28.1).
- CLI-контракт повторно покрыт офлайн-тестами через поддерживаемые entrypoints
  (`python -m memnotsafe.cli` / консольный скрипт) в 752-тестовом наборе.
