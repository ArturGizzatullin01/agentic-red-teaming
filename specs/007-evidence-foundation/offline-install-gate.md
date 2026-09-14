# Offline-проверка установки CLI (предварительная, C10-preview) — состояние

Дата: 2026-09-14 · Кандидат: `evidence/foundation` @ `4ee868a`+ · Блок: Evidence Foundation

## Вердикт: BLOCKED (объективный блокер среды, не дефект пакета)

## Что требуется для gate (C10-предварительный)

1. **Сборка wheel** — PEP 517 backend `setuptools>=68` (`pyproject.toml [build-system]`).
   setuptools ОТСУТСТВУЕТ в проверенных интерпретаторах (граница аудита: проверены
   три перечисленных; утверждать отсутствие setuptools на ВСЕЙ машине оснований
   нет — приёмщик независимо подтвердил отсутствие в используемом venv):
   - `.venv-integration` (3.14.7) — setuptools нет;
   - `pythoncore-3.14-64` (3.14) — setuptools нет;
   - `Python313` (3.13) — pip 26.2.1 есть, setuptools/wheel нет.
   Сборка через build-isolation или `uv build` требует сетевого bootstrap backend'а —
   без разрешения на сеть запрещено. `pip cache` (built wheels): пуст. uv 0.12.12
   установлен, но проблему offline-bootstrap не снимает.
2. **Колёса зависимостей для `--no-index`** — локально не представлены. Точный список
   wheelhouse (по `pip show`/метаданным установленного окружения):
   `memnotsafe` (наш), `pyyaml`, `httpx`, `h11`, `anyio`, `certifi`, `idna`,
   `rich`, `markdown-it-py`, `mdurl`, `pygments`.

## Команды для исполнителя с сетевыми правами (PowerShell; снять блокер, не менять код)

```powershell
# 0) рабочие каталоги вне исходников
$work = "$env:TEMP\c10-preview"
New-Item -ItemType Directory -Force -Path "$work\wheelhouse", "$work\smoke-cwd" | Out-Null
$PY = "C:\Users\dota2\memnotsafe-integration\agentic-red-teaming-main\.venv-integration\Scripts\python.exe"
$repo = "C:\Users\dota2\memnotsafe-integration\worktrees\evidence-foundation"

# 1) wheelhouse (одна сетевая сессия: deps + наш sdist)
& $PY -m pip download -d "$work\wheelhouse" pyyaml httpx "rich>=13.9,<15"
& $PY -m pip download -d "$work\wheelhouse" --no-deps "$repo"

# 2) сборка нашего wheel (build-isolation сам подтянет setuptools>=68 в эфемерное окружение)
& $PY -m pip wheel "$repo" --no-deps -w "$work\wheelhouse"

# 3) чистое окружение ВНЕ исходников и вне venv-integration
& $PY -m venv "$work\clean-venv"
& "$work\clean-venv\Scripts\python.exe" -m pip install --no-index `
    --find-links "$work\wheelhouse" (Get-Item "$work\wheelhouse\memnotsafe-*.whl").FullName
& "$work\clean-venv\Scripts\python.exe" -m pip check

# 4) контроль чистоты окружения
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
& "$work\clean-venv\Scripts\python.exe" -c "import memnotsafe; print(memnotsafe.__file__)"
# ожидание: путь в clean-venv\Lib\site-packages, НЕ в ...\worktrees\evidence-foundation\src
```

Далее — smoke-чеклист ниже из `$work\smoke-cwd` (`Set-Location "$work\smoke-cwd"`).

## Smoke-чеклист после установки (выполнен будет отдельной карточкой/gate)

- [ ] cwd = `$work\smoke-cwd`, переменная PYTHONPATH не задана;
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
