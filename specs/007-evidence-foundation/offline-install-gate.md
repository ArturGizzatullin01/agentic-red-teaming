# Offline-проверка установки CLI — C10 gate

Дата: 2026-09-14/15 · Кандидат: `feature/p09-full` @ `1b77a66` (фиксы RETURN_FOR_FIX d09299a)

## Вердикт (финал, 2026-09-15, после RETURN_FOR_FIX): PASS

История: PASS (2026-09-14) → приёмкой Codex переведён в RETURN_FOR_FIX —
installed `generate` вне репозитория без `--classes` давал сырой traceback
(нарушение контракта runtime/config error). Исправлено в `a2399a5c`-линейке
(коммит `a239a5c`), wheel ПЕРЕСОБРАН из исправленного дерева, повторён
ЗАТРОНУТЫЙ installed-smoke:

- wheel пересобран: `memnotsafe-0.1.0-py3-none-any.whl`, sha256
  `d1955e69d8c643ea7b03ed7570fb36b470c82ccaa4bcd05c61e2ce21d17cfdc2`
  (был `270c73a2…`); установлен в НОВЫЙ чистый venv строго
  `--no-index --find-links`; `pip check` — чисто;
- `memnotsafe.__file__` → site-packages чистого venv (PYTHONPATH снят, cwd
  `$env:TEMP\c10-preview\smoke-cwd` — вне исходников);
- generate (installed, cwd вне репо, без `--classes`) → **exit 1, stderr
  `[FATAL] … --classes <dir> …`, 0 байт traceback**; с реальным
  `--classes` → exit 0; `--json`-режим ошибки → stdout пуст, stderr —
  ровно один JSON-объект `{schema_version, command, outcome:"error",
  exit_code:1, data, artifacts}`;
- регресс затронутой зоны: probe --json (0 ANSI, stderr пуст), protected
  run → exit 0 + NOT_EXPLOITABLE, report → exit 0 — все из установленного
  пакета.

Дальнейшее — история предыдущего PASS (2026-09-14, wheel `270c73a2…`).

---

## Предыдущий вердикт (2026-09-14): PASS (частично отозван приёмкой — см. выше)

Разрешение пользователя: «Разрешаю одну сетевую сессию C10 для скачивания
зависимостей и сборки wheel. Live и платные LLM-вызовы не разрешаю».

Выполнено (кандидат `main=f3b4e02`, worktree `full-stack-rc1`):

1. **Wheelhouse** `$env:TEMP\c10-preview\wheelhouse` (вне репо): 12 колёс —
   pyyaml 6.0.3 (cp314), httpx 0.28.1, rich 14.3.4 + транзитивные
   (httpcore, h11, anyio, certifi, idna, markdown-it-py, mdurl, pygments,
   typing_extensions).
2. **Wheel проекта**: `pip wheel <repo> --no-deps` →
   `memnotsafe-0.1.0-py3-none-any.whl`, size 256928,
   sha256 `270c73a2ffb8857391de6283acb68084f46d2c0dfe4d1cdb2fe94f08c67ce7bc`
   (build isolation сам подтянул setuptools>=68 в эфемерное окружение).
3. **Чистый venv** `$env:TEMP\c10-preview\clean-venv` (вне репо и вне
   venv-integration): `pip install --no-index --find-links <wheelhouse>` —
   13 пакетов установлено строго из wheelhouse, editable НЕ использовался.
4. **`pip check`**: No broken requirements found.
5. **Import-proof** (cwd = `$env:TEMP\c10-preview\smoke-cwd`, PYTHONPATH снят):
   `memnotsafe.__file__` → `...\c10-preview\clean-venv\Lib\site-packages\memnotsafe\__init__.py`;
   консольный скрипт `memnotsafe.exe` установлен.
6. **Installed-CLI smoke** (все команды — установленным пакетом, исходное
   дерево не требуется):
   - `--help` exit 0/stdout, stderr пуст; неизвестный аргумент exit 2/stderr/stdout пуст;
   - `probe --target mock`: human/`--json`/`--quiet`/`--json --quiet`/`--no-color` —
     exit 0; JSON — ровно один объект; **0 ANSI-байт во всех выводах**; stderr пуст;
   - `run cross_user_bac.yaml` → exit 0 (позитив); `cross_user_bac_protected.yaml`
     → **exit 0 + `status: NOT_EXPLOITABLE`, ASR 0%** (честный негатив);
   - `campaign --iterations 2` → exit 0; `report` обоих прогонов → exit 0
     (replay + verify_run_evidence); `report --json` — один объект, `asr` в data;
   - `replay --case <id>` → exit 0 (трасса с call_id-корреляцией);
   - `judge-calibrate --from-run … --out …` → exit 0; неверные аргументы → exit 2;
   - `generate` (offline stub-writer, 5 записей корпуса) → exit 0;
   - `report --input <missing>` → **exit 1**: human — `[FATAL]` в stderr/stdout пуст;
     `--json` — stdout пуст/JSON-ошибка в stderr/без ANSI;
   - артефакты установленного пакета: `experiment.json`, `bundles/<case>/manifest.json`,
     `attempts.jsonl`, `budget-ledger.jsonl`, `campaign.json` — созданы и читаются.
7. **Известная грань (не дефект wheel, зафиксирована)**: `generate` без
   `--classes` из каталога без `attack_classes/` даёт сырой traceback + exit 1.
   Поведение **байт-в-байт совпадает** с принятым исходным деревом
   (`FileNotFoundError: 'attack_classes'` — cwd-относительный дефолт);
   контрактный путь ошибки (report missing, config-gate) чист. Правка —
   отдельной карточкой CLI, не в C10 и не в P09 (запрещено менять CLI-контракт).

Полный suite 759 повторно не гонялся — исходники не менялись (C10 не трогает код).

---

## История: предварительное состояние (до сетевого разрешения)

### Вердикт: BLOCKED (объективный блокер среды, не дефект пакета)

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
