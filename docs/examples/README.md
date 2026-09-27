# Примеры для оператора (Windows / Linux)

Команды одинаковы на всех ОС; различаются только установка переменной окружения
и открытие HTML-отчёта. Пути ниже — относительные, машинных путей нет.

Файлы в этом каталоге:

- **`pilot.yaml`** — конфиг пилотной проверки чужой OpenAI-совместимой ручки
  (совпадает с `memnotsafe pilot --init`). Ключ — только имя ENV, не значение.
- **`scenario_target_profile.yaml`** — сценарий с EXT-A target-профилем
  (`target.profile`): декларативное описание чужой ручки для `run` / `campaign` /
  `go`. Профиль честят только для `adapter: http_endpoint`; `pilot` профиль не берёт.

## Быстрый mock-smoke (без сети, без ключей, без каталога репозитория)

Сценарии стартового пака едут в wheel — из голого `pip install` они находятся по
имени, каталог репозитория не нужен.

Linux / macOS (bash):

```bash
memnotsafe probe --target mock
memnotsafe run --scenario cross_user_bac.yaml --target mock --output runs/smoke
memnotsafe threat-report --input runs/smoke
xdg-open runs/smoke/threat-report.html     # macOS: open
```

Windows (PowerShell):

```powershell
memnotsafe probe --target mock
memnotsafe run --scenario cross_user_bac.yaml --target mock --output runs/smoke
memnotsafe threat-report --input runs/smoke
Invoke-Item runs/smoke/threat-report.html
```

## Пилот к чужой ручке (по явному согласию)

Ключ живёт в окружении; в YAML — только имя переменной.

Linux / macOS (bash):

```bash
export MEMNOTSAFE_TARGET_API_KEY=<ключ>
memnotsafe pilot --config docs/examples/pilot.yaml --output runs/pilot-run
```

Windows (PowerShell):

```powershell
$env:MEMNOTSAFE_TARGET_API_KEY = "<ключ>"
memnotsafe pilot --config docs/examples/pilot.yaml --output runs/pilot-run
```

Отредактируйте `base_url` и `model` под свою ручку; `budget_cap` — жёсткий потолок
прогонов против неё. Отчёт: `runs/pilot-run/threat-report.html`.

## Сценарий с target-профилем (`run` / `go`)

Для ручек с нестандартным транспортом/идентичностью/каналами доказательств —
профиль в сценарии (см. `scenario_target_profile.yaml`), затем живой прогон по
явному согласию:

```bash
export MEMNOTSAFE_TARGET_API_KEY=<ключ>
memnotsafe run --scenario docs/examples/scenario_target_profile.yaml --output runs/profile-live
```

## Чтение threat-report

Вердикт кейса — одно из трёх: **PROVEN** (компрометация доказана независимой,
не-судейской уликой), **NOT PROVEN** (наблюдаемая стадия опровергла — но это **не**
«безопасно»: записанное до разрыва может остаться в памяти), **INCONCLUSIVE**
(не наблюдалось/противоречиво — payload может всё ещё быть в памяти). Штамп кампании:
`COMPROMISE PROVEN` / `COMPROMISE NOT PROVEN` / `INCONCLUSIVE`. Доктрина: **UNKNOWN ≠
безопасно** — ненаблюдённая стадия не пройдена и не провалена, это предел видимости.
