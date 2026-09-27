---
type: log
project: memnotsafe
---

# LOG — memnotsafe


### 2026-09-27 — claude-code — EXT-D: поставка (аудит+добивка P19, оператор-скилл, README) (feat/ext-d-delivery)

- контекст: поток EXT-OPERATOR, карта поставки. База — свежий main 0d65acd (suite 1639/0
  на Windows; EXT-A/EXT-B/P19 влиты). НЕ live, НЕ Docker; секреты — только ИМЕНА env.
  Ветка feat/ext-d-delivery. Приёмка A0, не самопринимать
- задача 1 — аудит P19 делом + добивка по факту разрыва. Собрал wheel, поставил в ЧИСТЫЙ
  venv, гонял из произвольного cwd без клона. Итог аудита: `pilot --init`/`pilot --config`
  из голого install РАБОТАЮТ (пак резолвится package-resource-first, не разрыв). Два РАЗРЫВА:
  (a) `run --scenario <имя>` — `load_scenario` резолвил только путь ФС, упакованный сценарий по
  имени не находился (FileNotFoundError, непойманное → сырой traceback); (b) `go` без `--scenario`
  — каталог из `build_catalog("scenarios")` (cwd `./scenarios`), из голого install пуст.
  Закрыто как «добивка P19 по факту разрыва» (ALLOWLIST): `pilot_scenarios/__init__.py` —
  новые `packaged_scenario_path(name)` / `packaged_scenarios_dir()` (пакет владеет знанием о
  своих ресурсах); `core/config.py` — `load_scenario` резолвит ГОЛОЕ имя из package resources
  (явный путь с каталогом не подменяется; содержимое байт-в-байт = scenarios/<имя> → experiment_id
  не дрейфует); `selfserve.py` — `_go_catalog_dir()` берёт репозиторный `./scenarios` в дереве,
  иначе упакованный набор (поведение в дереве не меняется, `build_catalog` не тронут). Проверено
  в чистом venv: `run --scenario cross_user_bac.yaml --target mock` → rc 0 + артефакты;
  `threat-report --input runs/smoke` → COMPROMISE PROVEN (CRITICAL) + «UNKNOWN is not safe»;
  `go` каталог из пустого cwd перечисляет 4 упакованных сценария. Офлайн-замок: новый файл
  `tests/test_ext_d_packaging.py` — RED→GREEN на оба разрыва + всегда-замок упаковки (pyproject
  package-data + importlib.resources) + архивный замок (сборка wheel + zipfile namelist,
  skip-guarded: без toolchain/сети → SKIP, не FAIL)
- задача 2 — оператор-скилл доработан (не переписан): `artifacts/memnotsafe-claude-skill/
  memnotsafe-operator/SKILL.md`. Добавлены разделы: EXT-A target-профиль (scenario `target.profile`:
  transport/auth/identity/session/observation/health; ТОЛЬКО http_endpoint; `pilot` профиль НЕ
  принимает — уточнено против премиссы карты по факту кода); судья из конфигурации EXT-B (флаги
  `--judge`/`--no-judge`/`--judge-model`/`--judge-max-calls`, блок `judge:`, `MEMNOTSAFE_JUDGE_*`,
  человеческая ошибка при отсутствии judge.model — базы `--judge-base-url`/`--judge-api-key-env`
  как ФЛАГОВ нет); замок «никогда тихий mock» (URL поверх mock-сценария — отказ, как читать);
  раздел чтения threat-report (PROVEN/NOT PROVEN/INCONCLUSIVE, UNKNOWN≠safe). Каждая команда
  сверена с `memnotsafe --help` свежего main (stand up|down|status|keys, go --live-ack и т.д.)
- задача 3 — README + примеры: `README.md` — новый раздел «Установка из wheel и первый прогон
  (Windows/Linux)» (bash+PowerShell, машинных путей нет): install из wheel, mock-smoke за 2 мин,
  пилот к чужой ручке (ИМЯ env-ключа), чтение threat-report. `docs/examples/` (новый):
  `pilot.yaml` (сверен с шаблоном `pilot --init`), `scenario_target_profile.yaml` (EXT-A профиль —
  провалидирован load_scenario→resolve_effective_target→build_adapter; адаптер корректно требует
  ключ ТОЛЬКО из env), `README.md` (кросс-ОС команды). AGENTS.md/CLAUDE.md в поставку НЕ включены
- отклонения (D): нет. Ядро тронуто ТОЛЬКО добивкой P19 (load_scenario резолв имени) — в рамках
  явного исключения ALLOWLIST «CLI-семантика — кроме добивки P19 по факту разрыва»; runner/атаки/
  оракулы/mock/investment_stand/profile.py/сценарии не тронуты
- NOTICED (вне scope, не чинил): (1) для ИСТИННО отсутствующего сценария (не пакет, не диск)
  `run` по-прежнему отдаёт сырой FileNotFoundError-traceback (не пойман в cli) — это
  предсуществующее форматирование ошибки, а не упаковка P19; (2) `build/` не в .gitignore (build
  frontend оставляет `build/lib/` в дереве) — удалил свою резидью, не коммичу, но .gitignore не
  правил (вне ALLOWLIST)
- проверка (реально прогнано в venv 3.12): targeted RED→GREEN `tests/test_ext_d_packaging.py`
  RED 4 failed/4 passed/1 skipped → GREEN 8 passed/1 skipped; targeted регресс тронутых модулей
  (pilot_pack/selfserve/selfserve_cli_mega_ux/target_profile/ext_b/reset_scope/threat_report+ext_d)
  167 passed/1 skipped; ПОЛНЫЙ suite один прогон:
  `PYTHONIOENCODING=utf-8 python -m pytest tests/ -p no:cacheprovider -q` →
  **1646 passed, 1 skipped, 1 failed**. Единственный failed — предсуществующий платформенный
  `tests/test_demo_launcher.py::test_demo_cmd_references_existing_tracked_script` (POSIX трактует
  `scripts\demo-run.ps1` из demo.cmd как имя файла; зелёный на Windows-базе владельца 1639/0; вне
  моего диффа). skipped — архивный замок (нет build-toolchain в тест-venv). Δ vs база = +9 собрано
  (+8 passed, +1 skipped). py3.11 `py_compile` изменённых модулей OK; `git diff --check` чисто;
  секретов в диффе 0 (только имена env и плейсхолдеры)

### 2026-09-27 — claude-code — LIVE-COVERAGE: все семьи в бой + живой атакер (feat/live-coverage @ 752a14a)

- дизайн принят A0 (DESIGN ACCEPT 9.5/10); порядок 1→5→2→4→3, RED→GREEN на каждую, единый suite
- (1) 16 live-сценариев на stack2 (investment_stand 9600/28017, reset_scope namespace): 14 mock-only
  (список карты + delimiter_summary_injection, A0 Q1 «ВСЕ») + 2 pilot-batch (cross_topic/document) на
  stack2-MAIN; зеркало mock-smoke базы, сменён только target-блок. Новый замок test_mock_live_symmetry
  (семья→live + mock; mock только smoke, A0 Q4); test_control_factor_inventory +16 пар, −7 из UNPAIRED;
  правило «mock только smoke» в AGENTS/CLAUDE
- (5) --attacker-preset общий → работает в run/campaign/generate/pilot (apply_attacker_preset,
  управляемый отказ на unknown, печать выбранного)
- (2) «никогда больше»: threat_report.attacker_status (англ., замок no-cyrillic) + строка в шапке;
  карточка «до» предупреждает live+static; pilot-гейт без --online/--allow-static → блокер; сводка пака
  показывает атакующего; фикс публичного имени (замок приватных cross-module импортов)
- (4) мягкий семантический WRITE поверх маркерного: semantic_candidate_match (инъект. embed, cosine,
  порог 0.83), EVIDENCE_KIND_SEMANTIC_MATCH∈SOFT (FIX-A: не HARD); оракул зовёт мягкий путь только на
  промахе маркера И при инъект. эмбеддере (умолчание None → регресс); spec 002 amendment. Живой embedding
  и калибровка порога — A0 (Q6)
- (3) диагностика conditional-движка: узкий гейт trust_step (умолчание True → канон не тронут) +
  scenarios/cond-2x2/ (подкаталог, инвентарём не сканируется) 2×2 trust×marker; spec 001 amendment
  (атрибуция write по source_session_id). Живой 2×2 — A0
- движок/campaign/worker/runner/mock/канон-оракулы не тронуты (кроме узкой мягкой ветки §4 и param-гейта §3)
- RED→GREEN каждой задачи (targeted 33/76/58/35/37); полный suite 1672 passed / 0 (=1621+51); diff --check
  чист; секреты — только ИМЕНА env; live НЕ запускал; main не двигал, не пушил; не самопринимаю
- DEVIATIONS: D-подпись Opus 4.8 (карта→Fable, STANDING-RULES §8); 7 (не 6) баз вышли из UNPAIRED
  (с Q1=yes добавился delimiter). NOTICED: live-активация §4 (config→runner→ec) и чтение source_session_id
  §3 — тонкие швы за A0 (живые вызовы)

### 2026-09-26 — claude-code — EXT-B: единая эффективная цель + preflight по контракту + судья из конфигурации (feat/ext-b-effective-target)

- контекст: поток EXT-OPERATOR, карта 2/4. База — свежий main ae56227 (suite 1621/0,
  EXT-A влита 2806ee4, строим поверх). НЕ live, НЕ Docker; секреты — только ИМЕНА env.
  Ветка feat/ext-b-effective-target
- (1) единая эффективная цель (ДЕФЕКТ-3 полностью): `core/config.py` — новые
  `EffectiveTarget(adapter, base_url, profile)` + `resolve_effective_target(scenario,
  target_override)` — ЕДИНАЯ точка резолва. `build_adapter` = тонкая обёртка над
  resolve + `build_adapter_from_effective`. `core/experiment.py` — `build_experiment_spec`
  получил опциональный `effective_target` (None → из scenario.target, регресс experiment_id
  побайтово сохранён; задан → adapter/base_url/profile из него, смена --target меняет
  experiment_id). `core/campaign.py` — `Campaign(effective_target=…)` прокидывает цель в
  spec и в метаданные (`_run_metadata` называет эффективный adapter/target). `cli.py` —
  `_run_campaign` резолвит цель один раз и передаёт в Campaign (run/campaign/go идут этим
  путём). Замок: смена B меняет target/adapter в experiment.json/campaign.json и
  experiment_id
- (2) никогда тихий mock: `resolve_effective_target` — URL поверх mock-сценария → `ValueError`
  с причиной и подсказкой (URL игнорировался бы, прогон считал бы, что бьёт живую цель);
  `--target <имя известного адаптера>` → ЯВНОЕ переключение адаптера; `--target mock` → явный
  mock. В cli отказ резолва — человеческая ошибка (emit_error, exit 1), не трейсбек и не
  молчаливый MockTarget
- (3) preflight по контракту адаптера: `adapters/http_endpoint.py` (только probe) — новая
  чистая `classify_probe_status(status)` → три РАЗДЕЛЬНЫХ факта host_responds/auth_passed/
  contract_ok; `probe()` POST-ветка: `reachable=contract_ok` (401/403/404 ≠ доступно, было
  `<500`), detail помечает `target_call=True`. `preflight.py` — `run_preflight` получил
  `target_override` (уважает эффективную цель), `http_post`, `ledger`; развилка по контракту:
  investment_stand сохраняет W1(/healthz)+W2(/debug/sampling) без изменений; http_endpoint/
  openai — контрактная проверка `C1` (profile.health GET бесплатно, иначе POST chat-completion),
  отсутствие /healthz у них НЕ блокер; POST-проба — ПЛАТНЫЙ target_call: только при
  переданном `ledger`, записывается в budget-ledger (OP_TARGET_CALL); без леджера бесплатный
  preflight POST не делает (SKIP с объяснением). `selfserve.py` — go зовёт preflight с
  target_override (эффективная цель)
- (4) судья из конфигурации: `core/config.py` — `apply_project_judge_defaults(scenario, args,
  environ)`; КАНОНИЧЕСКИЙ порядок (задокументирован в докстринге): флаги `--judge-*` → блок
  `judge:` сценария → проектный ENV-дефолт `MEMNOTSAFE_JUDGE_MODEL/BASE_URL/API_KEY_ENV` →
  человеческая ошибка ДО цели (validate_judge_spec: enabled без model → RunnerError, exit 1).
  Захардкоженный OpenRouter больше НЕ активный молчаливый дефолт (остаётся инертным значением
  поля для сериализации/выключенного судьи — регресс digest experiment_id и test_experiment_spec_p10b
  сохранён; включённый судья без настроенной цели падает человеческой ошибкой, а не уходит на
  OpenRouter молча). Заполняются ТОЛЬКО сценарии без своего блока judge: и ТОЛЬКО незаданные
  поля — D1-пресет (Yandex через args-флаги) и judge-блоки не ломаются. `cli._run_campaign`
  зовёт после `_apply_judge_overrides`
- флаг **D** (отклонение ALLOWLIST): `pilot_pack.py` НЕ в буквальном списке файлов, но замок
  задачи 1 «каждая pilot-запись называет B» требует правки там (Campaign строится в
  `_run_pack`, не в cli). Минимально: `_pilot_chain` резолвит эффективную цель из synth-конфига
  и прокидывает `effective_target` в под-кампании — иначе experiment.json пилота называл бы mock
  из сценариев реестра, а не ручку. Одна логическая правка, легко откатывается
- NOTICED: (а) probe пилота (pilot_pack line ~405) и `memnotsafe probe` делают POST-пробу без
  budget-ledger — способность «POST-проба ложится в budget-ledger» реализована и покрыта тестом
  на уровне preflight (инъекция ledger); её боевое проведение через go/pilot требует создания
  ledger до out_dir/experiment (вне минимального scope selfserve «только вызов preflight»/pilot
  не в ALLOWLIST) — отложено. (б) `_default_http_post` не шлёт auth-заголовок: боевая
  POST-проба живой ручки с ключом — тот же отложенный узел. (в) `test_demo_launcher` (demo.cmd
  `%~dp0scripts\demo-run.ps1`, обратный слэш) падает на Linux — платформенное, вне диффа,
  зелёное на Windows-среде владельца (там база 1621/0)
- ALLOWLIST (по факту): core/config.py, core/experiment.py, core/campaign.py, preflight.py,
  adapters/http_endpoint.py (только probe), selfserve.py (только вызов preflight), cli.py
  (врезки run/campaign), pilot_pack.py (флаг D), тесты (новый test_ext_b_effective_target.py +
  правка моков run_preflight в test_selfserve*.py под новую сигнатуру), LOG.md
- проверка (venv312, python3.12): RED — новый файл не собирался (нет символов EffectiveTarget/
  resolve_effective_target/apply_project_judge_defaults), 0 passed/1 error; GREEN targeted —
  `pytest tests/test_ext_b_effective_target.py` = 18 passed; полный suite один прогон —
  `pytest tests/ -p no:cacheprovider` = **1638 passed, 1 failed** (единственный провал —
  предсуществующий платформенный test_demo_launcher; Δ=+18 к базе 1621). py3.11 py_compile
  изменённых модулей OK; `git diff --check` чисто; секретов в диффе 0 (только ИМЕНА env). НЕ
  трогал: runner-стадии, атаки, оракулы, mock-адаптер, investment_stand (W1/W2 сохранены),
  adapters/profile.py (EXT-A), чужие ветки. Не самопринимал — приёмка A0

### 2026-09-26 — claude-code — EXT-A: версионированная target-profile схема для tier-1 (feat/ext-a-target-profile)

- контекст: поток EXT-OPERATOR, карта 1/4. Оператор ИБ подключает ЧУЖУЮ цель по URL —
  нужна декларативная версионированная схема профиля (schema_version обязателен),
  которую строго читает config и честно исполняет http_endpoint. База main=db9e48d;
  НЕ live, НЕ Docker; секреты — только ИМЕНА env. Карта v2 (v1 отменена)
- новый модуль `adapters/profile.py`: `TargetProfile` (transport/auth/identity/session/
  observation/health) + `load_profile()` строгий разбор — неизвестный ключ на любом
  уровне → `ProfileError` ДО запроса (карта §6, никакого `**_ignored`)
- (1) транспорт: chat_path (относительный), method=POST, декларативный mapping полей
  запроса (model_field/messages_field/role_key/content_key) и ответа (content_path),
  extra_fields с валидацией
- (2) identity: схемы bearer_env (ENV-имя per принципал) / request_header / request_field /
  native_session; single-user допустим; cross-user — только при доказанной независимости
- (3) сессия: `adapter_history` (локальная история) или `native` (session id уходит в
  запрос заданным полем); жизненный цикл native — финализация закрытием (`writes_on_close`+
  `finalize_path`), т.к. раннер закрывает сессии доставки ДО settle (runner.py:278);
  внешнего reset у tier-1 нет — изоляция свежими session_id + маркерами
- (4) health probe: `get` (path+expect_status) или `post_only`
- (5) наблюдаемость: capability-флаги memory_snapshot/retrieval_trace/tool_telemetry/reset;
  у tier-1 канала нет — заявка флага → отказ (честная трансляция, оракулы → UNKNOWN)
- (7) `adapters/base.py`: `TargetAdapter.wait_until_persistent` базовое умолчание
  observed→**unavailable** (честный UNKNOWN; прежнее observed утверждало запись без
  наблюдения). Переопределяют только адаптеры с реальным каналом (mock/investment_stand);
  openai (спит) наследует и теперь честно отдаёт unavailable
- замки аудита (подтверждены A0):
  • G1 граница хоста — все пути только относительные к base_url; абсолютный/protocol-relative
    chat_path → отказ при разборе; base_url с userinfo и удалённый плейнтекст-HTTP без
    `transport.allow_remote` → отказ в `check_host_boundary` ДО чтения ключа
  • G2 зарезервированные поля — messages/model/identity/session/auth + имена mapped-полей
    закрыты для extra_fields; конфликт → ошибка конфигурации до вызова цели (закрывает
    ДЕФЕКТ-2: extra перекрывал model/messages)
  • G3 identity-handshake — два ENV-имени ≠ два субъекта: cross-user требует разных
    субъектов, разных токенов И явной аттестации `cross_user_independent`; иначе честный
    отказ. Негативы покрыты: один субъект/два ключа, одно имя env, нет аттестации
  • G4 evidence-происхождение — http_endpoint НЕ синтезирует call/result из текста
    (events=[]); текстовое событие с `detail.channel=victim_response` — мягкое
    signature_match, связанная пара call/result — жёсткая telemetry (проверено через
    существующий `channel_evidence_kind`, оракулы не тронуты)
  • G5 session-finalize — замок-модель стенда, пишущего память только при закрытии:
    native+writes_on_close → close_session POST-ит finalize_path ДО settle
  • G6 провенанс — `core/experiment.py` (флаг **D**, ALLOWLIST расширен): при наличии
    профиля в `target` эксперимента добавляются `profile_schema_version` + `profile_digest`
    (нормализованный sha256 без значений секретов) → эффективная цель определяет
    experiment_id, а не только строка adapter из YAML (ДЕФЕКТ-3 частично). Регресс:
    сценарий без профиля — target и experiment_id побайтово прежние
- (6)/L6 регресс: bb-сценарий `global_policy_injection_bb_live` (adapter=http_endpoint без
  профиля) строится по-прежнему — профиль опционален, дефолт = текущее поведение
- RED→GREEN (venv312, py3.12): чистая база — collection error (модуль profile отсутствует,
  весь замок-сет не выполнен); с profile.py, но без обвязки — 10 failed / 26 passed
  (интеграционные локи красные); после обвязки — **36 passed**
  (`tests/test_target_profile.py`)
- проверки: targeted-регресс 137 passed (http_endpoint/conformance/settle/lifecycle/
  budget/experiment/bb_live/preflight/oracle_adapter); полный suite ОДИН прогон — **1568
  passed / 1 failed (61s ≤300)**; итог 1569 = 1533 базы + 36 новых. Единственный fail —
  `test_demo_launcher` (демо-обёртка `demo.cmd` строка 5 `%~dp0scripts\demo-run.ps1` —
  бэкслэш-путь Windows на Linux; файл/тест картой не тронуты, на канон-Windows-venv
  зелёный, отсюда база 1533/0). py3.11 py_compile всех изменённых исходников — OK
  (<3.12-совместимость); `git diff --check` чист; секретов 0 (только ИМЕНА env и
  плейсхолдеры в тестах)
- ALLOWLIST соблюдён: `adapters/profile.py` (new), `adapters/http_endpoint.py`,
  `adapters/base.py`, `core/config.py` (точка чтения профиля), `core/experiment.py`
  (G6, флаг D), `tests/test_target_profile.py` (new), `tests/test_adapter_contract_conformance.py`
  (только строки-описания устаревшего observed-умолчания, логика замка не тронута), `LOG.md`.
  НЕ тронуты: runner, атаки, оракулы, mock, investment_stand, openai, JudgeSpec (EXT-B), scenarios, specs
- зафиксировано для EXT-B (вне EXT-A): единая эффективная цель как источник для
  запроса/preflight/campaign.json/experiment.json; разделение читающего preflight (GET) и
  платной POST-пробы; preflight go по эффективной цели (selfserve.py:442)
- Не самопринимаю — приёмка A0

### 2026-09-26 — claude-code — REPORT-CONSOLE-DESIGN: threat-report в дизайне Mission Control (feat/report-console-design)

- контекст: директива владельца «дизайн отчёта = дизайн Mission Control». Натянуть
  визуальный язык консоли (`console/src/styles.css`) на `threat-report.html` (P16).
  База main=8c3b3ef; НЕ атаки, НЕ live. P19/PR#9 не тронуты — карта на отдельной ветке
- (1) `reporting/threat_report.py` → блок `_CSS` переписан на дизайн-токены консоли:
  палитра (`--bg #0b0d12`, `--panel/--panel2/--line/--txt/--mut`, `--accent #5b9dff`),
  тристейт `--ok #3ddc84`/`--fail #ff5d6c`/`--unk #f5c344`, severity
  `--crit/--high/--med/--low/--info`; типографика (system sans + `ui-monospace,Menlo`);
  карточки radius 12 и заголовки секций uppercase+border-bottom; штамп-вердикт —
  tinted-outline бейдж консоли (proven=red / not-proven=green / inconclusive=amber);
  severity — solid-бейджи; doctrine/callout — баннер консоли (амбер, color-mix).
  ТОЛЬКО CSS/разметка — логика вердиктов и данные не тронуты; все имена классов и
  data-атрибуты сохранены
- (2) тристейт дословно из консоли (директива «pass=зелёный, fail=красный,
  UNKNOWN=янтарный»): стадия `success` True→зелёный(pass), False→красный(fail),
  None→янтарный. Перевёрнуты цвета `.dot`/`ol.steps li.ok|fail|unk` (было по-защитному
  confirmed=red) и текст легенды цепочки. Штамп и раскраска стадий читаются из тех же
  записанных вердиктов, что рисует funnel консоли → расхождений нет (сверено на трёх
  состояниях: PROVEN=all-pass зелёный, NOT PROVEN=external_effect refuted красный,
  INCONCLUSIVE=adoption/tool UNKNOWN янтарные — байт-в-байт как console-фикстуры)
  • ВНИМАНИЕ A0 (визуальная приёмка): следствие дословности — PROVEN-прогон рисует
    цепочку зелёной (как funnel консоли), а алярм несёт красный штамп + красные плитки
    ASR (метрика защитника, `_tile_class` не тронут). Это поведение консоли; если нужна
    защитная семантика (confirmed=red) — скажи, разведу цвета цепочки и штампа
- (3) контракт P16 цел: single-file, офлайн, без сети, английский хром + дословный язык
  прогона (причины оракулов/цитаты). Python <3.12: бэкслэшей в выражениях f-строк не
  добавлено — замок `test_threat_report_fstring_py311` зелёный, `ast.parse` feature 3.11 OK
- (4) скрин-фикстуры (3 состояния): отрендерены из реальных mock-прогонов сценариев
  `cross_user_bac` / `cross_user_bac_protected` / `tool_route_hijack_skipped` (как делались
  фикстуры консоли — `campaign --target mock`; их campaign-данные совпадают со stage-формой
  console-фикстур), сняты Chromium/Playwright в тёмной (дефолт) и светлой темах, переданы
  владельцу для визуальной A0 (бинарь в репо не кладём — вне ALLOWLIST)
- проверки: targeted `tests/test_threat_report*.py` — 25 passed (адаптация НЕ потребовалась:
  тесты держатся за data-атрибуты/текст/классы-слова, не за цвета/CSS); полный suite
  **1532 passed / 1 pre-existing fail** (`test_demo_launcher` — Windows-путь
  `scripts\demo-run.ps1` на Linux; `demo.cmd` картой не тронут, дефект платформенный).
  `git diff --check` чист; секретов 0; диффом задет ровно один модуль
- ALLOWLIST соблюдён: `reporting/threat_report.py` (только шаблон/CSS/разметка), LOG.md.
  `tests/test_threat_report*.py` — правок не потребовалось. Не самопринимаю — приёмка A0
  визуальная (штампы/цвета/скрины)

### 2026-09-26 — claude-code — CLI-MEGA-UX · правка D1 (RETURN_FOR_FIX) — рабочий пресет судьи (feat/cli-mega-ux @ 1d14a6f)

- по VERDICT-CLI-MEGA-UX-2026-09-26 (RETURN_FOR_FIX, 1 дефект). D1: `_choose_judge` ставил
  только `args.judge=True`; на сценарии БЕЗ блока `judge:` судья включался с дефолтами JudgeSpec
  (OpenRouter/OPENROUTER_API_KEY/пустая модель) → блокер требовал чужой ключ, с ключом падал на
  `validate_judge_spec`, а карточка «до» обещала deepseek-v4-flash. Обещание словом, не делом
- правка (только путь мастера): `selfserve._apply_default_judge_preset` — когда мастер включил судью,
  у сценария нет своего `judge.model` и нет `--judge-model` → пресет карты §2: model
  `gpt://b1g0nvl5lgk8he84ckp8/deepseek-v4-flash/latest` (folder буква `l`, через `_yandex_model`,
  A0 1d6e9aa), base_url Yandex, api_key_env `PROVIDER_API_KEY`; кладём в сценарий (карточка/блокер/
  ping) И в args; `cli._apply_judge_overrides` теперь применяет `judge_base_url`/`judge_api_key_env`
- не-регресс: свой блок `judge:` и явный `--judge-model` не трогаем; прямые run/campaign этих флагов
  не имеют (getattr→None) → без изменений. Замок: `go --yes` по живому (SK_GENAI_1003+PROVIDER_API_KEY,
  без OPENROUTER_API_KEY) доходит до live-ack с судьёй Yandex
- RED (источник родителя 1d6e9aa, 6 новых тестов) → 6 failed по сути (нет `_apply_default_judge_preset`;
  блокер OPENROUTER; namespace без judge-полей; base_url остаётся OpenRouter). GREEN: targeted 45 (39+6),
  полный suite 1578 / 0 (1572+6). Движок/campaign/атаки/оракулы/mock не тронуты; секретов 0; live не запускал
- ALLOWLIST правки: `cli.py`, `selfserve.py`, `tests/test_selfserve_cli_mega_ux.py` (+секция D1). Сдача в
  handoff/inbox (HANDOFF-CLI-MEGA-UX-D1-FIX + red/targeted/suite логи); не самопринимаю — жду A0


### 2026-09-26 — claude-code — CLI-MEGA-UX: стенд из CLI, авто-ключи, выбор атаки/атакующего, «до проникновения» (feat/cli-mega-ux)

- директива владельца «займись CLI»; карта поглощает UX-STAND-KEYS-MODELS + GO-UNTIL-PROVEN;
  чинит три спотыкания первого пользователя (ушёл в mock думая что бьёт стенд; судья выключен
  молча; после прогона нет пути в консоль). Только mock (smoke); live прогонит A0 по «го»
- (1) новый `standctl.py` + `memnotsafe stand up|down|status|keys`: docker CLI ищется в PATH и в
  `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin`; каталог compose — из `MEMNOTSAFE_STACK2_DIR`/
  pilot.yaml (не хардкод); `up` = compose up -d + ожидание healthz :9600→200; `keys` = перевыпуск
  SK_GENAI_1001..1005 в .env с бэкапом .env.bak (UI_CLIENT_SECRET из env; значения не печатаются).
  Все внешние точки (runner/healthz/issuer) инъектируемы — юниты без реального docker и сети;
  мёртвый Docker/недостижимый healthz → человеческое сообщение, не traceback; compose без shell=True
- (2) `selfserve.py`: карточка «до» первой строкой печатает ЦЕЛЬ (`MOCK (smoke)` / `ЖИВОЙ СТЕНД <url>`);
  непропускаемое подтверждение живого (под `--yes` нужен `--live-ack`); блокер отсутствующих ИМЁН
  ключей перед live (не traceback); явный выбор судьи с ценником (deepseek-v4-flash, ≈3 вызова/попытку)
  и дефолтом по типу цели (live black-box → рекомендуем вкл)
- (3) каталог `go` — группировка по family + однострочное описание из metadata + фильтр по адаптеру
  (`--adapter`); пресеты атакующего (`--attacker-preset` qwen|yandexgpt|deepseek|stub|manual) →
  существующие флаги `--attacker-*` (cli.py:583-593 не тронуты)
- (4) `go --until-proven` зовёт ШТАТНЫЙ `campaign` со `stop_on_success` и iterations=5 (свой цикл не
  строим — петля одна, в движке Campaign.run); cli.py: `campaign --stop-on-success` (врезка в
  `_run_campaign`); честный итог NOT_PROVEN (все N мимо ≠ «готово»); бюджет наперечёт перед стартом
- (5) `selfserve.console_open_hint` + карточки «после» (`go` и `pilot_pack`): точный путь открытия
  прогона в консоли (`cd console && npm run dev` / PowerShell `;`) + каталог прогона. Консоль из CLI
  не стартуем (решение владельца; NOTICED)
- ALLOWLIST: cli.py (врезки), selfserve.py, новый standctl.py, pilot_pack.py (только печать пути),
  tests (2 новых файла), README.md (быстрый старт по факту), LOG.md. Движок/campaign/атаки/оракулы/
  mock НЕ тронуты. Секретов 0; compose без shell=True; значения ключей не печатаются
- замки RED→GREEN: RED на чистом main 8c3b3ef (только новые тесты) — test_standctl ImportError
  (модуль отсутствует) + 22 failed по сути (нет target_goal_line/before_card goal/live-ack/
  missing_key_names/_choose_judge/apply_attacker_preset/group_by_family/until-proven/console_open_hint/
  run_dir), 1 green — pre-existing регресс-гвард mock. targeted 39 passed; полный suite 1572 passed / 0
  (= 1533 базовых + 39 новых)
- DEVIATIONS: D1 подпись коммита Opus 4.8 (карта адресована Fable; STANDING-RULES §8 — по факт-модели);
  D2 folder-id атакующего взят из карты (b1g0nvl51gk8he84ckp8) — расходится с EXECUTOR-BOOTSTRAP §5
  (b1g0nvl5lgk8…, буква l vs цифра 1); docs везде элидят его как gpt://…/, живой литерал только в
  .env/контейнере (читать нельзя) → A0 сверяет до батареи; пресет manual — обход. NOTICED: боевой
  HTTP-поток `stand keys` (Keycloak→9600) реализован best-effort — bootstrap_api_keys.sh вне репо
  (isolated-live-test/, открывать нельзя), сверяет A0 ручным приёмом up→keys→status→down
- live НЕ запускал; ручной приём стенда (up→healthz→status→down) — за A0 по «го» владельца


### 2026-09-26 — claude-code — COND-CANON: условный вариант канона global_policy_injection (feat/cond-canon-global-policy)

- контекст: H09 rate-замер (live, N=12): условная форма — hit-rate WRITE 11/12=0.917 против
  декларатива 2/12=0.167 (Fisher p=0.00064). Карта переносит формулировку в канон вариантом
  `conditional` и готовит полную цепь к live-замеру A0 (WRITE известен, дальше retrieval→
  adoption→external_effect меряет A0 отдельным «го»)
- (1) `attacks/global_policy_injection.py`: `_VARIANTS` += `"conditional"`; в `generate` — ветка
  условного каркаса (структурный аналог ячейки 6 матрицы H09): «Если клиент спрашивает X —
  применяй Y», глагол «применяй» (решение A0; «считайте» не подменяли), ядро перехвата
  `cus="{hijack_value}"` и маркер-операнд V-4 — тот же контракт. bare/self_exfil/safety_framed —
  байт-в-байт прежние (обёрнуты в else, строки не тронуты)
- (2) `scenarios/global_policy_injection_conditional_live.yaml` (новый): живой сценарий варианта
  по образцу `global_policy_injection_live`, `variant: conditional`, `reset_scope: namespace`,
  стенд stack2 (9600/28017), settle 60, маркер-операнд V-4; секретов нет — только имена ENV
- (3) mock-честность: на mock условная форма — ЧЕСТНЫЙ MISS (контракт мока
  `WRITE_MARKERS`/`_INFERRED_RULE_RE` не маршрутизирует «применяй»; в тексте нет «Запомни»/
  «внутренний регламент») → write=False, 0 записей, вердикт NOT PROVEN (излом на write). Мок НЕ
  правили — доказательство варианта live (прецедент ячейки 6 / FATAL-заготовок H09)
- (4) микро-долг вердикта H09-IMPL: докстринг `attacks/h09_matrix.py` — ключ family теперь ЕСТЬ
  в FAMILY_PLAYBOOK (severity_map, impact cross_user_data → CRITICAL), устаревшая фраза исправлена
- (5) замки: `tests/test_global_policy_conditional_variant.py` (4: каркас/ядро/код,
  маркер-операнд, честный mock-MISS + NOT PROVEN, декларация live-сценария);
  `tests/test_control_factor_inventory.py` +1 строка `EXPECTED_UNPAIRED` (live-only вариант, не-live
  двойника по правилу паринга нет). MAP.md сценарии поимённо не перечисляет («20 семейств», вариант
  семью не добавляет) — правки MAP не требовалось
- проверки: RED на базе 0fda533 (новый тест, скопирован на detached-базу) — 4 failed по СУТИ карты
  (variant отвергнут ValueError / сценарий отсутствует); targeted 76 passed; полный suite
  **1533 passed / 0** (= 1528 базовых + 4 новых + 1 параметр reset_scope). `git diff --check` чист;
  live НЕ запускал (по «го» A0 после влития)
- ALLOWLIST соблюдён: `attacks/global_policy_injection.py`, `attacks/h09_matrix.py` (докстринг),
  новый сценарий, tests, LOG.md. Мок/раннер/оракулы/ядро НЕ тронуты

### 2026-09-25 — claude-code — FIX-C: reset_scope по умолчанию безопасен и достижим из YAML (fix/qa-c-reset-scope)

- дефект (перепроверен, блокер перепрогона G3.1/G3.2): дефолт `scope="global"` в
  investment_stand → `reset_state()` делал `delete_many({})` по ВСЕМ 4 коллекциям,
  включая `agent_policy_memories` (глобальный слой политик — предмет G3.2); ни один
  сценарий не задавал режим, а `build_adapter` прокидывал только `target.extra` →
  namespace-режим адаптера был НЕДОСТИЖИМ из YAML. Эрратум G3.1: живые прогоны шли
  с глобальным wipe (стирали то, что измеряли)
- (1) `core/config.py`: у `Scenario` новое поле `reset_scope` (default отныне
  `"namespace"`), парсится из верхнеуровневого ключа YAML. `build_adapter` прокидывает
  его в адаптер ЯВНО (`scope=reset_scope`); `"global"` — только по явному слову И с
  непустым `target.reset_ack`, иначе `ValueError` (защита от опечатки/унаследованного
  global). `scope`/`reset_ack` исключаются из extra (единый источник, без дубля kwarg)
- (2) `adapters/investment_stand.py`: страж имени БД — при `scope="global"` имя БД
  обязано matchить паттерн тестового стенда (`agent_memory` / `agent_memory_<suffix>`),
  иначе `ValueError` в конструкторе ДО обращения к Mongo (защита от опечатки в
  mongo_uri/mongo_db живого прогона). Опечатку в самом scope по-прежнему ловит
  прежняя проверка `scope not in _RESET_SCOPES`
- (3) миграция 16 живых investment_stand-сценариев: явная строка
  `reset_scope: namespace` (фиксация намерения; дефолт и так namespace)
- поведение адаптера при namespace/global не менял (только достижимость + стражи);
  ASR/оракулы не тронуты. Прежний прямой конструктор адаптера (scope default global)
  сохранён для тестов — безопасный дефолт живёт на уровне Scenario/build_adapter
- замок `tests/test_reset_scope_default_safe.py` (24): сценарий без поля → namespace;
  namespace достижим из YAML; global без ack / с пробельным ack → отказ; global+ack →
  глобальный адаптер; опечатка scope → отказ; страж БД (global+чужая БД → отказ,
  agent_memory[_suffix] → ок); все 16 живых сценариев резолвятся в namespace
- проверки (по разу): RED на базе 9043476 → 22 failed / 2 passed; targeted →
  173 passed; полный suite → 1509 passed / 0 (= 1485 базовых + 24 новых);
  git diff --check чист; секретов 0 (в YAML — только ИМЕНА ENV, как и было)
- ALLOWLIST: core/config.py, adapters/investment_stand.py (только страж),
  scenarios/*.yaml (ровно +1 строка reset_scope на файл), тест, LOG — соблюдён
- DEVIATION: база `9043476` (свежий main из постановки владельца), не `0685392`
- **После влития — A0 перепрогоняет G3.1/G3.2** (namespace: изоляция держится на
  свежих session_id, глобальный слой политик больше не стирается между попытками)

### 2026-09-25 — GLM — H09-IMPL: исполняемые ячейки матрицы H09 — семья h09_matrix (feat/h09-matrix-family)

- задача: сделать 8 заготовок scenarios/h09-matrix/ исполняемыми (карта
  CARD-H09-IMPL-2026-09-25): семья-наследник канона global_policy_injection,
  payload из params.payload_text (принцип II: новый файл, канон/ядро не тронуты);
  замки RED→GREEN; сверка mock-прогонов с эталоном замера H09-MATRIX
  (1–4 HIT global cus=1005, 5–8 MISS)
- НОВЫЙ `attacks/h09_matrix.py`: наследник GlobalPolicyInjection; payload_text
  ОБЯЗАТЕЛЕН (отсутствие/пустой → ValueError в generate() ДО доставки; через
  раннер — RunnerError с ValueError в cause); expected_effect наследуется через
  super() с правкой policy_code на код ячейки из params (метка атрибуции,
  fallback — детерминированный POL- канона); marker-operand V-4 и
  delivery/trigger наследуются; variants bare|self_exfil|safety_framed унаследованы
- регистрация: `attacks/__init__.py` +1 строка импорта (штатная точка
  расширения); `reporting/severity_map.py` +строка FAMILY_PLAYBOOK["h09_matrix"]
  (инвариант set(ATTACK_REGISTRY)==set(FAMILY_PLAYBOOK), test_threat_report:566;
  impact cross_user_data, remediation канона — та же цепь)
- сценарии: 8 ячеек scenarios/h09-matrix/ (переведены в статус «исполняемо»,
  README обновлён) + канон-представитель scenarios/h09_matrix.yaml в корне
  (= ячейка 2, требование test_protected_symmetry_audit: канон-сценарий id==family
  в корне, подкаталоги не сканируются)
- инвентарь: tests/test_control_factor_inventory.py EXPECTED_UNPAIRED + "h09_matrix"
  (канон-представитель непарный; ячейки в подкаталоге glob'ом не видны)
- замки `tests/test_h09_matrix.py` (9): регистрация; ValueError без/с пустым
  payload_text (прямой и через раннер — до доставки, память пуста); payload
  verbatim; marker-operand контракт канона (tail отвергнут); expected_effect
  type==global_policy_injection + код ячейки; ячейка 2 — HIT global cus=1005 с
  полной цепью (write…external True); ячейка 6 — MISS (все стадии False, 0 записей)
- проверки: RED на чистой базе 9/9 FAILED (KeyError family='h09_matrix',
  коммит cdb8189) → GREEN 9/9 passed; CLI-прогоны 8×1 (rc=0 всюду): ячейки 1–4
  write=True и цепь PROVEN (success=True), 5–8 все стадии False — ЭТАЛОН
  воспроизведён, расхождений нет (сводка: handoff/inbox/h09-impl-logs-2026-09-25/)
- suite: первый прогон 1493 passed / 3 FAILED — все три об инварианте
  playbook-регистрации (severity-single-source[h09_matrix], threat_report:566):
  я пропустил штатную строку FAMILY_PLAYBOOK; после добавления (и после чистки
  приватного кросс-модульного импорта _PORTFOLIO_TOOL → super()-наследование,
  замок test_no_private_cross_module_imports_in_src) финальный прогон
  **1496 passed / 0 failed** на ветке
- ALLOWLIST-отклонения (все — штатные точки расширения при регистрации семьи,
  прецедент 07a0350 H2x): attacks/__init__.py (+1 строка),
  reporting/severity_map.py (+playbook-строка), scenarios/h09_matrix.yaml
  (новый файл в корне), tests/test_control_factor_inventory.py (+1 строка).
  Канон global_policy_injection.py, оракулы, runner, mock — НЕ тронуты
- границы: только mock; live/.env/стенд не тронуты; rate-замер (трио 2/1/6,
  N=12) — отдельное «го» владельца; ветка локально, без push, не самопринято
### 2026-09-26 — claude-code — FIX-D: порядок маркера H19/H22 + ловушка W10 (fix/qa-d-marker-order)

Два в одном (последняя карта FIX-PACK-QA).

**(а) порядок маркера H19/H22.**
- дефект (перепроверен): `core/campaign.py` в REGISTERED-записи истории (attempt 0)
  звал `attack.expected_effect(ctx)` ДО того, как runner выводит `ctx.case_marker`
  (инвариант T002-10/FR-B «producer маркера — runner»). У маркерных семей
  `deferred_payload` (H22) и `delimiter_summary_injection` (H19) `expected_effect`
  требует маркер → `_require_marker` бросал ValueError НАРУЖУ трейсбеком; эти семьи
  были непрогоняемы через run/go
- фикс: новый `_registered_goal_digest(attack, ctx)` откладывает goal_digest
  REGISTERED-записи (None), если маркер ещё не выведен; на пост-ран записи (attempt 1)
  он и так считается из `candidate.expected_effect` с уже выведенным маркером.
  Контракт истории не изменён (goal_digest и так Optional). Реальные ошибки
  expected_effect не глотаются — всплывают в run_attack (generate зовёт его с
  маркером). Producer маркера остался в runner (маркер в campaign НЕ вывожу)
- выбор обоснования: «отложить запись expected_effect», а не «получать маркер
  заранее» — последнее нарушило бы инвариант «producer маркера — runner»

**(б) ловушка W10 (editable-install).**
- дефект (QA W10): `pip install -e` мог указывать на СТАРЫЙ checkout — «голый»
  `memnotsafe` молча исполнял старую версию
- фикс: `selfserve.render_provenance(console)` печатает версию/путь пакета при
  старте `go` и `pilot` и предупреждает, если пакет импортирован НЕ из текущего
  дерева (сравнение `Path(memnotsafe.__file__)` с `cwd/src`|`cwd`). Ничего не
  блокирует — только предупреждение. Общий хелпер в selfserve, pilot_pack его
  импортирует (существующее ребро pilot_pack→selfserve)

- замок `tests/test_marker_order_and_provenance.py` (8): deferred-payload и
  delimiter-summary-injection прогоняются через Campaign без трейсбека (главный
  замок карты); `_registered_goal_digest` откладывает без маркера / считает с
  маркером и у обычных семей; `_package_is_in_tree` true/false; render_provenance
  предупреждает вне дерева и молчит в дереве (печатая провенанс всегда)
- проверки (по разу): RED на базе 864cace → 8 failed (2 — реальный ValueError из
  expected_effect через Campaign; 6 — новые символы); targeted → 72 passed;
  полный suite → 1493 passed / 0 (= 1485 базовых + 8 новых); git diff --check чист;
  секретов 0
- ALLOWLIST: core/campaign.py, selfserve.py/pilot_pack.py (только провенанс/
  предупреждение), тест, LOG — соблюдён
- DEVIATION: база `864cace` (свежий main из постановки владельца), не `0685392`
### 2026-09-25 — claude-code — P19: PEP 701 замок на весь пакет + wheel со сценариями пилота (для пилота Влада)

- база: main = `9043476`; ветка сессии `claude/dazzling-goodall-l7hww1` (карта
  просила `feat/p19-py311-smoke-wheel` — расхождение отмечено в PR). НЕ атаки, НЕ live
- ALLOWLIST соблюдён: `pyproject.toml`, `pilot_pack.py` (только резолвинг),
  `tests/test_py311_fstring_hygiene.py` (new), `test_pilot_pack.py`,
  `test_threat_report_fstring_py311.py` (переиспользование хелпера) + новый
  package data `src/memnotsafe/pilot_scenarios/`. MANIFEST.in НЕ понадобился
  (package-data кладёт .yaml в wheel). Сценарии не редактировались (копии байт-в-байт)
- **Часть 1** — обобщён AST-сканер FIX-E на весь `src/memnotsafe/`: общий хелпер
  `fstring_expr_backslash_offenders` в новом тесте; `test_all_package_modules_*`
  падает, если хоть одно выражение FormattedValue (вкл. format_spec и вложенные
  f-строки) содержит бэкслэш. FIX-E-тест теперь переиспользует хелпер (поведение
  замка на threat_report.py не изменено). Точность позиций — на 3.12+ (интерпретатор
  suite); на 3.11 реальный дефект и так не даёт ast.parse. RED показан на
  искусственном дефектном модуле (в tmp_path сканер ловит бэкслэш; отдельно —
  временный дефектный модуль в src → whole-tree gate краснеет → удалён → зелено)
- **Часть 2** — стартовый набор сценариев пилота упакован в wheel как package
  data пакета `memnotsafe.pilot_scenarios` (4 файла, копии `scenarios/<name>.yaml`
  байт-в-байт). `pilot_pack._resolve_pack_path` резолвит: importlib.resources →
  fallback на repo-путь (dev). Контракт CLI не менялся. Единый источник истины
  защищён `test_packaged_pilot_scenarios_match_repo_originals` (дрейф = красный).
  Замки: ресурс виден через importlib.resources; pilot резолвит сценарий с
  подменённым (мёртвым) `_REPO_ROOT` — RED→GREEN
- проверка wheel: `pip wheel . --no-deps` → 4 сценария внутри
  `memnotsafe/pilot_scenarios/`; офлайн-установка (`--no-index --no-deps`) в свежий
  venv → importlib.resources видит все 4 БЕЗ каталога репозитория
- проверки: RED→GREEN по каждой части (per-test, стэш src + скрытие пакета);
  полный `pytest tests/` — **1491 passed** на Python 3.12 (1 пред-существующий
  провал `test_demo_launcher.py` — Windows-разделитель `\` на Linux, вне P19).
  `git diff --check` чист, секретов ноль
- НЕ самопринимаю: приёмка A0
- открытые/пред-существующие: `test_demo_launcher.py` (Windows-путь на POSIX) —
  платформенный артефакт канона, не связан с P19


### 2026-09-25 — claude-code — FIX-E: f-string backslash ломает импорт threat_report на Python <3.12 (fix/qa-e-fstring-backslash)

- дефект (просьба владельца, блокер демо Влада): `reporting/threat_report.py:1396`
  — бэкслэш `\"` внутри ВЫРАЖЕНИЯ f-строки `{... else '<span class=\"muted\">—
  </span>'}`; легально с PEP 701 (3.12+), но на Python <3.12 это жёсткий
  SyntaxError на этапе импорта → весь модуль неимпортируем → бизнес-отчёт
  `threat-report` не открывается. venv здесь 3.14 (импорт проходит), поэтому
  дефект латентен для наших прогонов, но рвёт демо-стенд на старом интерпретаторе
- фикс: em-dash пустой причины вынесен в переменную `muted_dash` ДО f-строки;
  выражение `{...}` больше без бэкслэша, вывод байт-в-байт прежний (+5/−1)
- замок `tests/test_threat_report_fstring_py311.py` — структурный AST-скан: ни
  одно выражение `FormattedValue` (и format_spec) во ВСЁМ модуле не содержит
  бэкслэша (инвариант до PEP 701). RED на базе: ровно один узел (строка 1396);
  GREEN после. Портативно: на <3.12 тест краснеет ошибкой импорта при сборке, на
  ≥3.12 — ассертом на латентный дефект
- DEVIATION: механизм замка из просьбы — `ast.parse(feature_version=(3,11))` — на
  3.14 НЕ ловит дефект (feature_version не возвращает старый токенайзер f-строк;
  эмпирически проверено, был бы зелёным на базе). Заменён на эквивалентный по
  смыслу структурный скан, который реально краснеет на базе
- DEVIATION: база `bf56518` (свежий main), не `4decedd` из постановки — main
  ушёл вперёд (CONSOLE + docs v3.60, threat_report.py не затронут); `bf56518 ⊇
  4decedd (FIX-A)`
- проверки (по разу): RED `tests/test_threat_report_fstring_py311.py` на базе
  bf56518 → 1 failed; targeted (new + test_threat_report + global_policy_injection)
  → 45 passed; полный suite → 1445 passed / 0 (= 1444 базовых + 1 новый)
- ALLOWLIST (карта-хотфикс без явного списка → минимальный след): threat_report.py
  (только вынос литерала), новый тест, LOG.md — соблюдён; секретов 0; diff --check чист
### 2026-09-25 — claude-code — FIX-PACK-2 / MULTI-1: харденинг планировщика пакетов (семантика, не структура)

- база: main = `bf56518`; ветка сессии `claude/dazzling-goodall-l7hww1` (карта
  просила `fix/multi1-scheduler-hardening` — расхождение отмечено в PR)
- ALLOWLIST соблюдён: `core/plan.py`, `core/worker.py`, `tests/test_plan_orchestrator.py`,
  новый `tests/test_scheduler_hardening.py`, `LOG.md` — ядра стадий/атак/оракулов/CLI не касался
- D1 расход = ФАКТ вызовов цели из `<run_dir>/budget-ledger.jsonl` (operation=target_call,
  phase=executed), не знаменатель ASR (число КЕЙСОВ): общий `plan.count_executed_target_calls`
  / `resolve_target_calls_actual`; леджера нет/битый → грубая оценка m с пометкой `estimate:true`;
  расход контроля считается так же
- D2 `requires` разблокирует зависимое ТОЛЬКО исходом completed (`plan._deps_status`): иначе
  зависимое → `blocked` с detail «зависимость <id> <outcome>»; цепочка «разведка→атака» больше
  не стартует после провала разведки (гейт и слив `_drain_blocked` через один хелпер)
- D3 `orchestrate_plan` обёрнут try/except/finally: run_plan наполняет переданный `results`,
  при исключении воркера недовыполненные → `unknown` (detail = тип исключения), summary.json +
  batch-state.json ВСЁ РАВНО пишутся, исключение пробрасывается
- D4 `rebuild_summary` берёт факт из леджера (не m) и добавляет расход контроля симметрично
  живому пути (прежде терялся); estimate-флаг и принципалы восстанавливаются из состояния
- D5 (осознанная смена семантики): `isolation_group` — маркер ОБЩЕГО РЕСУРСА, не независимости.
  Обе PlanError-проверки пересечения принципалов удалены; пересечение принципалов у РАЗНЫХ
  групп → неблокирующее предупреждение сводки (`plan.plan_warnings`, ключ `warnings`). Гейт
  параллелизма (общая группа ≤1 активного) не тронут. Затронутые тестовые планы: два
  `test_stop_*` в `test_plan_orchestrator.py` переписаны (легальность + предупреждение)
- D6 (record-only): стенд/принципалы пробрасываются дочернему процессу env-ом
  `MEMNOTSAFE_BATCH_STAND_ID`/`MEMNOTSAFE_BATCH_PRINCIPALS` (`worker.batch_child_env`, дочерний
  CLI их игнорирует), принципалы стенда прогона пишутся в JobRun/summary
- проверки (RED→GREEN per-defect на чистой базе, стэш только src): RED 17 failed / 26 passed;
  после фиксов затронутые файлы 53 passed; полный `pytest tests/` — 1458 passed на Python 3.12
  (интерпретатор канона; на 3.11 `reporting/threat_report.py` не парсится по PEP 701 — вне
  scope, не в allowlist). `git diff --check` чист, секретов ноль. Детерминированно, без реальных
  подпроцессов; существующий integration-тест не сломан (расширен D1/D6-ассертами)
- НЕ самопринимаю: приёмка A0 (семантический спот-тест с подставным runner, пишущим
  budget-ledger.jsonl с известным числом target_call)
- открытые/пред-существующие: `test_demo_launcher.py` падает на Linux (Windows-разделитель
  `\` в demo.cmd) — платформенный артефакт канона (Windows), вне FIX-PACK-2
### 2026-09-25 — claude-code — FIX-B: единый источник severity (fix/qa-b-unified-severity)

- дефект (перепроверен): `reporting/findings.py::_SEVERITY_BY_FAMILY` знал 4
  семьи, остальные 18 молча падали в MEDIUM (`.get(f,"MEDIUM")`) и так уходили в
  SARIF/JSON — расходясь с каноном эталона `threat_report.IMPACT_SEVERITY` по
  `FAMILY_PLAYBOOK[family].impact`. Одна находка = CRITICAL в threat-report, MEDIUM
  в SARIF (global_policy_injection; tool_route_hijack — HIGH vs MEDIUM)
- цикл: `threat_report` импортирует `findings` (:119) + инвариант ацикличности
  `tests/test_import_layers.py` (SCC>1 запрещён, граф по AST ловит и ленивые
  импорты) → findings НЕ может импортировать threat_report ни на каком уровне.
  Поэтому канон вынесен в НОВЫЙ лист `reporting/severity_map.py` (импортирует
  только typing) — его берут и findings, и threat_report, без цикла
- (1) `severity_map.py`: `IMPACT_SEVERITY`/`_SEVERITY_RANK`/`FAMILY_PLAYBOOK`
  перенесены дословно из threat_report + `impact_severity_for_family(family)`
  (severity по канону; None = семья без записи) + сентинел `UNRATED`
- (2) `threat_report.py`: таблицы заменены импортом-реэкспортом из severity_map
  (внешние читатели `tr.FAMILY_PLAYBOOK`/`IMPACT_SEVERITY` — selfserve, тесты —
  видят их по-прежнему; `_severity`/`_observed_impact` не тронуты)
- (3) `findings.py`: удалён `_SEVERITY_BY_FAMILY`; severity SUCCESS-находки =
  `impact_severity_for_family(display_key)`; None → `UNRATED` с причиной в
  `status_reason`, НЕ молчаливый MEDIUM. Композит/ASR не тронуты
- (4) `sarif.py`: `UNRATED → level=note` (иначе неоценённая находка читалась бы
  как warning≈MEDIUM)
- изменились ровно 2 семьи (обе были занижены): global_policy_injection
  MEDIUM→CRITICAL, tool_route_hijack MEDIUM→HIGH; прочие 20 не изменились; все 22
  семьи реестра есть в FAMILY_PLAYBOOK (UNRATED — защитная ветка для будущих семей)
- замок `tests/test_severity_single_source.py` (25 тестов): сверка severity
  каждой находки с каноном эталона (параметризовано по всему ATTACK_REGISTRY);
  tool_route_hijack → SARIF error/HIGH; cross-user → CRITICAL в обоих выходах;
  неизвестная семья → UNRATED/note. Канон в тесте берётся из threat_report-таблиц
  (есть на базе и после) → RED краснеет ПО СУТИ
- DEVIATION: карта предлагала «findings берёт правило вызовом/импортом из
  threat_report». Прямой импорт НЕВОЗМОЖЕН (цикл + test_import_layers). Реализовано
  эквивалентно через общий лист severity_map — это и есть «вынос общего доступа»
  из ALLOWLIST, просто отдельным модулем (иначе SCC-инвариант красный)
- DEVIATION: новый файл `reporting/severity_map.py` — вне буквального списка
  ALLOWLIST (findings/threat_report/sarif/tests/LOG), но требуется ацикличностью;
  MAP.md строка 39 стоит дополнить `severity_map` (и там уже нет `sarif`) — не
  трогал, MAP вне ALLOWLIST, оставил A0
- DEVIATION: база `bf56518` (свежий main), FIX-E ещё не влит — пересечений с ним нет
- проверки (по разу): RED на базе bf56518 → 4 failed / 21 passed; targeted →
  146 passed; полный suite → 1469 passed / 0 (= 1444 базовых + 25 новых);
  git diff --check чист; секретов 0


### 2026-09-25 — claude-code — FIX-A: мягкое доказательство ≠ доказанное без судьи (fix/qa-a-adoption-channel)

- дефект (QA-аудит, перепроверен A0): живой стенд поднимает `capabilities.trace/
  tool_calls` по ЛЮБОМУ каналу, включая victim_response (regex-скрейп текста
  ответа), и синтезирует из скрейпа `llm_decision{resolved_cus}`/`tool_result`;
  `oracles/adoption.py::_adoption_from_decision` ставил жёсткое
  EVIDENCE_KIND_TELEMETRY, игнорируя `channel` (в отличие от external_effect);
  судья по умолчанию выключен, `_blocked_by_unavailable_judge` срабатывал только
  при СКОНФИГУРИРОВАННОМ судье → отказ жертвы с цитатой чужого cus в тексте
  штамповался SUCCESS/CRITICAL
- (1) НОВЫЙ общий хелпер `oracles/adoption.py::channel_evidence_kind(events)`:
  канал victim_response → мягкое signature_match, иначе (в т.ч. без поля channel:
  mock/белый ящик) → жёсткое telemetry; `_adoption_from_decision` теперь берёт
  природу по каналу решений, подтвердивших вердикт
- (2) `oracles/external_effect.py::_effect_evidence_kind` — тонкая обёртка над
  общим хелпером (вынос правила канала, чтобы adoption и external_effect судили
  victim_response одинаково); лишние импорты kind-констант убраны
- (3) `reporting/findings.py`: новое `_soft_only_effect_stages` — если НИ ОДНА
  True-стадия эффекта (adoption/external_effect) не подтверждена жёстко/судьёй
  (только marker/signature без судьи), находка понижается SUCCESS→INCONCLUSIVE
  (severity INFO), с названной причиной в новом поле `Finding.status_reason`;
  правило judge-unavailable распространено на «судьи не было вовсе». scope_escalated
  (жёсткая adoption в глобальном слое) и жёсткая телеметрия SUCCESS сохраняют
- НЕ трогает композит (`result.success`) и ASR (считаются по r.success), поэтому
  метрики/воронка неизменны; понижение живёт только в слое отчёта
- замок tests/test_evidence_kind_soft_no_judge.py (6): adoption канал→природа
  (soft/hard), findings-понижение мягкого успеха без судьи + причина, регресс
  жёсткой телеметрии, судейское мягкое сохраняет успех, сквозной «_RefusalStand»
  (отказ с цитатой чужого cus, канала телеметрии нет) → находка не SUCCESS
- RED на базе 2d87850: 3 failed / 3 passed (замки эффекта падают, регрессы
  зелёные); targeted 482 passed; полный suite 1444 passed (1438 + 6)
- ALLOWLIST соблюдён (adoption, external_effect, findings, новый тест, LOG);
  `git diff --check` чист, секретов 0. НЕ самопринято — жду вердикт A0

### 2026-09-25 — claude-code — CARD-CONSOLE: Mission Control (console/)

- задача: новый каталог `console/` в зеркале — статичный офлайн-вьюер артефактов
  прогона (React+TS+Vite). Только чтение локальных JSON/HTML; ноль сети, ноль
  секретов. Ядро (`core/`, `cli.py`, атаки, оракулы) не трогалось.
- форматы выучены из кода-продюсера, не выдуманы: `campaign.json` ←
  `core/campaign_serialize.py` (`aggregate_metrics.funnel` — pass/fail/unknown/total
  на 6 стадий); `findings.json` ← `reporting/findings.py` (status
  SUCCESS/NOT_EXPLOITABLE/INCONCLUSIVE, severity, ATT&CK/OWASP); `attempts.jsonl` ←
  `core/attempt.py`; `budget-ledger.jsonl` ← `core/ledger.py` (usage=null = unknown,
  не ноль); `report.html`/`threat-report.html` — self-contained, встраиваются в
  sandbox-iframe и линкуются.
- доктрина в коде (`src/lib/tristate.ts`): тристейт pass/fail/UNKNOWN не
  схлопывается. UNKNOWN ≠ safe и UNKNOWN ≠ exploited: null-стадия — янтарная, не
  зелёная и не красная, в ASR не входит. Ключевой фикс self-review: кейс, который
  `findings.json` пометил NOT_EXPLOITABLE, но со стадией success=null, считается
  INCONCLUSIVE, не controlled (единый `caseVerdict` для бейджа рана, статуса кейса
  и метрик — рассинхрона нет). Сырой `findings.json`-статус тоже показан рядом.
- знаменатель ASR — завершённые КЕЙСЫ из `campaign.json`, не строки
  `attempts.jsonl` (истории попыток суммируются только описательно).
- фикстуры `console/fixtures/` — 3 реальных прогона `campaign --target mock`
  (синтетика, без живой памяти): vulnerable (EXPLOITED, ASR 100%), protected
  (CONTROLLED, контроль держит, ASR 0%), tool_route_hijack_skipped (INCONCLUSIVE:
  adoption/tool не наблюдались — ASR 0%, но НЕ safe). Секрет-скан фикстур чист.
- вьюхи: галерея прогонов со штампами; страница прогона с воронкой (тристейт-бары),
  таблицей кейсов (статус/severity/тристейт-точки/ATT&CK+OWASP), сводками попыток и
  бюджета, превью отчётов; загрузка своего `runs/<name>/` через FileReader (ничего
  не выгружается).
- проверки прогнаны реально: `npm run build` (tsc app+node + vite) — OK;
  `npm test` (tsc tsconfig.test + vitest) — 19 passed (parse на реальных фикстурах,
  доктрина тристейта, render-smoke: баннер «UNKNOWN ≠ safe» на skipped-ране);
  `npm run dev` и `npm run preview` подняты и отдают index+ассеты (200). lockfile
  зафиксирован.
- ограничения: `memnotsafe threat-report` на этой машине падает SyntaxError
  (f-string с бэкслэшем, Python 3.11 < 3.12 PEP 701) — это в `reporting/threat_report.py`,
  вне scope карты, не чинил; `threat-report.html`-фикстуры поэтому нет, вьюер
  переносит её отсутствие штатно (artifact note). База ветки — 2d87850.
- предупреждение сборки про размер чанка ожидаемо: фикстуры (полный evidence +
  report.html) инлайнятся в бандл; это демо-данные, не ошибка.

### 2026-09-24 — claude-code — P17: пилот одной командой (feat/p17-pilot-pack)

- задача: `memnotsafe pilot` — продуктовая упаковка поверх существующих механик
  (T1 http_endpoint, probe, preflight, стартовый пак, threat-report P16); атак не
  сочинять, переиспользовать вызовом, контракты CLI/T1/runner не менять
- НОВЫЙ src/memnotsafe/pilot_pack.py: `--init` (валидный шаблон pilot.yaml +
  подсказка); `--config … --output …` — цепочка build_adapter(T1) → probe →
  run_preflight → стартовый пак (Campaign по существующим сценариям реестра
  против ручки) → объединённый campaign.json + events → write_threat_report
  (рендерер P16) → консольная сводка (штамп, N of M, путь); `--baseline …` —
  retest-секция (FIXED/STILL VULNERABLE/NEW/UNKNOWN)
- переиспользование ВЫЗОВОМ (логика не копируется): selfserve.load_dotenv +
  selfserve.attempt_lines, reporting.threat_report.write_threat_report,
  preflight.run_preflight, core.Campaign, core.config.build_adapter,
  core.result_readouts.aggregate_metrics, campaign_serialize.campaign_to_dict
- cli.py: одна аддитивная врезка (маркер CARD-P17, ленивый импорт, load_campaign
  параметром — pilot_pack не импортирует cli)
- стартовый пак — данными в модуле из существующих сценариев реестра
  (cross_user_bac_c_mk_operand, direct_poisoning, cross_user_bac + control
  cross_user_bac_protected); новых атак нет
- ЗАМОК UNKNOWN ≠ FIXED: тристейт кейса берётся из вердикта threat-report P16
  (PROVEN→True, NOT PROVEN→False, INCONCLUSIVE→None); classify_retest никогда не
  выносит FIXED при новом None (без наблюдаемости «исправлено» не доказать)
- ошибки человекочитаемые: нет env-ключа → инструкция (rc 2, без traceback);
  ручка недоступна → причина probe (rc 2); budget_cap обязателен (валидация);
  секретов ноль — наружу только ИМЯ переменной api_key_env
- skill/SKILL.md (англ., внешний потребитель): установка → env-ключ → --init →
  запуск → чтение отчёта (штамп, INCONCLUSIVE ≠ safe) → retest; секретов ноль
- отклонение: preflight из уже запущенного цикла нельзя звать напрямую
  (run_preflight внутри делает asyncio.run) — уносим в поток (run_in_executor)
- отклонение: ветка feat/p17-pilot-pack (новая, не env-pinned) — по требованию
  карты; коммит на main = eed3bb9
- отклонение: ultracode сессии OFF — совпало с бюджетом карты; solo, один проход
  self-review
- проверки (venv python 3.12.3, `pip install -e .`, PYTHONIOENCODING=utf-8,
  `-p no:cacheprovider`): RED на базе eed3bb9 — tests/test_pilot_pack.py
  collection ModuleNotFoundError (pilot_pack нет); полный suite
  `python -m pytest tests -q` — 1416 passed / 1 failed (единственный failed —
  test_demo_launcher, Windows-путь в POSIX, вне диффа; = 1407 базовых + 10 новых,
  на каноне 1417/0); e2e против localhost fake-сервера (probe→preflight→run→
  threat-report.html со штампом INCONCLUSIVE, pilot-cases.json, retest без FIXED);
  git diff --check чист, секретов 0
- NOTICED (не делал): scenarios/ не в wheel — пилот резолвит пак от корня
  репозитория (parents[2]); из голого pip-install без чекаута пак не найдётся
  (нужен чекаут/упаковка сценариев — Этап 2); необязательный chat_path в конфиге
  под нестандартные пути ручки — не добавлял (Этап 2); MAP.md обновляет A0 при влитии

### 2026-09-25 — claude-code — H2x: семья global_policy_injection (feat/h2x-global-policy-injection)

- задача: формализовать доказанную A0 цепь CRITICAL (P13-e, v3.52) в семью
  `global_policy_injection` — policy-shaped payload с операнд-маркером V-4,
  global-зона + steering/adoption/consequence оракулы, live + black-box
  сценарии, строка FAMILY_PLAYBOOK. Движок/runner/cli не трогать
- НОВЫЙ `attacks/global_policy_injection.py`: policy-payload (регламент банка +
  внутренний код POL-… + числовой якорь 0.1%) с операндом перехвата
  `cus="attacker"` и изоморфным операнд-маркером `reg="CM-…"` (стиль operand,
  V-4); варианты bare|self_exfil|safety_framed; multi-turn delivery;
  trigger = benign-портфель + citation-проба (детекция чёрного ящика)
- оракулы (АДДИТИВНЫЕ ветки типа `global_policy_injection`, существующие стадии
  не тронуты): tool — steering по hijack_field≠session; adoption —
  `resolved_cus==hijack` (телеметрия) ЛИБО цитата правила в ответе (marker_match),
  честный тристейт; external_effect — `customer==hijack & 200` (consequence).
  WRITE/PERSIST/RETRIEVE тип-агностичны, global-слой уже покрыт (scope=None)
- сценарии: `global_policy_injection.yaml` (mock-канон, база), `_live.yaml`
  (белый ящик investment_stand 9600/28017, telemetry-детекция),
  `_bb_live.yaml` (чёрный ящик http_endpoint tier-1, citation-детекция)
- reporting: строка семьи в `FAMILY_PLAYBOOK` (impact cross_user_data → CRITICAL,
  remediation из v3.52)
- НОВЫЙ `tests/test_global_policy_injection.py`; правки существующих замков —
  см. хендоф (2 файла сверх исходного ALLOWLIST, санкционировано владельцем)
- проверки: RED на базе → targeted → полный suite один раз; числа в хендофе
- открытые риски: bb на http_endpoint (не investment_stand) — живую разводку
  эндпоинта подтверждает A0; live-прогоны делает A0 после влития


### 2026-09-24 — claude-code — MULTI-1: планировщик пакетов проверок, Этап 1 офлайн (feat/multi1-plan-orchestrator)

- задача: режим `memnotsafe orchestrate --plan plan.yaml --output runs/<batch>` —
  планировщик тестовых операций поверх существующих команд; движок стадий и
  старый `orchestrate --scenario` не трогать; тексты сценариев не открывать
- НОВЫЙ core/plan.py (зависит только от stdlib+yaml, периферию/reporting не тянет):
  модель Plan/Stand/Job + load_plan/validate_plan (стоп ДО первого запуска,
  PlanError с конкретной причиной), планировщик run_plan (инжектируемый runner),
  таксономия исходов + classify_outcome, сводка build_summary/write_batch/
  rebuild_summary
- core/worker.py: ОДНА точка входа orchestrate_plan — грузит+валидирует план,
  гоняет run_plan с дефолтным исполнителем (подпроцесс CLI-кампании, приём
  PYTHONPATH как у orchestrate_campaign) и дефолтной проверкой чистоты (hook
  clean_check профиля); пишет summary.json + batch-state.json; rc 0/1 как у
  orchestrator_rc. Существующие FileLease/orchestrate/orchestrate_campaign не
  тронуты
- cli.py: одна аддитивная врезка (маркер CARD-MULTI-1, ленивый импорт); --plan
  добавлен, --scenario сделан не-required (старый вызов `orchestrate --scenario
  X --output Y` работает как прежде); --plan и --scenario взаимно исключают
- планировщик: очередь; 1 активное задание на стенд; общая isolation_group
  блокирует параллелизм (≤1 активное на группу); ≤ max_parallel_stands активных
  стендов; committed вызовов ≤ max_total_target_calls (потолок не превышается,
  оценка ДО выдачи); каждый job_id выдаётся ровно один раз (повторы — только
  iterations); re-check чистоты перед выдачей (грязный/UNKNOWN — не выдаём); deps
  requires гейтят выдачу
- исходы различимы (транспорт/401/429/неполный finalize/неизвестно/бюджет/грязно/
  UNKNOWN-чистота/blocked), скрытых повторов нет; сводка: batch_id, дочерние
  experiment_id, статусы, ASR как N of M, расходы, ссылки на артефакты; UNKNOWN ≠
  False (asr value=None, не 0); секретов нет; rebuild_summary пересобирает из
  batch-state + артефактов, задания НЕ перезапускает
- интерпретации (карта оставила детали исполнителю): (1) isolation_group ⟺
  пересечение принципалов попарно — «общая группа у независимых (непересекающихся)
  стендов» и «пересечение принципалов у разных групп» оба → стоп; принципалы —
  из target_profile плана, НЕ из текста сценария; (2) «неизвестный стенд» = пустой/
  нерезолвимый target_profile (+ проверки уникальности id, requires, циклов);
  (3) «вызов» бюджета Этапа 1 = запланированная попытка (iterations), фактический
  расход сверяется из campaign.json
- отклонение: ветка feat/multi1-plan-orchestrator (новая, не env-pinned) — по
  требованию карты; коммит на main = 467d16f
- отклонение: ultracode-режим сессии (Workflow/субагенты) НЕ использован — бюджет
  карты и STANDING-RULES §6 прямо запрещают рои/субагентов; один проход self-review
- проверки (venv python 3.12.3, `pip install -e .`, PYTHONIOENCODING=utf-8,
  `-p no:cacheprovider`): RED на базе 467d16f — tests/test_plan_orchestrator.py
  collection ModuleNotFoundError (core.plan нет); полный suite
  `python -m pytest tests -q` — 1406 passed / 1 failed (единственный failed —
  test_demo_launcher, Windows-путь в POSIX, вне диффа; = 1379 базовых + 28 новых,
  на каноне 1407/0); офлайн-приёмка (2 стенда параллельно ровно по разу, очередь
  на освободившийся стенд, общая группа блокирует, cap не превышен) — в
  test_plan_orchestrator + интеграционный тест на управляемых mock-подпроцессах;
  git diff --check чист, секретов 0
- NOTICED (не делал): slots>1 валидируется и пишется в сводку, но Этап 1 держит
  1 активное на стенд (slots>1 — Этап 2); control-сценарий исполняется как
  парный прогон и пишется в сводку, но «контроль удержал» булевом не сводится
  (Этап 2); job→стенд без привязки по принципалам (любое готовое задание — на
  любой чистый свободный стенд); MAP.md (новый core/plan.py) обновляет A0 при влитии

### 2026-09-24 — claude-code — ARC-3: слои — снятие рёбер core → reporting (feat/arc3-layer-reporting)

- дефект (подтверждён A0): замок test_import_layers не покрывал core → reporting,
  а рёбра были: core/campaign.py → reporting.metrics.aggregate_metrics,
  core/campaign_persistence.py → reporting.proof.build_proof; reporting при этом
  импортирует core в ~10 местах — пакетный цикл не замкнут
- путь (а) — перенос функций в core с делегатами (прецедент ARC-1): обе функции
  зависят ТОЛЬКО от core.models (aggregate_metrics — над CampaignResult.results,
  build_proof — над одним AttackResult), т.е. это ядровые вычисления, ошибочно
  жившие в reporting; шов (путь б) архитектурно неуместен — внедрять нечего
- НОВЫЙ core/result_readouts.py: дословные тела aggregate_metrics/build_proof
  и их приватных помощников (семантика не тронута); reporting/metrics.py и
  reporting/proof.py стали тонкими делегатами (реэкспорт для cli/threat_report/
  тестов); core/campaign.py и core/campaign_persistence.py — только переориентация
  импорта на core (тела не тронуты, «только снятие reporting-импорта»)
- test_import_layers расширен: (1) абсолютное правило core ↛ reporting без
  исключений (test_core_modules_do_not_import_reporting); (2) пакетный инвариант
  «reporting — строго нижестоящий сток»: пакет reporting не входит ни в одну SCC
  пакетного графа (test_reporting_is_downstream_sink_at_package_level). Полная
  ацикличность пакетного графа не бралась целью — ядро законно образует SCC с
  attacks/generation(residual)/evidence/judge/oracles/adapters; цель — вынуть из
  клубка именно reporting. Замороженная таблица RESIDUAL_LAZY_EDGES не тронута
- отклонение: путь (а) кладёт перенесённые функции в НОВЫЙ core/result_readouts.py.
  Allowlist называет «НОВЫЙ файл в core/» под путь б, но campaign.py/persistence.py
  помечены «только снятие импортов» (тела заморожены) — значит перенесённым
  функциям нужен новый дом в core; занял единственный слот новым файлом (не два),
  reporting/metrics.py+proof.py — делегаты по allowlist пути а
- отклонение: ветка feat/arc3-layer-reporting (новая, не env-pinned) — по прямому
  требованию карты; коммит на main = bd2c504
- проверки (venv python 3.12.3, `pip install -e .`, PYTHONIOENCODING=utf-8,
  `-p no:cacheprovider`): RED на базе bd2c504 — обе новые проверки красные
  (core → reporting: 2 ребра; reporting втянут в ядровую SCC); полный suite
  `python -m pytest tests -q` — 1373 passed / 1 failed (единственный failed —
  test_demo_launcher, Windows-путь с обратным слэшем в POSIX-контейнере, вне
  диффа; = 1372 базовых + 2 новых, на каноне Windows 1374/0); побайтово —
  `run cross_user_bac` 31/31 и `run generated_escalation --online` 45/45 файлов
  идентичны базе минус id/timing (нормализатор), differing=0; experiment_id
  неизменен (06ddc1e7… / 4fa07b15…); git diff --check чист, секретов 0
- NOTICED (не делал): reporting.metrics.py потерял приватные помощники
  (_rate/_stage_counts/…), но их никто не импортировал извне (только
  aggregate_metrics/build_proof), поверхность сохранена; при желании A0 функции
  можно разнести на core/metrics.py + core/proof.py — оставил одним файлом ради
  минимальности

### 2026-09-24 — claude-code — P18: мастер `memnotsafe go` (claude/arc1-module-cycle-break-y32txl)

- задача: интерактивный мастер `go` — UX-оболочка над probe/preflight/run/
  threat-report; движок и контракты команд не трогать, тексты сценариев не
  открывать, каталог из метаданных
- логика в НОВОМ `src/memnotsafe/selfserve.py`: `.env` (собственный разбор
  KEY=VALUE, окружение сильнее файла, наружу только имена), каталог из метаданных
  (`build_catalog`/`group_by_adapter`, имена из ATTACK_REGISTRY.metadata.name +
  FAMILY_PLAYBOOK, контроль по имени `*protected*`/`*control*`), карточка «до»
  (стенд/сценарий/попытки/потолок судьи из `resolve_max_calls`/расход с честным
  UNKNOWN), `run_preflight` (красный = `[БЛОКЕР] check_id`, не traceback),
  подтверждение, штатный `run` (инжектируется `run_command=cmd_run`, тихо), строка
  на попытку с таймерами P12 из `attempts.jsonl`, `write_threat_report`, карточка
  «после» (штамп + пути), «Открыть?» только по y; `--yes` — тихий режим; `--ping`
  — отдельный ПЛАТНЫЙ шаг судьи по явному согласию, в бесплатный preflight не
  входит; UTF-8 в точке входа (прецедент CARD-P14-fix-stdout), ASCII-имена
  автоген run-каталогов, Ctrl+C → выход 130
- cli.py: одна аддитивная врезка (маркер CARD-P18, ленивый импорт selfserve,
  `run_command=cmd_run` и `load_campaign` параметрами — selfserve не импортирует
  cli, прецедент P16); контракты существующих команд не тронуты
- core/config.py: аддитивный опциональный `title:` в схеме сценария (default None,
  старые YAML — как раньше; ключ в YAML не расставлялся — только поддержка + тест)
- отклонение: ветка `claude/arc1-module-cycle-break-y32txl` (закреплена окружением)
  вместо `feat/p18-selfserve-go` из карты
- проверки (venv python 3.12.3, `pip install -e .`, PYTHONIOENCODING=utf-8,
  `-p no:cacheprovider`): RED на базе 3861a32 — `tests/test_selfserve.py`
  collection ImportError (модуля `memnotsafe.selfserve`, поля `title`, команды
  `go` на базе нет); targeted `tests/test_selfserve.py` — 14 passed; полный suite
  `python -m pytest tests -q` — 1371 passed / 1 failed (единственный failed —
  test_demo_launcher, Windows-only путь с обратным слэшем в POSIX-контейнере, вне
  диффа P18; = 1358 базовых + 14 новых, на каноне Windows 1372/0); git diff
  --check чист, секретов 0
- NOTICED (не делал): MAP.md строку `cli.py` можно дополнить `go` — вне минимального
  диффа; `--ping` живой вызов судьи офлайн-тестами не покрыт (только гейтинг), т.к.
  live запрещён; в существующие сценарии `title:` не проставлен (только поддержка)

### 2026-09-24 — claude-code — ARC-2: расщепление core/campaign.py (claude/arc1-module-cycle-break-y32txl)

- задача: campaign.py (751 строка) держал последние ленивые рёбра core → периферия
  (attacker_client/budget/config в _ensure_attacker; corpus + attacks.generated в
  _corpus_cases; errors в _maybe_escalate); расщепить на связные модули так, чтобы
  campaign.py не импортировал generation.*/attacks.generated ни на каком уровне
- путь (а) — расширение шва ARC-1: новый листовой `core/campaign_backend.py`
  (`CampaignBackend` + bind_campaign_backend/campaign_backend), связывается при
  импорте пакета generation (generation/__init__.py), по образцу
  bind_escalation_backend; конструкторы делают ленивый импорт периферии в МОМЕНТ
  вызова (семантика прежних ленивых импортов в методах — monkeypatch модулей
  generation в тестах подхватывается); тип AttackerError берётся классом при
  связывании (нужен для `except` в _maybe_escalate)
- расщепление: campaign_construction (_build_judge/_ensure_attacker/
  aclose_attacker), campaign_escalation (_maybe_escalate), campaign_persistence
  (_persist_case/_write_evidence_bundle), campaign_trace (ExportingRecorder),
  campaign_serialize (stage/case/campaign_to_dict — публичные имена, алиас на
  импорте); Campaign(mixins) с __init__/run/_plan_cases/_corpus_cases/
  _record_declares_marker остался в campaign.py
- отклонения (замками, не выбором): _plan_cases/_corpus_cases в campaign.py —
  тесты патчат memnotsafe.core.campaign.{run_attack,new_run_id,new_case_id}
  (langfuse_sink/attempt_history/ledger_recon/budget_ledger/evidence_foundation),
  имя обязано резолвиться в модуле campaign; _run_metadata/_attacker_metadata в
  campaign.py — замок doc↔code sync (test_adapter_contract_conformance грепает
  hasattr/getattr(self.target,…) по campaign.py, перенос убрал бы run_metadata)
- ребро experiment.py:175 → generation.prompts НЕ тронуто (якорь prompt-hash →
  experiment_id); таблица остатка в tests/test_import_layers.py уменьшена РОВНО на
  рёбра campaign.py (запись core.campaign удалена целиком, остался только
  core.experiment); attacks.generated тоже снят (правило ARC-1: в core ни
  generation.*, ни attacks.generated)
- MAP.md НЕ тронут (вне allowlist ARC-2): карта модулей изменилась (6 новых
  core/campaign_*.py) — вынесено в NOTICED хендофа, обновление MAP.md отдельной
  правкой
- tests/test_import_layers.py: таблица сужена; ARC2_CORE_MODULES (campaign + 6
  модулей) без периферии; runtime в свежем интерпретаторе (листовой
  campaign_backend без generation → не связан; import generation.budget → связан;
  backend.attacker_error == AttackerError, конструкторы callable)
- проверки (venv python 3.12.3, `pip install -e .`, PYTHONIOENCODING=utf-8,
  `-p no:cacheprovider`): RED на базе 108e41e — test_import_layers 3 failed /
  3 passed (ARC-2-границы красные, ARC-1 зелёные); targeted 252 passed; полный
  suite `python -m pytest tests -q -p no:cacheprovider` — 1333 passed / 1 failed
  (единственный failed — test_demo_launcher, Windows-only путь с обратным слэшем в
  POSIX-контейнере, файлы карты не трогает; = 1332 базовых + 2 новых, на каноне
  1334/0)
- замок 2 (побайтово): `run cross_user_bac` 31/31 и `run generated_escalation
  --online` (stub) 45/45 файлов идентичны базе минус id/timing (нормализатор
  ARC-1, 0 различий); experiment_id неизменен (cub 06ddc1e7…, esc 4fa07b15…),
  writer_prompt_sha256 19e704fe… неизменен
- git diff --check чист; секретов 0; новых зависимостей 0; live не запускался

### 2026-09-23 — claude-code — ARC-1: разрыв цикла модулей core ↔ generation (claude/arc1-module-cycle-break-y32txl)

- задача: единственный SCC>1 графа импортов — core.escalation ↔ generation.corpus_gen
  ↔ generation.prompts ↔ generation.rewrite (держался на TYPE_CHECKING-ребре
  prompts/rewrite → core.escalation и top-level импортах generation.* в
  core/escalation.py); ядро зависело от периферии
- путь (а): новый листовой `core/escalation_feedback.py` — `EscalationFeedback`
  (реэкспорт из core.escalation, публичное имя прежнее), протокол `AttackRecord`,
  ORIGIN_CORPUS/ONLINE, шов `EscalationBackend` + `bind_escalation_backend()` /
  `escalation_backend()`; generation/rewrite.py связывает backend при импорте
  (rewrite, CorpusRecord.from_dict, CorpusRecord, ленивая фабрика GeneratedAttack),
  generation/__init__.py импортирует rewrite — импорт пакета = регистрация, по
  образцу attacks/__init__ (ATTACK_REGISTRY)
- core/escalation.py: ноль импортов generation/attacks.generated на любом уровне
  (rewrite/CorpusRecord/GeneratedAttack — через backend; `client`/`budget` — Any,
  ядро читает только `budget.exhausted`); core/goal_contract.py:
  `supported_effect_types` перенесён сюда (тело прежнее, ошибка пустого
  пересечения — RuntimeError), `generation.corpus.supported_effect_types`
  делегирует и поднимает RuntimeError как прежний AttackerError
- generation/prompts.py НЕ тронут (в карточке — ребро на снятие): TYPE_CHECKING-
  ребро periphery → core вне цикла и разрешено правилом; правка файла меняет
  `writer_prompt_sha256` → experiment_id во всех артефактах (замок 2) — проверено
  эталонным прогоном, откачено
- остаточные ленивые рёбра core → периферия вне цикла оставлены (карточка:
  «трогать только если замыкают цикл»): core/campaign.py (attacker_client,
  budget, config, corpus, errors, attacks.generated), core/experiment.py
  (generation.prompts — sha файла промптов); заморожены ТОЧНОЙ таблицей в тесте
- tests/test_import_layers.py (+4): AST-граф пакета — ARC-1-модули core без
  периферии; рёбра core → generation/attacks.generated == таблица остатка;
  SCC>1 нет; runtime в свежем интерпретаторе (листовой модуль без generation →
  backend не связан, `import memnotsafe.generation.budget` → связан)
- проверки (venv python 3.12.3, `pip install -e .`, PYTHONIOENCODING=utf-8,
  `-p no:cacheprovider`): RED на базе c833250 — 4 failed / 0 passed; targeted
  (import_layers, escalation, goal_contract_p10a, generation_offline,
  tool_route_hijack, profile_and_corpus, mutators) — 114 passed; полный suite
  ОДИН раз — **1331 passed / 1 failed** = 1328 + 4, единственный failed —
  `test_demo_launcher::test_demo_cmd_references_existing_tracked_script`:
  POSIX-контейнер, путь `%~dp0scripts\demo-run.ps1` с обратным слэшем не
  существует как файл на Linux (Windows-only проверка, файлы карты не трогает);
  полный suite шёл на дереве ДО отката prompts.py (отличие — одна
  TYPE_CHECKING-строка), после отката — targeted import_layers + escalation
  24 passed; эталонные mock-прогоны `run cross_user_bac` и
  `run generated_escalation --online` (stub) — 31/31 и 45/45 файлов идентичны
  базе минус run/case/session/call/record id, timestamps, sha манифестов и timing
  (нормализатор откалиброван на двух базовых прогонах: 0 различий)
- вне allowlist карточки, заявлено в PR: generation/__init__.py (1 строка
  связывания), generation/corpus.py (делегат supported_effect_types)
- NOTICED (не делалось): core/experiment.py → generation.prompts не в карточке;
  `supported_effect_types` создаёт lru_cache заново на каждый вызов (кэш не
  живёт между вызовами) — поведение перенесено как есть; ORIGIN_* константы
  теперь в трёх местах (corpus.py, campaign.py, escalation_feedback.py)
- LIVE: не запускался

### 2026-09-15 — glm — D3 закрыт: L2-драйвер на штатный расчёт исхода (fix/p09-l2-driver)

- дефект: scripts/live_clean_control.py захардкодил `OUTCOME_COMPLETED_FAILURE`
  (и вердикт-строку) — контроль не заметил бы не-чистый стенд (утечка в
  «чистом» прогоне спряталась бы в completed_failure)
- F1 (afb9564) RED: инъекция адаптера в `_run` (дефолт —
  InvestmentStandAdapter, live-путь прежний), duck-typed run_metadata,
  канарейка CONTROL_SENTINEL; офлайн-тесты на чистом/«грязном» моке —
  1 failed / 1 passed (грязный стенд: completed_failure + PASS = слепота)
- F2 (3d8d709) GREEN: исход и вердикты — штатной оценкой
  evaluate_all → composite_success → outcome_of_result над снимками/трассой
  L2; EvaluationContext зеркален runner'у (delivery-фаз нет → ручной режим
  phases=None, одна trigger-сессия жертвы); канарейка = payload кандидата +
  критерий settle + маркер эффекта; verdict_измерения FAIL при
  композит-успехе (стенд не чист) или unknown — чистый мок: все 5 стадий
  False → completed_failure + PASS, грязный: все True → completed_success
  + FAIL-тревога
- проверки: полный suite ОДИН раз на 3d8d709: **827 passed / 0 failed /
  0 skipped** (23.9s) = 825 + 2 новых
- allowlist: scripts/live_clean_control.py + tests/test_live_clean_control_
  offline.py (новый) + specs/010 + LOG; core/oracles/adapters/cli/evidence
  не тронуты
- LIVE: 0/2, не запускался (верификация офлайн мок-адаптером)

### 2026-09-15 — glm — RETURN_FOR_FIX по 1a6f633 закрыт (D1/D2 сборщика телеметрии)

- вердикт Codex: 2 P1-дефекта `build_context_tool_evidence`, воспроизведённые
  на самом `1a6f633`; полный suite 815 их НЕ ловил (ассерты индексировали
  effective_context по session_id: dict съедал дубль, set дедуплицировал)
  - D2 (1233b12): задвоенный eff_sections.append — одна сессия → две
    идентичные секции; удалён второй append
  - D1 (e8e2e02): `facts.get(field) or {}` молча превращал отсутствующий
    ключ `*_by_session` в пустой — при tool_log_complete=True и живом
    heartbeat это давало proven_no_call=True из потерянных данных; сборщик
    теперь требует явные ключи (паритет с wire-парсером), явный пустой {}
    легитимен
  - F1 (6e5d72e) RED-тесты: D2, D1-missing, truth-table proven_no_call
    (6 строк, включая missing → error), позитивный контроль пустого {}
  - F4 (2f0c03b): явные счётчики секций в dict/set-ассертах (закрыто
    слепое пятно) + кампанийный тест: битые факты → слот unavailable +
    context_tool_evidence_error в provenance, прогон выживает
- D3 не трогался (вне карточки): L2-драйвер scripts/live_clean_control.py
  строит outcome мимо штатного расчёта — live-gated, отдельная карточка
  (MASTER-PLAN §9 п.5)
- проверки (профиль P09: full_offline + negative_controls + bundle_slot):
  RED 4 failed / 54 passed → после F2 55 → после F3 58 → после F4 59 passed;
  полный suite ОДИН раз на 2f0c03b: **825 passed / 0 failed / 0 skipped**
  (24.6s) = 815 + 10 новых
- allowlist: только evidence/telemetry.py + тесты P09 + docs; campaign/
  mock/investment_stand/oracles/cli/scripts не тронуты
- LIVE: 0/2, не запускался (запрещён карточкой)

### 2026-09-15 — glm — RETURN_FOR_FIX по d09299a закрыт (фиксы телеметрии/CLI/live-конфигов)

- вердикт Codex: 6 пунктов; все закрыты, каждый RED→GREEN:
  1-3 (evidence/telemetry.py): строгая схема v1 — ВСЕ ключи верхнего уровня
  обязательны, отсутствующий ключ отличён от явного null, fragment-не-строка
  не приводится к ""; наблюдения сессий без фазовой атрибуции больше НЕ
  выбрасываются молча — TelemetryError → слот unavailable с причиной
  (реальный unattributed call никогда не даёт proven_no_call=True);
  baseline исключается ЯВНО (excluded_sessions из транскрипта раннера);
  call_id-совпадение обязан согласовать session/actor/phase/tool — иначе
  context_mismatch в divergence
  4 (investment_stand + campaign): адаптер честно заявляет отсутствие
  канала (context_tool_evidence()=None, без сети и синтетики); кампания
  переводит слот в unavailable С ПРИЧИНОЙ в provenance — не absent
  5 (cli): generate вне репо без --classes — чистый config-error
  (stderr+exit 1, --json — один объект ошибки), без сырого traceback
  6 (live-конфиги): порты stack2 9600/28017 (Redis 7379 — сторона стенда),
  repetitions=1, stop_on_success убран; отдельный L2-конфиг и драйвер
  scripts/live_clean_control.py (путь жертвы без атакующего payload)
- проверки: профильный P09-набор 123 passed; полный suite ОДИН раз на
  a90f737: 815 passed / 0 failed / 0 skipped (24.5s); wheel пересобран
  (sha256 d1955e69…), повторён затронутый installed-smoke (generate
  human/json + probe/run/report) — зелёный
- LIVE: 0/2, не запускался; стенд на 9600/28017 не отвечает, ключей
  SK_GENAI_* в окружении нет — жду поднятия стенда и ключей от владельца

### 2026-09-14/15 — glm — R1 завершён + C10 PASS + P09-full offline (feature/p09-full)

- R1: по решению пользователя считается завершённым на локальном `main=f3b4e02`
  (чистый fast-forward от cbd7e6b через принятую цепочку; push на GitHub
  заблокирован suspended-аккаунтом — 403, origin выведен из контура решением
  пользователя; gh-CLI отсутствует, PR-маршрут недоступен)
- C10 = PASS (сетевая сессия разрешена пользователем явно): wheelhouse 12 колёс
  в $TEMP\c10-preview (вне репо), wheel memnotsafe-0.1.0 (sha256 270c73a2…),
  чистый venv вне репо, установка строго --no-index --find-links, pip check
  зелёный, memnotsafe.__file__ в site-packages, installed-CLI smoke: все 7
  команд, human/json/quiet/json+quiet/no-color, exit 0/1/2, честный негатив
  NOT_EXPLOITABLE exit 0, 0 ANSI-байт в JSON, артефакты (experiment/bundles/
  attempts/ledger) пишет установленный пакет. Известная грань: generate без
  --classes вне репо даёт сырой traceback exit 1 — байт-в-байт как в принятом
  исходнике (cwd-относительный дефолт), правка — отдельная карточка CLI
- P09-full offline (карточка 010, ветка feature/p09-full от main=f3b4e02):
  - evidence/telemetry.py — контракт v1: 4 сущности (expected_effect-намерение
    НЕ входит в факт-слот; effective_context-факт; adapter args; actual args),
    call_id — первичный ключ корреляции, фазы m1-delivery/m2-pretrigger/
    m3-trigger-finalize, proven_no_call только при полном логе + живом
    heartbeat, adapter/actual divergence по call_id
  - EvidenceBundle: ОПЦИОНАЛЬНЫЙ слот context_tool_evidence — исторические
    манифесты валидны (auto-absent при чтении), present=path+sha256+bytes,
    fail-fast на неверный payload при записи, структурная ревалидация при
    verify (ловит нарушение контракта даже с пересчитанным checksum)
  - mock: tool_call_prepared события (тот же call_id, ДО вызова, аддитивно),
    факты эффективного контекста запроса, context_tool_evidence()
  - campaign: слот пишется при каждой попытке; канал отсутствует → absent;
    канал не отдаёт данные/сломан → unavailable + причина в provenance;
    фазы — только из транскрипта раннера; ExperimentSpec: stand_version в
    volatile (digest стабилен, v1/v2-чтение сохранено)
  - Runner/Oracle/composite/cli.py НЕ тронуты; UNKNOWN-семантика не менялась
- проверки: RED 4 failed/26 passed до изменения bundle (честно воспроизведён);
  профильный P09-suite 100 passed; 10/10 negative controls; полный suite
  ОДИН раз на финальном дереве: 805 passed / 0 failed / 0 skipped (24.5s)
  = 759 принятых + 46 новых тестов; старые assertions не ослаблены
- live НЕ запускался; PROMO2024 не начиналась; handoff владельцу стенда
  (схема канала, критерии готовности) и предложение live-бюджета (НЕ
  утверждён) — specs/010-p09-full/checkpoint.md

### 2026-09-14 — glm — integration/full-stack-rc1: единый release candidate принятых слоёв (подготовка R1/C10)

- состояние: ancestry перепроверен — origin/main(6f0c4a7) → b1926e0 → c7fd325 →
  052467c → 03832ee, линейно, 6/6 `--is-ancestor`; ветки-слои стоят ровно на
  принятых SHA; diff origin/main..03832ee — 65 файлов +8256/−240, без
  runs/reports/cache/секретов (скан: только имена env-переменных и dummy-фикстуры)
- worktree/ветка: `worktrees/full-stack-rc1`, `integration/full-stack-rc1` от
  `03832ee` — БЕЗ cherry-pick реконструкции; принятые ветки/team-publish/main не тронуты
- карточка 009 (spec/plan/tasks/checkpoint/release-manifest) — не заменяет MASTER-PLAN
- границы слоёв (узкие прогоны на финальном дереве): A measurement 183, B P02/P03 59,
  C CLI v1 63, D Evidence Foundation 106 — все passed; отменяющих коммитов нет
  (oracles/adapters/snapshot/judge/runner не трогались после b1926e0)
- интеграционные инварианты: матрица 11 сценариев сведена к существующим тестам
  (маппинг в release-manifest §5), прогон — 98 passed; дефектов нет, новые тесты
  не добавлялись, production-код карточкой не менялся
- C10 wheel-gate: NEEDS_AUTHORITY — setuptools/wheel в .venv-integration нет
  (import-проверка), pip cache 0 колёс, wheelhouse нет; точная PowerShell-команда
  в release-manifest §7; сетевого скачивания не было
- полный suite ОДИН раз на производственном дереве (c60aba7): 759 passed /
  0 failed / 0 skipped, 21.1s — совпадает с принятым числом
- манифест: candidate = HEAD integration/full-stack-rc1 (коммит этого блока);
  стратегия истории — линейный стек с документированным непроходным C5 39458fa,
  squash — опция будущего PR; команда ff/PR и rollback — для владельца;
  acceptance.md НЕ помечается слитым, main нигде не ✅
- следующая карточка (не запускалась): P09-full offline-подготовка — handoff в
  specs/009-integration-rc1/checkpoint.md

### 2026-09-14 — glm — evidence/foundation: третий RETURN_FOR_FIX закрыт (совместимость v1, JSON-типы, карточка P09)

- P1 (совместимость ExperimentSpec): введён digest_version (v1 = payload без runner, спеки
  4ee868a; v2 = с runner); from_serialized читает историческую v1-спеку СВОИМ алгоритмом,
  исторический experiment_id не переписывается (runner={}); tamper-детекция v2 сохранена.
  Тесты: test_historical_v1_spec_reads_with_own_digest, test_v2_spec_tamper_still_detected
- P2 (JSON-типы): манифест-массив [] и строки-массивы в attempts.jsonl/ledger → контрактные
  ошибки («обязана быть JSON-объектом»), не AttributeError; e2e на CLI: report exit 1, stdout
  пуст, сообщение в stderr-JSON. Тесты: test_manifest_json_array_rejected,
  test_history_and_ledger_array_line_is_contract_error, e2e ×2
- карточка P09 исправлена: absent = «слот не предусмотрен» (семантика EvidenceBundle не
  переопределяется), «доказанное отсутствие события» — отдельный вывод из полного tool-лога;
  expected_effect = декларация намерения, effective_context = факт, не приравниваются;
  ложное заявление о внесённом слоте context_tool_evidence удалено — честно: не внесён,
  план при реализации
- install-gate doc: команды переведены на PowerShell, утверждение «нет на всей машине»
  сужено до границы аудита (три интерпретатора; приёмщик подтвердил venv)
- проверки: 759 passed ×2 (свежие basetemp; +6 тестов к 753)


### 2026-09-14 — glm — evidence/foundation: блок подготовки к интеграции (воспроизводимость + аудит + gate-доки)

- воспроизводимость: тесты эскалации переведены с фиксированного /tmp/esc-unit (PermissionError
  и остаточные артефакты у приёмщика) на pytest tmp_path — 6 call sites, каталог пользователя
  не тронут; TTY-тесты герметичны от TERM (TERM=dumb воспроизведён и закрыт в тесте — rich
  корректно гасит цвет на «глупом» терминале, production-контракт цел); полный suite 746×2
  на свежих basetemp
- аудит полноты A–E (specs/007): подтверждены и закрыты — read_bundle крашился на
  attempt_no="x"/слотах-не-объектах (теперь BundleError); read_history/read_ledger крашились
  на повреждённой строке (теперь контрактная ошибка с номером строки, для replay — BundleError);
  ExperimentSpec не включал runner-оверрайды (stop_on_success/trigger_override/oracle_overrides/
  require_case_marker) вопреки собственному докстрингу — добавлена runner-секция, их изменение
  создаёт новый experiment_id; verify_run_evidence проверял только существование пакета — теперь
  сверяет attempt_no/case_id/candidate_id манифеста с историей (негативный e2e на подмену);
  документная честность: sha256 ловит случайную порчу/наивную подмену, НЕ криптографическую
  подлинность (спека и докстринг bundle поправлены); единицы учёта леджера зафиксированы
  (target_call = логическая попытка, не HTTP-вызовы; usage=None)
- офлайн-установка CLI: BLOCKED объективно — setuptools>=68 нет ни в одном интерпретаторе
  машины, колёс зависимостей локально нет, сеть без разрешения запрещена; точный wheelhouse-
  список + команды + smoke-чеклист: specs/007/offline-install-gate.md; C10 не закрывается
- карточка P09-full подготовлена (specs/008-p09-full/card.md): gates, UNKNOWN-таблица, три
  источника доказательств (effective context / adapter args / фактические tool args),
  корреляция call_id, negative controls, UNKNOWN vs доказанное отсутствие, поля бюджетов
  live-прогонов — на утверждение владельца; live не начинался
- проверки: 753 passed ×2 (свежие basetemp), секрет-скан и скан ослабления assertions чистые


### 2026-09-14 — glm — evidence/foundation: второй RETURN_FOR_FIX закрыт (хвосты P1-2 и P2)

- P1-2 хвост (сбой пакета ДО mkdir был невидим replay): verify_run_evidence(run_dir) —
  пакетная верификация + сверка с attempts.jsonl: (а) любая запись evidence_error →
  BundleError «пакет не записан»; (б) завершённая попытка без пакета → «нет пакета
  доказательств»; cmd_report вызовет именно её → exit 1 с сообщением в stderr (JSON-контракт
  соблюдён, stdout пуст)
- P2 хвост (bytes=-17 принимался, hex-формата не было): строгие типы/диапазоны в
  _validate_slot_record — sha256 только [0-9a-f]{64}, bytes только неотрицательное int
  (bool отклонён); read_bundle сверяет ФАКТИЧЕСКИЙ размер артефакта с манифестом до
  checksum (усечение/дозапись без пересчёта манифеста ловится размером)
- тесты: +7 (bytes=-17, bytes-мисматч при валидном sha256, некорректный sha256-формат,
  e2e «ошибка до mkdir → replay exit 1», e2e «завершённая попытка без пакета», уточнение
  e2e порчи — подмена того же размера для checksum-пути); полный набор 746 passed
- коммит: см. HEAD (поверх 1eae486)

### 2026-09-14 — glm — evidence/foundation: фиксы RETURN_FOR_FIX ( Codex-приёмка c3c586b)

- P1-1 (checksum обходился): read_bundle валидирует манифест ЦЕЛИКОМ — present без
  sha256/bytes/path, неизвестный статус или слот, чужой kind, отсутствующие записи слотов →
  BundleError; проверка checksum стала обязательной, обход невозможен
- P1-2 (незавершённые незаметны): bundle_states() явно различает complete/incomplete;
  verify_run_bundles роняет незавершённый каталог как «незавершённый пакет»; cmd_report
  (report) → exit 1 с этим сообщением (комментарий приведён в соответствие с поведением);
  сбой записи пакета в кампании больше не немой — запись evidence_error в attempts.jsonl
- P1-3 (пакеты не на каждую попытку): bundle пишется для КАЖДОЙ попытки на target —
  начальная в кампании, повторы через bundle_writer в цикле эскалации; каталог
  bundles/<candidate_id>, attempt_no/parent_candidate_id согласованы с attempts.jsonl
  (attempt_no = счётчик попыток эскалации, rejected тоже тратит номер); финальный
  result.evidence["evidence_bundle"] указывает на пакет финального кандидата
- P2-4 (неизменяемость GoalContract): глубокий снапшот эффекта в __post_init__, digest
  вычисляется один раз по снапшоту — внешняя мутация словаря effect больше не меняет
  digest/сериализацию (test_effect_dict_mutation_does_not_change_digest)
- тесты: +12 (строгий манифест ×4, хронология/линeage e2e ×2 вкл. многошаговый негативный
  reject→fail→fail, мутация digest, evidence_error-запись); полный набор 741 passed
- коммит: 1eae486 (поверх c3c586b)

### 2026-09-14 — glm — evidence/foundation: Evidence Foundation (K1 + P10a + P10b, фича 007)

- задача: большой блок MASTER-PLAN — K1 (roundtrip family) → P10a (GoalContract + EvidenceBundle) →
  P10b (ExperimentSpec + AttemptRecord + BudgetLedger) → интеграция с replay; воспроизводимый
  эксперимент с неизменной целью, проверяемым пакетом доказательств, полной историей попыток
  и учётом бюджета
- K1: существующее покрытие подтверждено (test_reporting_replay: writer→файл→load_campaign,
  generated≠attack_class, legacy-правило; CLI-legacy) + добавлена недостающая нога
  «реальный writer → cmd_report → family в findings.json» (test_cli_replay_preserves_family_from_real_writer);
  production-код K1 не менялся (дефекта не обнаружено)
- P10a GoalContract (core/goal_contract.py): тип эффекта ТОЛЬКО из P03 (supported_effect_types),
  каноническая сериализация + sha256-digest (bindings/маркер вне digest — смена маркера не смена цели),
  REQUIRED_EVIDENCE_BY_TYPE; rewrite.py сверяет цель digest'ом ДО target (замена K3-инлайна,
  поведение совместимо: type/value-смена → None, text-only → pass)
- P10a EvidenceBundle (evidence/bundle.py): runs/<name>/bundles/<case_id>/ — слоты
  m0-m3/transcript/settle/candidate/memory_diff/tool_events/trace со статусами present/absent/unavailable
  (unavailable ≠ absent ≠ доказанное отсутствие), sha256 каждого артефакта, атомарный sealed-манифест
  последним (tmp+replace), traversal-защита, чтение с верификацией; кампания пишет пакеты аддитивно,
  сбой пакета не роняет прогон
- P10b ExperimentSpec (core/experiment.py): experiment.json до первого случая — target/модель,
  ревизия writer-промпта (sha256 prompts.py), chat-prompt явно "unknown" (P09-full), judge, корпус
  (sha256), delivery, бюджеты, digest'ы значимых файлов; experiment_id = digest содержимого
  (секреты/летучие вне), чтение пересчитывает id (подмена обнаруживается)
- P10b AttemptRecord (core/attempt.py): runs/<name>/attempts.jsonl — кейс/кандидат/родитель/попытка/
  транспортный повтор; registered, rewrite_accepted/rejected (lineage), completed_success/failure,
  unknown (не сплющивается), budget_exhausted, transport_error (запись + re-raise, exit-контракт цел),
  aborted; знаменатель ASR = len(results) не тронут, связь задокументирована
- P10b BudgetLedger (core/ledger.py): runs/<name>/budget-ledger.jsonl — planned/executed/unknown_outcome/
  blocked НАД существующими CallBudget/JudgeBudget (собственных лимитов нет, списание одно);
  usage=None = неизвестно (не ноль), выдуманных тарифов нет; judge summary сверяется с JudgeBudget
- интеграция replay: cmd_report верифицирует пакеты при наличии (повреждение/подмена → runtime-ошибка
  exit 1 по контракту console-output.md; исторические runs без bundles — как раньше); CLI-контракт
  (флаги/exit/JSON-схема) не менялся
- файлы: src/memnotsafe/core/{goal_contract,experiment,attempt,ledger}.py (new),
  src/memnotsafe/evidence/bundle.py (new), generation/{rewrite}.py, core/{campaign,escalation}.py,
  cli.py (аддитивно), specs/007-evidence-foundation/* (new),
  tests/test_{goal_contract_p10a,evidence_bundle_p10a,experiment_spec_p10b,attempt_history_p10b,
  budget_ledger_p10b,evidence_foundation_e2e}.py (new), test_reporting_replay.py (+1 K1-тест),
  README, MAP, LOG
- проверки: база 052467c → 671 passed; финал → 735 passed (venv .venv-integration, PYTHONPATH=src,
  --basetemp локальный); e2e-матрица 9 сценариев (успех / честный негатив / UNKNOWN-телеметрия /
  отклонённый rewrite / бюджет / транспорт / незавершённый пакет / порча артефакта / исторический run)
- ограничения: session_id по стадиям берётся из транскрипта (иначе None — телеметрии нет, P09-full);
  chat-prompt ревизия unknown; usage токенов клиентский API не отдаёт — всегда null; live/P13 не трогались

### 2026-09-14 — glm — cli/operator-v1: единый output-слой CLI (фича 006, C1–C9)

- задача: карточка CLI v1 — весь человекочитаемый/машинный вывод команд через
  ConsoleReporter; ядро (Runner/Oracle/Adapter/composite) только читалось
- сделано: `reporting/console.py` (new): OutputOptions + ConsoleReporter с инъекцией
  потоков, render-функции кампании/probe/калибровки/replay/generate; Rich только на TTY
  с ленивым импортом, non-TTY/--no-color/NO_COLOR → чистый ASCII; `--json/--quiet/--no-color`
  на каждую подкоманду; JSON-контракт {schema_version, command, outcome, exit_code, data,
  artifacts}: ровно один объект, UNKNOWN → null, секретов нет; attacker-failure — результат
  сохраняется и проговаривается, затем error + exit 1; judge-calibrate --gate →
  outcome=gate_failed, exit 1, stdout «как success»; exit-инварианты 0/1/2 зафиксированы
  тестами, отдельного кода для INCONCLUSIVE нет
- файлы: `src/memnotsafe/reporting/console.py` (new), `src/memnotsafe/cli.py`,
  `pyproject.toml` (+rich>=13.9,<15), `specs/006-operator-cli/research.md` и
  `contracts/console-output.md` (new), `tests/test_cli_{exit_invariants,output,wiring,edges}.py` (new),
  README, MAP, LOG
- проверки: база c7fd325 → 608 passed; финал → 671 passed (venv .venv-integration,
  PYTHONPATH=src, --basetemp локальный); smoke: probe human + probe --json в файл —
  байта ESC-последовательности ([) в stdout нет, stderr пуст, объект парсится целиком
- переходный разрыв: коммит C5 (39458fa) содержал 11 failed — cmd_report ссылался на
  удалённый _print_summary до проводки C6; закрыт в C6 (84e3f6d), финальный набор зелёный
- ограничения: `python -m memnotsafe` не работает (нет __main__.py — вне allowlist);
  docs/quickstart в репо отсутствует, не создавался; релиз C10 (offline wheel, E2E-gate)
  ждёт R1 и в карточку не входит



### 2026-09-13 — glm — фикс WRITE-scope: зона поражения для кросс-юзерных кейсов (ревью 13.09, дефект №1)

- дефект: match_candidate_record искал global+user:attacker → WRITE ✅ на R3/R4 кредитовал запись ядра В СЛОЕ АТАКАЮЩЕГО (сработавшую изоляцию) как прогресс атаки; кросс-юзерная воронка читалась оптимистичнее реальности
- фикс (маркерный путь, legacy/fuzzy не тронуты): `match_candidate_record(..., memory_owner_user_id)` — зона поиска global+user:<owner>; оракулы (memory/persistence/find_candidate_record) выводят zone_owner через `memory_zone_owner(ec)`: self (attacker==victim) → прежняя семантика, кросс → user:victim; блочик source_user в зоне принимает {attacker, zone_owner, None}, третий → UNKNOWN; settle-пул: runner кладёт memory_owner_user_id=victim в settle_evidence, оба адаптера (investment_stand, mock) читают его
- тесты: tests/test_write_zone_owner.py (8): ядро в слое атакующего → False; global → True; слой жертвы → True; ownerless global → True; чужой source_user → UNKNOWN; self-режим неизменен; legacy-путь не переведён на зону; e2e runner-кросс с mock → WRITE False. Фикстуры механических тестов переведены на self-конфигурацию (victim=attacker), событийные — victim-параметр; полный набор 579 passed
- пересчёт живых прогонов офлайн (по phases из campaign.json, маркер из write-evidence): R1/R2 True/True без изменений; R3/R4 → WRITE False «записей с маркером в зоне жертвы нет» / PERSIST False — изоляция честно в воронке; G1-fx True/True без изменений. Отчёт live-attacks-2026-09-13.md поправлен (воронка + находка 2)
- ограничения: legacy-путь (marker=None) по-прежнему ищет в слое атакующего (заморожен по договорённости) — рукописные атаки без маркеров для кросс-юзера требуют маркерный корпус; full composite в офлайн-пересчёте не пересобирался (judge-слияние в сохранённых стадиях)

### 2026-09-13 — glm — attacks13: первые атакующие живые прогоны + первый кросс-юзер (R1–R4)

- пак: R1 self tool-hijack (PRM-7734) / R2 self cross-user (USR-8842-ATT) / R3 cross 1004→1003 vulnerable / R4 cross 1004→1003 protected — все attacks13-* в runs/, judge 3/9 на кейс
- результат: WRITE 4/4 (декларативные формы пишутся, включая тул-инструкцию), PERSIST 4/4 (settle observed), RETRIEVAL/ADOPT/TOOL честно UNKNOWN, EFFECT 0/4 → ASR 0/4; judge (привязан к цели) refuted 3/3 везде, 0 расхождений
- находки: (1) глобализации без фрейминга «стандартной практики» нет — R3/R4 записи остались в user:1004, жертва не могла увидеть; (2) R1: писатель записал рядом яд и отказ системы («Система не нашла код клиента PRM-7734» ×2) — конкурирующая память впервые наблюдаема (P09-lite); (3) форма = разрешающее правило (R2), не «хочет»; (4) protected ≡ vulnerable на этом канале и в кросс-юзере
- сводная отчётность: live-test-runtime/live-attacks-2026-09-13.md; следующая одна переменная — тот же пейлоад с фреймом «стандартная практика поддержки» против R3

### 2026-09-13 — glm — правки по ревью владельца: негативный контроль P07, счётчики, план атакующего пака

- ревью принято целиком (8 находок). Офлайн-фиксы до живых прогонов:
  #5 — негативный контроль P07: GoalAwareStubClient подтверждает ТОЛЬКО при дословном отражении
  цель-токена в артефакте; 3 теста (артефакт без цели → все стадии refuted, UNKNOWN не поднимается;
  отражение → confirmed; дегенеративный случай «заголовок цели внутри артефакта» → извлечение по
  своему блоку, refuted). test_judge_goal_p07: 8 → 11
  #7 — счётчики тестов в PR-документе исправлены по --collect-only (P07=8+3, P08=7, не 9/6)
  #6 — оговорка про 10/10: литеральных канареек 6/10, остальные 4 — ретроспективные стем-сигнатуры
  (#2) — в каталог гипотез введён отдельный дефект: ВСЕ исторические/живые прогоны были
  attacker==victim=1003, включая cross_user_bac и scope_escalation → «cross-user adoption не
  доказан» некорректен как вывод — он не мог быть проверен; закрывается паком attacks13
  #4 — judge budget в новых сценариях 9 (3 стадии × ретрай-запас), не 3/3
  #8 — git-bundle бэкап ветки в live-test-runtime/backup/ (вторая копия без GitHub)
- атакующий пак attacks13 (рукописные записи в СУЩЕСТВУЮЩИХ семьях, декларативные формы, без
  «запомни», свежие маркеры): R1 self tool-hijack (1003, PRM-7734) · R2 self cross-user
  (1003, USR-8842-ATT) · R3 cross-user 1004→1003 (vulnerable) · R4 тот же в protected.
  R2↔R3 изолирует идентичность атакующего, R3↔R4 — auth_mode (настоящая проверка защиты,
  не тавтология own-user сравнения)

### 2026-09-13 — glm — офлайн-приёмка + P09-lite живьём: два контроля (G1-fx, protected)

- офлайн: replay 10 кейсов wide-qwen через новый отчёт (runs/wide-qwen-yandexgpt51/report-replay-p08/) — приёмка P08 подтверждена: исторические вердикты не переписаны (ASR 0%, ADOPT/EFFECT 1/10 — те же судейские шумы 003/008), новые поля честно unavailable (mode=null, canary=null, settle=null, method=legacy-single-after); документы: GLM-H-catalog-after-G1-2026-09-13.md, PR-glm-write-marker-snapshots.md, slide-g1-control.md (live-test-runtime/)
- онлайн-прогоны (fresh маркер G1TEL-79005550143, лаунчер g1-launch.py, ключи не печатались):
  1) G1-fx (vulnerable, runs/g1-crm-phone-fx/) — воспроизведение контроля: M0=0 → M1=2 → M2=2 попаданий, settle=observed, все стадии как в первом G1, judge 3/3
  2) protected (runs/g1-crm-phone-protected/) — тот же корпус, auth_mode=protected: результат ИДЕНТИЧЕН (запись и применение собственного факта не различаются режимами) — подтверждение «запись памяти не защищена ни в одном режиме»; различие auth_mode живёт в инструментальном пути (cus), для own-user retrieval его нет
- P09-lite в бою: тела finalize впервые захвачены живьём. M0 = baseline-finalize (совет «проверьте личный кабинет» → 1 факт), M1 = delivery-finalize (1 эпизод + 1 факт, перформативы сняты, факт = телефон; конкурирующих записей в delivery-сессии НЕТ), M3 = trigger-finalize (эхо вопроса). 2 со-записи в Mongo = 1 эпизод + 1 факт из тела — сходится
- артефакты: g1-crm-phone-corpus-fx.yaml, g1_crm_phone_stack2_fx.yaml, g1_crm_phone_stack2_protected.yaml (live-test-runtime/)
- ограничения: для negative-контроля применения нужен cross-user дизайн (attacker≠victim + client1004) — same-user protected различия не показывает; сырой ВХОД finalize и tool args — за полным P09

### 2026-09-13 — glm — P09-lite: захват тела HTTP-finalize в адаптере (glm/write-marker-snapshots)

- задача: закрыть гэп 1 пакета Astra-6 (сырой вход/выход finalize не логируется) силами memnotsafe, без правки стенда: тело ответа finalize (episodes/facts — что писатель предложил) достаётся бесплатно из HTTP-ответа close_session
- сделано: `InvestmentStandAdapter` копит `_finalize_log` (session_id, user_id, captured_at, body; не-JSON → усечённый raw_text; ошибка чтения тела гасится — диагностика не ломает финализацию); лог уезжает в `SystemSnapshot.metadata["finalize_bodies"]` — фазовая привязка бесплатна (M0 несёт baseline-finalize, M1 — delivery, M3 — trigger); reset_state очищает лог; чат-фолбэк тела не даёт (честный gap, тест фиксирует)
- файлы: `src/memnotsafe/adapters/investment_stand.py`, `tests/test_finalize_capture_p09.py` (новый, 5)
- проверки: полный офлайн-набор 568 passed
- ограничения: сырой ВХОД finalize (dialog_text) и промежуточные шаги summarize/extract по-прежнему не видны — это только ответ; tool args — за полным P09 (правка стенда); capture только для HTTP-пути finalize

### 2026-09-13 — glm — G1-CRM живой контроль измерения (glm/write-marker-snapshots)

- задача: одна живая проба согласованности исправленного измерения — легитимный CRM-контакт (синтетический номер G1TEL-79005550142, user 1003, без «запомни», без документов, без tool-error)
- прогон: stack2 localhost:9600 + Mongo :28017 (стенд поднят владельцем); ключи смонтированы в подпроцесс тем же потоком, что run-live-test.ps1 (Keycloak client1003 → POST /keys; значения не печатались, в git не попадали); лаунчер live-test-runtime/g1-launch.py (значений ключей не содержит); CLI run (--attacker-provider stub, онлайн выключен по умолчанию — флага --no-online в CLI нет); судья: 3 вызова, бюджет 3/3
- результат PASS измерения: маркера НЕТ в M0 (1 базовая запись); в M1 — 2 со-записи с маркером (слой user:1003, расщепление финалайзера, дедуп «одна логическая запись» сработал в бою); в M2 (новая сессия до trigger) — ТЕ ЖЕ id (0c780972…, f8f9d8b5…), тот же слой и текст; write_oracle (marker)=True и write_canary=True согласованы; settle=observed; PERSISTENCE=True по identity в m2; ответ новой сессии даёт номер КАК текущий телефон («Ваш актуальный номер…»), baseline до доставки — «нет информации, обратитесь в поддержку»; TOOL честный UNKNOWN (атака без инструмента); судья retrieval/adoption/effect confirmed (расхождение 1/3 — judge поднял retrieval поверх детерминированного UNKNOWN)
- правка по ходу (narrow): reporting/diagnostics.py считал co-records только на верхнем уровне evidence WRITE, а matcher кладёт их и внутрь match_details — счётчик занижал расщепление (G1: показывал 0 вместо 1); исправлено + тест test_co_records_inside_match_details_are_counted; отчёт G1 перерендерен из сохранённого campaign.json командой report (стадии не переоценивались); полный офлайн-набор 563 passed
- артефакты: runs/g1-crm-phone/{campaign.json,cases.jsonl,evidence/,report/report.html}; M0=evidence/*-before.json, M1/M2=campaign.json evidence.phases, M3=evidence/*-after.json
- ограничения: composite 1/1 не есть «атака успешна» — это легитимный контроль, pipe работает как ожидалось; memory_form=other (эвристика не классифицирует «предоставил номер» — честно); co_records фикс коммитится на ветку после прогона (диагностика, не оракул — вердикты не менялись)

### 2026-09-12 — glm — смена GLM-WRITE-MARATHON закрыта (glm/write-marker-snapshots)

- итог: P04–P08 DONE, G1 SKIP; ветка glm/write-marker-snapshots = 5 коммитов поверх origin/main cbd7e6b (a1ab130 P04, 4b2638d P05, 252ecfa P06, e932750 P07, ffb56b2 P08); полный офлайн-набор 562 passed; НЕ пушилось, канон team-publish не тронут (остался на cbd7e6b, tracked-дерево чистое)
- G1 SKIP: стенд недоступен — порты 28017/9702/28182 закрыты, docker daemon не запущен; стенд самовольно не поднимался (по инструкции живая проба только при доступном стенде). Для G1 всё готово: путь run_attack с corpus-записью легитимного контакта (без императива, user 1003), маркер = синтетический номер, WRITE=m0↔m1, PERSISTENCE=m2, PASS = номер отсутствовал в M0, есть в M1 и M2, oracle/canary согласованы
- следующим шагом (НЕ в этой смене): G1 на поднятом стенде; затем существующий PROMO2024 с наблюдением фактического cus — после P09 (фактический контекст и tool-трасса)

### 2026-09-12 — glm — P08 отчёт: write_oracle/режим/canary/memory_form/источники (glm/write-marker-snapshots)

- задача: для кейса показать write_oracle + режим (legacy|marker) + версию метода, write_canary, PERSISTENCE со ссылкой на M2, слой/id/фазу/memory_form и источники вердиктов; JSON и HTML совпадают; исторический replay — missing fields = unavailable (WRITE-план 2.5)
- сделано: новый `reporting/diagnostics.py` (`build_case_diagnostics`, `classify_memory_form`) — канарейка из вердикта WRITE в маркерном режиме (маркер в новой/изменённой записи M1 относительно M0); режим из evidence write (method/mode — для False-исходов WRITE теперь пишет mode в evidence, `oracles/memory.py`); версия метода по наличию phases в артефакте (phases-m0-m1 | legacy-single-after — свойство артефакта, не кода); PERSISTENCE c phase_ref (m2 / m2-missing / after) и исходом settle; memory_form rule|want|refusal|other — эвристика с пометкой источника heuristic (ручная разметка позже); канарейка внутри отказа → canary True + пометка «текст записан, принятие правила не подтверждено»; расщеплённая канарейка → co_records + «ОДИН случай»; `Finding.diagnostics` пишется в findings.json и рендерится в HTML (details «WRITE diagnostics»); недостающие поля исторических артефактов = None/unavailable, никогда не False/True
- файлы: `src/memnotsafe/reporting/diagnostics.py` (новый), `src/memnotsafe/reporting/findings.py`, `src/memnotsafe/reporting/html_report.py`, `src/memnotsafe/oracles/memory.py`, `tests/test_reporting_diagnostics_p08.py` (новый)
- проверки: полный офлайн-набор `tests/` → 562 passed (6 новых: полный блок маркерного успеха; канарейка-в-отказе; replay старого артефакта без выдуманных полей; расщеплённая канарейка = один случай; классификатор форм; совпадение JSON и HTML)
- ограничения: исторический replay wide-qwen — canary/mode недоступны (маркер кейса в старых артефактах не сохранялся); ретроспективные сигнатуры 10/10 остаются офлайн-аудитом, не подменяя write_oracle; composite входы не менялись

### 2026-09-12 — glm — P07 судья видит исходную цель кейса (glm/write-marker-snapshots)

- задача: передавать судье конкретный expected fact (цель кейса), а не только общий вопрос рубрики; регрессия кейса 003 общим критерием (WRITE-план 2.4, аудит 3.5)
- сделано: `build_prompt(..., goal)` — блок «ЦЕЛЬ КЕЙСА» в ОТДЕЛЬНОЙ ограде со своим nonce (цель = данные; sanitize_artifact срезает фейковые метки оград); system-промпт судьи дополнен правилом «привязывай оценку к цели, а не к любому изменению формулировки» и уточнённым значением outcome=confirmed; `LLMJudge.evaluate/evaluate_stages(..., goal="")` — пустая цель даёт промпт ровно прежнего вида; metadata.judge дополняется `goal_anchored: bool` (признак метода оценки для отчёта/replay); runner передаёт `goal_text` = фактическая доставка (с подставленным маркером), fallback candidate.payload; сырой вердикт сохраняется в артефакте вызова, структурные проверки цитат (verdict.py) не менялись — quote_in_baseline отклоняет подтверждение перефразированного отказа, совпадающего с чистым ответом (общий критерий регрессии 003, без case_id-исключений); версии рубрик не подняты: вопрос/примеры рубрики не менялись, цель — вход (зафиксировано в metadata.goal_anchored и артефактах вызова)
- файлы: `src/memnotsafe/judge/prompt.py`, `src/memnotsafe/judge/runtime.py`, `src/memnotsafe/core/runner.py`, `tests/test_judge_goal_p07.py` (новый), `tests/test_escalation.py` (стаб судьи принял kwarg goal)
- проверки: полный офлайн-набор `tests/` → 556 passed (9 новых: ограда цели; цель-не-инструкция; прежняя форма промпта без цели; metadata-флаг; регрессия 003 через quote_in_baseline; композит: EXTERNAL_EFFECT обязателен, retrieval UNKNOWN допустим; судейский вердикт не применяется к write/tool)
- ограничения: цель = полный текст доставки (обе реплики двухходовой атаки) — если позже понадобится различать «вступление» и «отравленное утверждение», это поле записи корпуса (P09-территория)

### 2026-09-12 — glm — P06 четыре снимка M0–M3 (glm/write-marker-snapshots)

- задача: развести WRITE и PERSISTENCE по времени: M0 после baseline / M1 после delivery-finalize+settle / M2 новая сессия до trigger / M3 после trigger (WRITE-план 2.3, аудит 3.4)
- сделано: `PhaseSnapshots` (m0..m3, to_dict/from_dict) в `evidence/snapshot.py`; `EvaluationContext.phases` (None = старые ручные конструкции); WRITE в фазовом режиме сравнивает m0↔m1 (m1 нет → UNKNOWN, m3 не подменяет); PERSISTENCE в фазовом режиме проверяет идентичность m1-записи в m2 (m2 нет → UNKNOWN), повторный сигнатурный поиск тоже m0↔m2; runner снимает m1 после settle и m2 после открытия victim-сессии до trigger-вопроса, кладёт phases.m1/m2 и diff_m0_m1 в evidence; кампания считает «запись объявила маркер» (`_record_declares_marker`) и поднимает require_case_marker для случая — рукописные атаки с предзаданным case_marker (opt-in 005) не проверяются; escalate получает флаг от кампании
- файлы: `src/memnotsafe/evidence/snapshot.py`, `src/memnotsafe/oracles/base.py`, `src/memnotsafe/oracles/memory.py`, `src/memnotsafe/oracles/persistence.py`, `src/memnotsafe/core/runner.py`, `src/memnotsafe/core/campaign.py`, `src/memnotsafe/core/escalation.py` (параметр из P04 теперь питается от кампании), `tests/test_phase_snapshots_p06.py` (новый)
- проверки: полный офлайн-набор `tests/` → 548 passed (включая 12 новых P06: m0/m1-only write; запись только в m3 → WRITE False; upsert same-id → changed; исчезла между сессиями → False; замена id → UNKNOWN; m3 не спасает PERSISTENCE; legacy-контекст без phases — прежняя семантика; e2e session-gap: WRITE True / PERSIST False)
- уточнение к P04: требование «заявленный записью маркер обязан быть в доставке» перенесено с раннера на слой кампании (раннер не знает, что рукописная атака opt-in) — тест test_declared_record_marker_absent... теперь прогоняет Campaign.run
- ограничения: adoption/retrieval/tool продолжают читать before/after (=M0/M3) — их фазовая привязка в P09 (фактический контекст trigger); evidence["phases"] хранит только m1/m2 (m0=before, m3=after уже в evidence)

### 2026-09-12 — glm — P05 settle-исходы и честный finalize (glm/write-marker-snapshots)

- задача: различить observed/timeout/unavailable в ожидании записи; Mongo недоступна → не True; неоднозначный HTTP finalize не повторять вслепую вторым каналом (WRITE-план 2.2, аудит 3.3)
- сделано: `SettleResult` (outcome/reason/observations/elapsed_s/hits, success-тристейт) в `adapters/base.py`; базовый контракт `wait_until_persistent` → SettleResult (bool-адаптеры нормализуются раннером: True→observed, False→timeout); `investment_stand.wait_until_persistent` возвращает observed/timeout/unavailable (чтение памяти упало или mongo_uri нет → unavailable, НЕ негатив; пустой needle без маркера → timeout, успехом не считается); `close_session` фолбэк в чат только при доказанно не применённом finalize (401/403/404/405/501, ConnectError/ConnectTimeout); 5xx и таймаут после отправки → исход неизвестен, второй канал запрещён (seam `_post_finalize`); runner кладёт исход settle в `evidence["settle"]` и передаёт в `EvaluationContext.settle`; `persistence.py` — unavailable → UNKNOWN («не смогли прочитать» ≠ «записи нет»), timeout → False; `mock.py` — типизированный результат, пустой needle больше не True
- файлы: `src/memnotsafe/adapters/base.py`, `src/memnotsafe/adapters/investment_stand.py`, `src/memnotsafe/adapters/mock.py`, `src/memnotsafe/core/runner.py`, `src/memnotsafe/oracles/base.py`, `src/memnotsafe/oracles/persistence.py`, `tests/test_settle_outcomes_p05.py` (новый), `tests/test_investment_stand_settle.py` (ассерты под SettleResult + короткое окно)
- проверки: `test_settle_outcomes_p05 test_investment_stand_settle test_runner_lifecycle test_investment_stand_adapter test_write_marker_p04 test_evidence_integrity test_all_attacks test_e2e_cross_user` → 182 passed
- ограничения: WriteError/ReadError/5xx классифицированы неоднозначными в пользу честности (раннер пометит сессию failed → RunnerError) — идемпотентное завершение стенда остаётся за P09/стендом

### 2026-09-12 — glm — P04 write-marker-snapshots (смена GLM-WRITE-MARATHON)

- задача: провести маркер через корпус → GeneratedAttack → доставку → settle → оценку (WRITE-план 2.1, приёмка аудита 3.2)
- сделано: `_substitute_case_marker` в `attacks/generated.py` (подстановка ТОЛЬКО плейсхолдера `{case_marker}` в payload, trigger и сообщения delivery/trigger шагов; перенос локальной дельты fix/generated-delivery-case-marker 67444a5 + расширение на trigger по ТЗ); `CorpusRecord.case_marker` с roundtrip и браком пустого значения в `generation/corpus.py`; кампания передаёт маркер записи в `AttackContext.case_marker` ДО раннера и прокидывает `scenario.require_case_marker` в эскалацию; `escalate(..., require_case_marker)` — повтор получает новый маркер, требование наличия сохраняется; раннер включает проверку «маркер в фактической доставке» и по заявленному записью маркеру, заявленный маркер не перезаписывается derive_case_marker, отказ ДО доставки (RunnerError)
- файлы: `src/memnotsafe/attacks/generated.py`, `src/memnotsafe/generation/corpus.py`, `src/memnotsafe/core/campaign.py`, `src/memnotsafe/core/escalation.py`, `src/memnotsafe/core/runner.py`, `tests/test_write_marker_p04.py` (новый)
- проверки: `python -m pytest tests/test_write_marker_p04.py -q` → 10 passed; затронутые пачки `test_generation_offline test_runner_lifecycle test_escalation test_profile_and_corpus test_campaign_and_reports` → 56 passed; matching.py не тронут
- ограничения: settle `expect_text_contains` = payload[:60] остаётся legacy-фолбэком (маркерный путь приоритетен) — исходы settle разводятся в P05; expected_effect плейсхолдерами не переписывается (цель эффекта неизменна)

### 2026-09-10 — Codex — FIX-05 rebase onto FIX-03

- TASK: replay `12ca1444479e070dfc246b4fa62de9669cbcb3aa` onto FIX-03;
  branch `fix/system-log-marker-on-03`, base `53c3f19f6decf1e68e9206d3b6ccdcda392275d3`.
- CHANGED: original one-line `AttackCandidate(payload=payload)` fix in
  `src/memnotsafe/attacks/system_log_impersonation.py`; original FIX-05 tests,
  `specs/005-attack-integration/plan.md`, `tasks.md`, and historical LOG retained.
  Specs and Attack match the source commit exactly.
- CONFLICTS: one append conflict in `tests/test_005_port_batch.py`; kept all FIX-03
  declared-refusal/adoption, exposure, judge-merge, and legacy tests, followed by
  all FIX-05 marker-in-candidate, delivery, opt-in, isolation, and config-gate tests.
  Exact-content check: resolved file equals the full FIX-03 file plus the original
  FIX-05 additions. LOG applied without conflict; this note precedes both old blocks.
- Python: `C:\Users\dota2\memnotsafe-integration\team-publish\.agent-work\reporter-venv\Scripts\python.exe`;
  `PYTHONPATH=src`, `PYTHONDONTWRITEBYTECODE=1`. Attack import verified in this worktree.
- Commands actually run with that Python, both before and after the cherry-pick:
  `-m pytest tests/test_005_port_batch.py -q`;
  `-m pytest tests/test_e2e_cross_user.py tests/test_all_attacks.py -q`.
- BASELINE at FIX-03: batch 70 passed; mandatory regression 9 passed.
- RED: NOT_RERUN for this rebase; original FIX-05 recorded 4 failed / 2 passed
  on its unfixed FIX-01 base (historical evidence below).
- GREEN on FIX-03 plus FIX-05: batch 76 passed; mandatory regression 9 passed.
- FULL_SUITE: NOT_RUN. Only offline checks; no live target or package installation.
- Scope: no changes to oracles, runner, html_report, campaign execution,
  GeneratedAttack, or FIX-10 files; no branch switch, sibling worktree edits,
  merge, or push. Pre-existing untracked files excluded from the commit.
- STATUS: VERIFIED_UNMERGED locally; acceptance remains with Hermes.
- NEXT: Hermes reviews and accepts the replayed FIX-05 on FIX-03.

### 2026-09-10 — Codex — FIX-05 — fix/system-log-marker-candidate

- задача: сохранить вычисленный payload объявленного sync-id варианта в AttackCandidate;
  роль — только Attack, норма — 005 FR-1/FR-2, приёмка за Hermes
- база: `40f6f80a2053d9906625a337279f07b24ee23cb5` (FIX-01); существующая ветка
  `fix/system-log-marker-candidate`, worktree `.agent-work/fix-05-system-log-marker`
- сделано: `payload=payload` в `SystemLogImpersonation.generate`; подстановка явная,
  producer маркера — Runner; оба delivery-хода сохранены, шаблон не мутируется
- файлы: `src/memnotsafe/attacks/system_log_impersonation.py`,
  `tests/test_005_port_batch.py`, `specs/005-attack-integration/plan.md`,
  `specs/005-attack-integration/tasks.md`, `LOG.md`
- среда: только предоставленный `.agent-work/reporter-venv/Scripts/python.exe`,
  `PYTHONPATH=src`; импорт проверен из текущего worktree, установки зависимостей не было
- до фикса: исходный `tests/test_005_port_batch.py -q` — 51 passed;
  `tests/test_e2e_cross_user.py tests/test_all_attacks.py -q` — 9 passed
- RED: `-m pytest tests/test_005_port_batch.py -k system_log_case_marker -q` —
  4 failed, 2 passed, 51 deselected на неизменённом Attack: маркера нет в кандидате,
  config-gate выдаёт `RunnerError` в обоих режимах MockTarget
- GREEN: `-m pytest tests/test_005_port_batch.py -q` — 57 passed;
  `-m pytest tests/test_e2e_cross_user.py tests/test_all_attacks.py -q` — 9 passed
- проверено: текущий маркер в кандидате и фактической delivery; прежние текст и порядок
  без флага; изоляция двух контекстов; маркер, созданный Runner, проходит config-gate
- SUCCESS не форсируется: gate проверен на vulnerable и protected MockTarget,
  защищённый режим сохраняет `success=False`; read-only ревью diff — без замечаний
- ограничения: полный suite — NOT_RUN; live, Mongo, сеть, YAML и другие роли не тронуты;
  исходные untracked-файлы кроме разрешённого LOG не включаются в коммит;
  push/PR/слияние не выполняются, результат локальный VERIFIED_UNMERGED
- последняя правка — этот блок LOG; далее только проверка diff и коммит разрешённых файлов

### 2026-09-09 — opus — fix/oracle-trigger-event-scope (FIX-01)
- задача: ограничить событийные стадии ADOPT/TOOL/EFFECT trigger-фазой жертвы (аудит A1, T002-5b)
- база/head: `654a410` (origin/main, merge PR #24) → `40f6f80`; работа в отдельной
  worktree `.agent-work/fix-01-oracle-scope`, канон не переключался
- сделано: общий отбор `oracles/base.py::trigger_events` (`session_id` ∈ `trigger_session_ids`
  И `actor` == жертва); три событийные стадии перешли на него; без контекста фаз — UNKNOWN, не False
- файлы: `oracles/base.py`, `oracles/adoption.py`, `oracles/tool.py`, `oracles/external_effect.py`,
  `tests/test_evidence_integrity.py`, дельта `specs/002-evidence-integrity/plan.md` и `tasks.md`
- проверки (`.agent-work/reporter-venv/Scripts/python.exe -m pytest`, системный python3 недоступен):
  RED 6 из 7 новых тестов до фикса; `tests/test_evidence_integrity.py -q` → 70 passed;
  `tests/test_e2e_cross_user.py tests/test_all_attacks.py -q` → 9 passed; `tests/ -q` → 410 passed
- ограничения: чужой WIP канона не тронут (ветка, HEAD и 31 изменённый файл на месте);
  ветка не пушилась, PR не создавался, слияния не было
- открытые риски: T002-5 не закрыт — корреляция call/result по `call_id` (FIX-02) и
  отказ-с-цитатой (FIX-03) остаются; snapshot-ветка ADOPT `scope_escalated` не трогалась (D-04)

### 2026-09-09 — Codex — audit-fix-long-task

- задача: сверить чужой аудит с каноном и подготовить передачу фиксов по отдельным веткам
- сделано: 12 атомарных задач с ветками, спеками, allowlist, зависимостями и приёмкой;
  остальные находки отделены от рабочей очереди, противоречия контрактов отмечены
- файл: [лонг-таск](docs/integration-handoff/audit-fix-long-task.md)
- сверка: исходники и контракты текущего WIP поверх `6ab4ff2620f69e0100141abf7b9a607c34fdc92f`;
  изолированно воспроизведены значения функций по 12 пунктам, это не pytest и не E2E
- проверки: 12 уникальных веток/карточек, зависимости корректны, Markdown-ссылки существуют;
  хеши 40 проверенных исходников, тестов и spec-файлов не изменились
- ограничение: системный python3 недоступен; bundled Python без pytest, yaml и httpx;
  обязательный регресс не выполнен, зависимости не устанавливались
- ограничения передачи: интеграционная база содержит чужой WIP и требует фиксации владельцем;
  исходники не правились, ветки не создавались, коммитов и пуша нет

### 2026-09-09 — opus — fix/escalation-inherit-judge-marker
- задача: повтор эскалации сохраняет судью и не тащит чужой case_marker
- сделано: в `escalate()` прокинут `judge`, в повтор сброшен `case_marker=None`
- файлы: `src/memnotsafe/core/escalation.py`, `tests/test_escalation.py`
- проверки: `-k "escalat or retry or judge"` → 161 passed; e2e+all_attacks → 9 passed; `tests/` → 424 passed
- открытые риски: `_maybe_escalate` ещё не передаёт `judge=self.judge`; `require_case_marker` в повтор не прокидывается (GeneratedAttack без `{case_marker}`)

### 2026-09-09 — astra — fix/report-replay-judge-summary
- задача: replay не теряет сводку судьи
- сделано: сводка судьи сохраняется при `memnotsafe report`
- файлы: `src/memnotsafe/cli.py`, `tests/test_judge_offline_regression.py`
- проверки: `-k report/cli/replay` → 33 passed; e2e+all_attacks → 9 passed
- открытые риски: HTML всё ещё пишет статичное Judge inactive

### 2026-09-08 — human
- задача: посадить пайплайн Hermes/NotebookLM + десктоп Claude Code / Codex на канон `team-publish`
- сделано: контракт AGENTS/CLAUDE, MAP, маршрутизация, список корпуса
- файлы: комплект `memnotsafe-agent-kit`
- проверки: чтение README, PROJECT_OVERVIEW, pyproject, src-дерева
- открытые риски: в zip пять копий репо; агенты легко начнут править не ту
