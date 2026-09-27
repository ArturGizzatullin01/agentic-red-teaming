"""src/memnotsafe/selfserve.py — CARD-P18: мастер `memnotsafe go`.

UX-оболочка НАД существующими командами: `go` ничего не измеряет сам и не
трогает движок. Он собирает каталог из МЕТАДАННЫХ сценариев (тексты сценариев
не открываются и не печатаются — только имя семейства, адаптер, человекочитаемое
имя), показывает карточку «до», гоняет бесплатный `run_preflight`, спрашивает
подтверждение, запускает штатный `run`-путь (через инжектированный `run_command`),
печатает по строке на попытку с таймерами P12 из `attempts.jsonl`, собирает
`threat-report` и показывает карточку «после».

Границы (карта карточки):
- контракты команд и движка не меняются: прогон идёт существующим `run`-путём,
  отчёт — существующим `write_threat_report`, preflight — существующим
  `run_preflight`;
- секретов наружу нет: `.env` подхватывается ТОЛЬКО здесь, печатаются лишь ИМЕНА
  переменных; окружение процесса сильнее файла;
- платные проверки (chat completion судьи) — отдельным шагом `--ping` и только по
  явному согласию; в бесплатный preflight они не входят;
- UTF-8 вывод чинится в точке входа (прецедент CARD-P14-fix-stdout); имена
  автогенерируемых run-каталогов — ASCII; пути с пробелами/кириллицей из `--output`
  работают как есть.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.prompt import Confirm, IntPrompt

from memnotsafe.core.config import Scenario, load_scenario
from memnotsafe.preflight import BLOCKER, run_preflight
from memnotsafe.reporting.threat_report import FAMILY_PLAYBOOK, write_threat_report

# Инъекции из cli.py (аддитивная врезка): запуск штатного `run` и читатель
# runs/<name>/campaign.json. Передаются параметрами — selfserve НЕ импортирует
# cli (прецедент P16: reporting не тянет cli, слои ацикличны).
RunCommand = Callable[[argparse.Namespace], int]
CampaignLoader = Callable[[Path], Any]

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Фазовые таймеры P12 (core/runner.py): секунды, None = фаза не выполнялась.
_TIMING_PHASES = ("t_reset", "t_delivery", "t_settle", "t_trigger", "t_finalize", "t_scoring")

# --- CARD-CLI-MEGA-UX -------------------------------------------------------
# §4: «кнопка до проникновения» — repetitions по UX-умолчанию (сам цикл в
# движке: Campaign.run + stop_on_success; свой цикл не строим).
UNTIL_PROVEN_REPETITIONS = 5

# §2: рекомендуемый судья и его цена (текст пункта мастера). ≈3 судимые стадии
# на попытку — это же число даёт JudgeSpec.resolve_max_calls (3×rep×(1+retries)).
RECOMMENDED_JUDGE_MODEL = "deepseek-v4-flash"
JUDGE_CALLS_PER_ATTEMPT = 3

# §2: адаптеры-НЕ-mock — «живой стенд». Держим согласовано с core.config.build_adapter
# (mock iff adapter=="mock" или --target mock); всё остальное — живая цель.
_LIVE_ADAPTERS = ("investment_stand", "http_endpoint", "openai", "openai_compatible")

# §3: пресеты атакующего (скрин владельца, Yandex folder). Константы модуля:
# model_uri + base_url + api_key_env — прокидываются в СУЩЕСТВУЮЩИЕ флаги
# --attacker-provider/--attacker-model/--attacker-base-url/--attacker-api-key-env
# (cli.py:583-593 не трогаем).
_YANDEX_BASE_URL = "https://llm.api.cloud.yandex.net/v1"
# Подтверждено A0 при приёмке CLI-MEGA-UX (2026-09-26): рабочий folder —
# b1g0nvl5lgk8he84ckp8 (буква l после nvl5). Доказательство — live-ответы судьи
# deepseek-v4-flash с model uri этого folder в батарее BATTERY-2026-09-26
# (direct_poisoning_live_judged: verdicts с rationale, model в evidence).
# Литерал карты §3 с цифрой 1 — опечатка карты; пресет #5 (manual) остаётся обходом.
_YANDEX_FOLDER = "b1g0nvl5lgk8he84ckp8"
_ATTACKER_API_KEY_ENV = "ATTACKER_API_KEY"
# §2/D1: ключ судьи — та же рабочая инфра проекта (доказана live в H09-RATE и
# батарее); имя переменной, не значение. Разъезд с ключом стенда (SK_GENAI_*).
_JUDGE_API_KEY_ENV = "PROVIDER_API_KEY"


def _yandex_model(model: str) -> str:
    return f"gpt://{_YANDEX_FOLDER}/{model}"


@dataclass(frozen=True)
class AttackerPreset:
    key: str
    label: str
    provider: str
    model: str | None
    base_url: str | None
    api_key_env: str | None
    manual: bool = False


# Порядок = порядок скрина владельца (карта §3).
ATTACKER_PRESETS: dict[str, AttackerPreset] = {
    "qwen": AttackerPreset("qwen", "qwen3.6-35b-a3b/latest (текущий канон)", "openai",
                           _yandex_model("qwen3.6-35b-a3b/latest"), _YANDEX_BASE_URL, _ATTACKER_API_KEY_ENV),
    "yandexgpt": AttackerPreset("yandexgpt", "yandexgpt-5.1/latest", "openai",
                                _yandex_model("yandexgpt-5.1/latest"), _YANDEX_BASE_URL, _ATTACKER_API_KEY_ENV),
    "deepseek": AttackerPreset("deepseek", "deepseek-v4-flash/latest", "openai",
                               _yandex_model("deepseek-v4-flash/latest"), _YANDEX_BASE_URL, _ATTACKER_API_KEY_ENV),
    "stub": AttackerPreset("stub", "stub (офлайн/CI)", "stub", None, None, _ATTACKER_API_KEY_ENV),
    "manual": AttackerPreset("manual", "вручную (модель + base_url + имя env-ключа)", "openai",
                             None, None, None, manual=True),
}


def apply_attacker_preset(args: argparse.Namespace, preset_key: str) -> AttackerPreset:
    """Проставляет пресет атакующего в СУЩЕСТВУЮЩИЕ флаги --attacker-* (cli.py не
    трогаем). manual — оставляет флаги оператора как есть. Неизвестный ключ →
    KeyError (вызывающий печатает человеческую причину)."""
    preset = ATTACKER_PRESETS.get(preset_key)
    if preset is None:
        raise KeyError(preset_key)
    if preset.manual:
        return preset
    args.attacker_provider = preset.provider
    if preset.model is not None:
        args.attacker_model = preset.model
    if preset.base_url is not None:
        args.attacker_base_url = preset.base_url
    if preset.api_key_env is not None:
        args.attacker_api_key_env = preset.api_key_env
    return preset


# --- §2: цель прогона (mock=smoke / живой стенд), судья, имена ключей ---------
def is_live_target(scenario: Scenario, target_override: str | None = None) -> bool:
    """Живая цель iff адаптер не mock и --target не 'mock' — ровно критерий
    core.config.build_adapter (mock iff adapter=='mock' или override=='mock')."""
    return not (scenario.target.adapter == "mock" or target_override == "mock")


def _live_url(scenario: Scenario, target_override: str | None = None) -> str:
    if target_override and target_override != "mock":
        return target_override
    return scenario.target.base_url or scenario.target.adapter


def target_goal_line(scenario: Scenario, target_override: str | None = None) -> str:
    """Первая строка карточки «до» (спотыкание №1): чётко ЧТО бьём. Mock —
    помечен словом smoke (решение владельца: mock только для smoke-тестов)."""
    if not is_live_target(scenario, target_override):
        return "MOCK (smoke)"
    return f"ЖИВОЙ СТЕНД {_live_url(scenario, target_override)}"


def effective_judge_enabled(scenario: Scenario, args: argparse.Namespace) -> bool:
    """Итоговое состояние судьи после флагов мастера (тот же приоритет, что у
    cli._apply_judge_overrides): --no-judge гасит; --judge/--judge-model или блок
    сценария включают."""
    if getattr(args, "no_judge", False):
        return False
    return bool(scenario.judge.enabled or getattr(args, "judge", False) or getattr(args, "judge_model", None))


def required_key_names(scenario: Scenario, args: argparse.Namespace) -> list[str]:
    """Имена ENV, нужные для ЖИВОГО прогона (значения не трогаем и не печатаем):
    ключи принципалов стенда (identities → SK_GENAI_*), ключ атакующей LLM при
    --online (ATTACKER_API_KEY), ключ судьи при включённом судье (PROVIDER_API_KEY
    на live)."""
    names: list[str] = [str(v) for v in (scenario.target.extra.get("identities") or {}).values()]
    if getattr(args, "online", False):
        names.append(getattr(args, "attacker_api_key_env", None) or _ATTACKER_API_KEY_ENV)
    if effective_judge_enabled(scenario, args):
        names.append(scenario.judge.api_key_env)
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def missing_key_names(scenario: Scenario, args: argparse.Namespace, environ: dict[str, str]) -> list[str]:
    """Из required_key_names — те ИМЕНА, которых нет в окружении (пусты). Порядок
    сохранён; значения не читаются наружу."""
    return [n for n in required_key_names(scenario, args) if not (environ.get(n) or "").strip()]


# --------------------------------------------------------------------- .env
def load_dotenv(path: str | Path, environ: dict[str, str]) -> list[str]:
    """Собственный разбор KEY=VALUE из `.env` (без новых зависимостей).

    Окружение СИЛЬНЕЕ файла: уже заданная переменная не перекрывается. Возвращает
    имена реально применённых переменных — значения не возвращаются и нигде не
    печатаются. Отсутствие файла — пустой список (не ошибка)."""
    p = Path(path)
    if not p.exists():
        return []
    applied: list[str] = []
    for raw_line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not _ENV_KEY_RE.match(key):
            continue
        if key in environ:  # окружение сильнее файла — не трогаем
            continue
        environ[key] = _strip_quotes(value.strip())
        applied.append(key)
    return applied


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


# ----------------------------------------------------------------- каталог
@dataclass(frozen=True)
class CatalogEntry:
    path: Path
    scenario_id: str
    adapter: str
    family: str
    name: str            # человекочитаемое имя (title | имя семейства | family)
    goal: str | None     # бизнес-цель из FAMILY_PLAYBOOK (пересказ, не payload)
    is_control: bool
    description: str | None = None  # однострочное описание из metadata атаки (§3)


def _ensure_registry() -> dict[str, Any]:
    """Импорт пакета атак регистрирует семейства (base.__init_subclass__)."""
    import memnotsafe.attacks  # noqa: F401 — сайд-эффект регистрации
    from memnotsafe.attacks.base import ATTACK_REGISTRY

    return ATTACK_REGISTRY


def _registry_name(registry: dict[str, Any], family: str) -> str | None:
    cls = registry.get(family)
    return cls.metadata.name if cls is not None else None


def _registry_description(registry: dict[str, Any], family: str) -> str | None:
    """Однострочное описание атаки из metadata (§3): не payload, а human-строка
    контракта AttackMetadata.description."""
    cls = registry.get(family)
    return cls.metadata.description if cls is not None else None


def _is_control(scenario_id: str) -> bool:
    """Контроль (защищённый/контрольный вариант) отличаем по ИМЕНИ сценария —
    метаданные, тело YAML не открываем."""
    low = scenario_id.lower()
    return "protected" in low or "control" in low


def human_name(scenario: Scenario, registry: dict[str, Any]) -> str:
    """Имя для каталога и карточки «до»: title сценария, иначе имя семейства из
    реестра, иначе сам family. Тело сценария при этом не читается."""
    if scenario.title:
        return scenario.title
    return _registry_name(registry, scenario.attack_family) or scenario.attack_family


def build_catalog(scenarios_dir: str | Path) -> list[CatalogEntry]:
    """Каталог из метаданных всех сценариев каталога. Битый сценарий пропускается,
    а не роняет каталог."""
    registry = _ensure_registry()
    entries: list[CatalogEntry] = []
    for path in sorted(Path(scenarios_dir).glob("*.yaml")):
        try:
            sc = load_scenario(path)
        except (OSError, ValueError, KeyError):
            continue
        entries.append(CatalogEntry(
            path=path,
            scenario_id=sc.id,
            adapter=sc.target.adapter,
            family=sc.attack_family,
            name=human_name(sc, registry),
            goal=(FAMILY_PLAYBOOK.get(sc.attack_family) or {}).get("goal"),
            is_control=_is_control(sc.id),
            description=_registry_description(registry, sc.attack_family),
        ))
    return entries


def filter_by_adapter(catalog: list[CatalogEntry], adapter: str | None) -> list[CatalogEntry]:
    """§3: фильтр каталога по целевому адаптеру (mock / investment_stand /
    http_endpoint / …). None — без фильтра."""
    if not adapter:
        return list(catalog)
    return [e for e in catalog if e.adapter == adapter]


def group_by_family(catalog: list[CatalogEntry]) -> dict[str, list[CatalogEntry]]:
    """§3: группировка каталога по family (внутри — контроль парой к своей атаке).
    Ключи отсортированы; порядок внутри — is_control, затем scenario_id."""
    groups: dict[str, list[CatalogEntry]] = {}
    for e in catalog:
        groups.setdefault(e.family, []).append(e)
    for family in groups:
        groups[family].sort(key=lambda e: (e.is_control, e.scenario_id))
    return dict(sorted(groups.items()))


def group_by_adapter(catalog: list[CatalogEntry]) -> dict[str, list[CatalogEntry]]:
    """Группировка по target.adapter; внутри — контроль встаёт парой к своей
    атаке (сортировка по family, затем is_control)."""
    groups: dict[str, list[CatalogEntry]] = {}
    for e in catalog:
        groups.setdefault(e.adapter, []).append(e)
    for adapter in groups:
        groups[adapter].sort(key=lambda e: (e.family, e.is_control, e.scenario_id))
    return dict(sorted(groups.items()))


# ------------------------------------------------------------- карточка «до»
def before_card(scenario: Scenario, *, repetitions: int = 1, online: bool = False,
                target_override: str | None = None, judge_enabled: bool | None = None) -> dict[str, Any]:
    """Данные карточки «до». goal — первая строка (спотыкание №1): mock=smoke или
    живой стенд <url>. judge_enabled=None → берётся из блока сценария; иначе —
    итоговое решение мастера. Потолок судьи — из resolve_max_calls; фактический
    расход честно UNKNOWN, если есть платный канал (судья/онлайн)."""
    judge_on = scenario.judge.enabled if judge_enabled is None else judge_enabled
    ceiling = scenario.judge.resolve_max_calls(repetitions) if judge_on else 0
    paid = judge_on or online
    return {
        "goal": target_goal_line(scenario, target_override),
        "is_live": is_live_target(scenario, target_override),
        "stand": scenario.target.adapter,
        "attempts": repetitions,
        "judge_enabled": judge_on,
        "judge_ceiling": ceiling,
        "online": online,
        # честный UNKNOWN: точную стоимость платных вызовов заранее не знаем
        "spend": "UNKNOWN" if paid else "0 платных вызовов",
    }


# --------------------------------------------------------- строки попыток P12
def _fmt_seconds(v: float | None) -> str:
    return "-" if v is None else f"{v * 1000:.0f}ms"


def attempt_lines(run_dir: str | Path) -> list[str]:
    """По строке на попытку из runs/<name>/attempts.jsonl с таймерами P12
    (секунды → ms; невыполненная фаза = «-»). Толерантно к строкам без timing и
    к отсутствию файла."""
    path = Path(run_dir) / "attempts.jsonl"
    if not path.exists():
        return []
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        timing = rec.get("timing") or {}
        phases = " ".join(_fmt_seconds(timing.get(k)) for k in _TIMING_PHASES)
        total = sum(v for v in (timing.get(k) for k in _TIMING_PHASES) if isinstance(v, (int, float)))
        cand = str(rec.get("candidate_id") or "")
        cand_short = cand[:12]
        lines.append(
            f"  [{rec.get('outcome', '?')}] {rec.get('case_id', '?')}"
            f" #{rec.get('attempt_no', '?')} {cand_short}"
            f"  Σ={total * 1000:.0f}ms  ({phases})"
        )
    return lines


# ------------------------------------------------------------------ вывод
def _resolve_run_output(output: str | None, scenario_id: str) -> Path:
    """Путь run-каталога. `--output` — как задан (пробелы/кириллица работают);
    без него — ASCII-имя runs/go-<slug>-<UTCstamp>."""
    if output:
        return Path(output)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = _ascii_slug(scenario_id) or "run"
    return Path("runs") / f"go-{slug}-{ts}"


def _ascii_slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


def _reconfigure_stdout_utf8() -> None:
    """UTF-8 вывод в точке входа (прецедент CARD-P14-fix-stdout): гвард для
    потоков без reconfigure (подменённый sys.stdout, pythonw)."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _package_provenance() -> tuple[str, Path]:
    """Версия и путь фактически импортированного пакета memnotsafe."""
    import memnotsafe

    try:
        from importlib.metadata import version as _dist_version

        ver = _dist_version("memnotsafe")
    except Exception:  # noqa: BLE001 — метаданные могут отсутствовать (не установлен как dist)
        ver = str(getattr(memnotsafe, "__version__", "unknown"))
    pkg_dir = Path(memnotsafe.__file__).resolve().parent  # .../src/memnotsafe
    return ver, pkg_dir


def _package_is_in_tree(pkg_dir: Path, cwd: Path) -> bool:
    """Импортированный пакет лежит в дереве текущего каталога (его src/ или он
    сам)? Ловушка W10: editable-venv указывает на СТАРЫЙ checkout, и «голый»
    memnotsafe молча исполняет старый код из другого дерева."""
    pkg_dir = pkg_dir.resolve()
    for root in (cwd / "src", cwd):
        try:
            pkg_dir.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def render_provenance(console: Console, *, cwd: Path | None = None) -> bool:
    """Печатает версию/путь пакета memnotsafe при старте go/pilot и предупреждает,
    если пакет импортирован НЕ из текущего дерева (ловушка W10). Возвращает True,
    если пакет из текущего дерева. Ничего не блокирует — только предупреждение."""
    cwd = cwd or Path.cwd()
    ver, pkg_dir = _package_provenance()
    console.print(f"[dim]memnotsafe {ver} — пакет: {pkg_dir}[/dim]")
    if not _package_is_in_tree(pkg_dir, cwd):
        console.print(
            f"[yellow]ВНИМАНИЕ: memnotsafe импортирован НЕ из текущего дерева "
            f"({cwd}). Возможно, editable-venv (pip install -e) указывает на другой "
            f"checkout — «голый» memnotsafe может исполнять СТАРУЮ версию. Проверьте "
            f"`pip show memnotsafe` / PYTHONPATH перед прогоном (W10).[/yellow]"
        )
        return False
    return True


def _build_run_namespace(args: argparse.Namespace, scenario_path: str, out_dir: Path) -> argparse.Namespace:
    """Namespace для штатного `run`: копия флагов мастера + фиксация scenario/
    output. run идёт в тихом режиме (quiet) — результат показывает мастер; движок
    и контракт run не затрагиваются."""
    d = dict(vars(args))
    d.update(scenario=str(scenario_path), output=str(out_dir), iterations=None, quiet=True, json=False)
    d.setdefault("target", None)
    return argparse.Namespace(**d)


def _build_campaign_namespace(args: argparse.Namespace, scenario_path: str, out_dir: Path,
                              repetitions: int) -> argparse.Namespace:
    """§4: Namespace для штатного `campaign` под «до проникновения». Инъектирует
    iterations=repetitions и stop_on_success=True — единственный цикл живёт в
    движке (Campaign.run + stop_on_success), свой цикл не строим. Контракт
    campaign не затрагивается: флаги — через getattr."""
    d = dict(vars(args))
    d.update(scenario=str(scenario_path), output=str(out_dir),
             iterations=repetitions, quiet=True, json=False, stop_on_success=True)
    d.setdefault("target", None)
    return argparse.Namespace(**d)


def _choose_judge(console: Console, args: argparse.Namespace, *, is_live: bool, yes: bool) -> None:
    """Спотыкание №2: судья не должен быть выключен молча. Явный пункт выбора с
    ценником; дефолт-подсказка по типу цели (живой black-box → рекомендуем вкл).
    Явные флаги --judge/--no-judge уважаем и не переспрашиваем. Итог кладём в
    args.judge — дальше его подхватит штатная judge-конфигурация (_apply_judge_overrides)."""
    if getattr(args, "no_judge", False) or getattr(args, "judge", False):
        return  # решено явным флагом
    default_on = is_live  # живой black-box → рекомендуем вкл
    if yes:
        args.judge = default_on
        return
    prompt = (f"Судья: включить? ({RECOMMENDED_JUDGE_MODEL}, ≈{JUDGE_CALLS_PER_ATTEMPT} вызова/попытку; "
              "живой black-box → рекомендуется вкл)")
    args.judge = _confirm(console, prompt, default=default_on)


def _apply_default_judge_preset(scenario: Scenario, args: argparse.Namespace) -> None:
    """D1 (VERDICT-CLI-MEGA-UX): мастер, включив судью, обязан дать РАБОЧИЙ пресет,
    а не дефолты JudgeSpec (base_url OpenRouter, api_key_env OPENROUTER_API_KEY,
    пустая модель) — иначе блокер требует чужой ключ, а с ключом прогон падает на
    validate_judge_spec «нужен judge.model», тогда как карточка «до» обещает
    deepseek-v4-flash. Заполняем рекомендуемую инфру проекта (Yandex, PROVIDER_API_KEY)
    ТОЛЬКО когда у сценария нет своего judge.model и оператор не назвал --judge-model.
    Сценарии со своим блоком judge: не трогаем.

    Пресет кладём в ОБА места: в загруженный сценарий — для карточки «до», блокера
    ИМЁН ключей и ping мастера; и в args — штатная команда перезагружает сценарий
    (load_scenario), пресет доедет через cli._apply_judge_overrides."""
    if getattr(args, "judge_model", None) or scenario.judge.model:
        return  # явный --judge-model или собственный блок judge: — не перебиваем
    model = _yandex_model(f"{RECOMMENDED_JUDGE_MODEL}/latest")
    args.judge_model = model
    args.judge_base_url = _YANDEX_BASE_URL
    args.judge_api_key_env = _JUDGE_API_KEY_ENV
    scenario.judge.enabled = True
    scenario.judge.model = model
    scenario.judge.base_url = _YANDEX_BASE_URL
    scenario.judge.api_key_env = _JUDGE_API_KEY_ENV


def _choose_attacker_preset(console: Console, args: argparse.Namespace, *, online: bool, yes: bool) -> None:
    """§3: атакующий по запросу. --attacker-preset уважаем всегда; интерактивный
    выбор — только при онлайне (атакующая LLM инстанцируется лишь под --online) и
    не в тихом режиме. Неизвестный пресет флага → блокирующая причина."""
    preset_key = getattr(args, "attacker_preset", None)
    if preset_key:
        try:
            preset = apply_attacker_preset(args, preset_key)
        except KeyError:
            console.print(f"[red]неизвестный пресет атакующего: {preset_key!r}. "
                          f"Доступны: {', '.join(ATTACKER_PRESETS)}.[/red]")
            raise
        console.print(f"[dim]атакующий: пресет {preset.key} — {preset.label}[/dim]")
        return
    if not (online and not yes):
        return
    ordered = list(ATTACKER_PRESETS.values())
    console.print("[bold]Атакующий (пресеты)[/bold]:")
    for i, p in enumerate(ordered, 1):
        console.print(f"  {i}. {p.label}")
    try:
        choice = IntPrompt.ask("Номер пресета (0 — оставить как есть)", default=0, console=console)
    except EOFError:
        return
    if 1 <= choice <= len(ordered):
        apply_attacker_preset(args, ordered[choice - 1].key)


def _render_until_proven_budget(console: Console, scenario: Scenario, repetitions: int,
                                *, judge_enabled: bool) -> None:
    """§4: бюджет наперечёт перед стартом (вызовы цели + судьи), затем подтверждение."""
    console.rule("[bold]БЮДЖЕТ «ДО ПРОНИКНОВЕНИЯ»[/bold]")
    console.print(f"  попыток (потолок):       {repetitions} (stop_on_success — стоп на первом доказанном)")
    console.print(f"  вызовов цели (потолок):  ~{repetitions} (одна атака на попытку; стадии внутри неё)")
    if judge_enabled:
        console.print(f"  вызовов судьи (потолок): ≤ {scenario.judge.resolve_max_calls(repetitions)}")
    else:
        console.print("  судья:                   выключен (0 платных вызовов судьи)")


def _render_until_proven_summary(console: Console, out_dir: Path, load_campaign: CampaignLoader,
                                 repetitions: int) -> None:
    """§4: честный итог по попыткам — «stop: SUCCESS на K из N» или все мимо →
    NOT_PROVEN. UNKNOWN ≠ провал ≠ успех."""
    if not (out_dir / "campaign.json").exists():
        return
    try:
        camp = load_campaign(out_dir)
    except (OSError, ValueError, KeyError):
        return
    attempts = getattr(camp, "attempts", 0)
    proven = sum(1 for r in getattr(camp, "results", []) if getattr(r, "success", False))
    if proven:
        console.print(f"[green]stop: SUCCESS на {attempts} из {repetitions} — доказано "
                      "(ранний выход по stop_on_success).[/green]")
    else:
        console.print(f"[yellow]все {attempts} попыток мимо → NOT_PROVEN (не «готово»). "
                      "UNKNOWN ≠ провал ≠ успех.[/yellow]")


def _confirm(console: Console, prompt: str, *, default: bool) -> bool:
    try:
        return bool(Confirm.ask(prompt, default=default, console=console))
    except EOFError:
        return default


def _interactive_pick(catalog: list[CatalogEntry], console: Console,
                      *, adapter_filter: str | None = None) -> str | None:
    """§3: нумерованный каталог по family с однострочным описанием из metadata;
    опциональный фильтр по целевому адаптеру. Выбор по номеру; None = отмена."""
    catalog = filter_by_adapter(catalog, adapter_filter)
    if not catalog:
        where = f" (адаптер {adapter_filter})" if adapter_filter else ""
        console.print(f"[red]Не найдено ни одного сценария в scenarios/{where}.[/red]")
        return None
    groups = group_by_family(catalog)
    ordered: list[CatalogEntry] = []
    title = "[bold]Каталог сценариев[/bold] (по семейству атак)"
    if adapter_filter:
        title += f" [dim]— адаптер {adapter_filter}[/dim]"
    console.print(title + ":")
    for family, entries in groups.items():
        head = f"\n[bold]{family}[/bold]"
        if entries[0].description:
            head += f" [dim]— {entries[0].description}[/dim]"
        console.print(head)
        for e in entries:
            ordered.append(e)
            tag = " [dim](контроль)[/dim]" if e.is_control else ""
            stand = "" if e.adapter == "mock" else f" [dim]({e.adapter})[/dim]"
            console.print(f"  {len(ordered):>2}. {e.name}{tag}{stand}")
    try:
        choice = IntPrompt.ask("Номер сценария (0 — отмена)", default=0, console=console)
    except EOFError:
        return None
    if not 1 <= choice <= len(ordered):
        return None
    return str(ordered[choice - 1].path)


def _render_before_card(console: Console, scenario: Scenario, scenario_path: str,
                        *, repetitions: int, online: bool,
                        target_override: str | None = None, judge_enabled: bool | None = None) -> None:
    registry = _ensure_registry()
    card = before_card(scenario, repetitions=repetitions, online=online,
                       target_override=target_override, judge_enabled=judge_enabled)
    console.rule("[bold]ДО ПРОГОНА[/bold]")
    # Спотыкание №1: ЦЕЛЬ — первой строкой, крупно. Живой стенд — красным.
    if card["is_live"]:
        console.print(f"  [bold red]ЦЕЛЬ: {card['goal']}[/bold red]")
        console.print("  [dim](живой стенд — не smoke; подтверждение живого запрашивается ниже)[/dim]")
    else:
        console.print(f"  [bold]ЦЕЛЬ: {card['goal']}[/bold]")
    console.print(f"  сценарий:   {human_name(scenario, registry)}")
    console.print(f"  попыток:    {card['attempts']}")
    # CARD-LIVE-COVERAGE Задача 2 («никогда больше»): по живому стенду без --online
    # атакующий статический (stub) — это ПРЕДУПРЕЖДЕНИЕ, а не тихий дефолт. На mock
    # (smoke) статика штатна. Живой атакующий: --online + --attacker-preset.
    if card["is_live"] and not online:
        console.print("  [bold red][ПРЕДУПРЕЖДЕНИЕ] АТАКУЮЩИЙ: СТАТИКА (не LLM)[/bold red] — "
                      "живой стенд без --online: payload статический, не живая LLM-атакующая. "
                      "Живой атакующий: --online + --attacker-preset.")
    elif online:
        console.print("  атакующий:  LLM (--online)")
    else:
        console.print("  атакующий:  статика (smoke)")
    if card["judge_enabled"]:
        model = scenario.judge.model or RECOMMENDED_JUDGE_MODEL
        console.print(f"  судья:      включён ({model}), потолок вызовов ≤ {card['judge_ceiling']}")
    else:
        console.print("  судья:      выключен")
    console.print(f"  платно:     {card['spend']}")


def _render_preflight(console: Console, result: Any) -> None:
    console.rule("[bold]PREFLIGHT[/bold] (бесплатно, только чтение)")
    console.print(f"  блокеров {result.blockers}, предупреждений {result.warnings}")


def _ping_step(console: Console, scenario: Scenario, *, yes: bool) -> None:
    """Платная проверка связи (chat completion судьи) — отдельным шагом и по
    явному согласию. В бесплатный preflight не входит; секреты не печатаются."""
    console.rule("[bold]--ping[/bold] (ПЛАТНАЯ проверка связи)")
    spec = scenario.judge
    if not spec.enabled or not spec.model:
        console.print("[yellow][SKIP] судья не сконфигурирован (judge.enabled/model) — платный ping не выполняется.[/yellow]")
        return
    if not os.environ.get(spec.api_key_env, "").strip():
        console.print(f"[yellow][SKIP] переменная {spec.api_key_env} не задана — платный ping не выполняется.[/yellow]")
        return
    if not yes and not _confirm(console, f"Выполнить ПЛАТНЫЙ ping модели {spec.model}?", default=False):
        console.print("Ping пропущен.")
        return
    res = asyncio.run(_judge_ping(spec))
    if res.ok:
        console.print(f"[green][OK] ответ судьи получен ({res.latency_ms} ms).[/green]")
    else:
        console.print(f"[red][FAIL] ping не удался: error={res.error} status={res.status} ({res.latency_ms} ms).[/red]")


async def _judge_ping(spec: Any) -> Any:
    from memnotsafe.judge.client import JudgeClient

    client = JudgeClient(
        model=spec.model or "", base_url=spec.base_url, api_key_env=spec.api_key_env,
        timeout_s=spec.timeout_s, temperature=spec.temperature,
    )
    try:
        return await client.complete("ping", "reply with a minimal JSON verdict")
    finally:
        await client.aclose()


def console_open_hint(run_dir: Path | str) -> list[str]:
    """§5 (спотыкание №3): точный путь открытия прогона в консоли Mission Control.
    Консоль из CLI НЕ стартуем (отдельный процесс, решение владельца; NOTICED)."""
    return [
        "  открыть в консоли:  cd console && npm run dev",
        "                      (PowerShell 5.1: cd console; npm run dev — && не работает)",
        f"  затем загрузите прогон:  {run_dir}",
    ]


def _render_after_card(console: Console, rc: int, stamp: str | None,
                       report_html: Path, threat_path: Path | None,
                       *, run_dir: Path | None = None) -> None:
    console.rule("[bold]ПОСЛЕ ПРОГОНА[/bold]")
    if stamp:
        console.print(f"  вердикт:         {stamp}")
    console.print(f"  код прогона:     {rc}")
    if report_html.exists():
        console.print(f"  report.html:     {report_html}")
    if threat_path is not None:
        console.print(f"  threat-report:   {threat_path}")
    if run_dir is not None:
        for line in console_open_hint(run_dir):
            console.print(line)


def _open_path(path: Path) -> None:
    """Открыть отчёт в системном просмотрщике. Сбой открытия не роняет мастер."""
    import subprocess

    try:
        if sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except (OSError, subprocess.SubprocessError):
        pass


# --------------------------------------------------------------- оркестрация
def run_go(args: argparse.Namespace, *, run_command: RunCommand,
           load_campaign: CampaignLoader, campaign_command: RunCommand | None = None,
           console: Console | None = None) -> int:
    """Точка входа мастера. Возвращает код штатного `run`/`campaign` (или 1/2/130
    на контрактных отказах / Ctrl+C). Ничего в движке не меняет: `--until-proven`
    зовёт штатный `campaign` со stop_on_success (единственный цикл — в движке)."""
    _reconfigure_stdout_utf8()
    console = console or Console(no_color=getattr(args, "no_color", False))
    render_provenance(console)  # W10: версия/путь пакета + предупреждение о чужом дереве
    yes = bool(getattr(args, "yes", False))
    online = bool(getattr(args, "online", False))
    until_proven = bool(getattr(args, "until_proven", False))
    target_override = getattr(args, "target", None)
    try:
        applied = load_dotenv(Path(".env"), os.environ)
        if applied:
            console.print("[dim].env: подхвачены переменные (имена): " + ", ".join(applied) + "[/dim]")

        scenario_path = getattr(args, "scenario", None)
        if not scenario_path:
            if yes:
                console.print("[red]--yes требует --scenario: в тихом режиме каталог не выбирают.[/red]")
                return 2
            scenario_path = _interactive_pick(
                build_catalog("scenarios"), console, adapter_filter=getattr(args, "adapter", None))
            if scenario_path is None:
                console.print("Отменено.")
                return 0

        try:
            scenario = load_scenario(scenario_path)
        except (OSError, ValueError, KeyError, FileNotFoundError) as exc:
            console.print(f"[red]Сценарий не загружается: {exc}[/red]")
            return 1

        is_live = is_live_target(scenario, target_override)

        # §3: атакующий по запросу (пресеты → существующие флаги). Неизвестный
        # пресет флага — управляемый отказ, а не трейсбек.
        try:
            _choose_attacker_preset(console, args, online=online, yes=yes)
        except KeyError:
            return 2

        # §2: явный выбор судьи (спотыкание №2) — до карточки «до», чтобы её строка
        # судьи показывала фактическое решение, а не молчаливый дефолт сценария.
        _choose_judge(console, args, is_live=is_live, yes=yes)
        judge_enabled = effective_judge_enabled(scenario, args)
        # D1: если мастер включил судью, а у сценария нет своего блока judge: —
        # ставим рабочий пресет (Yandex/PROVIDER_API_KEY) ДО карточки «до» и блокера
        # ИМЁН ключей, чтобы обещанное показалось и потребовался нужный ключ, а не
        # чужой OPENROUTER_API_KEY. Сценарии со своим judge: — не трогаем.
        if judge_enabled:
            _apply_default_judge_preset(scenario, args)

        repetitions = UNTIL_PROVEN_REPETITIONS if until_proven else 1
        _render_before_card(console, scenario, str(scenario_path), repetitions=repetitions,
                            online=online, target_override=target_override, judge_enabled=judge_enabled)

        # §2: перед ЖИВЫМ таргетом — блокер отсутствующих ИМЁН ключей (не трейсбек).
        if is_live:
            missing = missing_key_names(scenario, args, os.environ)
            if missing:
                console.print("[red][БЛОКЕР] не заданы переменные окружения (только ИМЕНА): "
                              + ", ".join(missing)
                              + " — задайте их (.env или окружение) перед живым прогоном.[/red]")
                return 1

        # §2: подтверждение живого стенда — НЕПРОПУСКАЕМОЕ. --yes его не гасит:
        # тихий прогон по живому требует явного --live-ack. Mock (smoke) не требует.
        if is_live and not _confirm_live(console, scenario, target_override, yes=yes,
                                         live_ack=bool(getattr(args, "live_ack", False))):
            return 2 if yes else 0

        # EXT-B (задача 3): preflight бьёт по ЭФФЕКТИВНОЙ цели (--target уважается),
        # чтобы проверялась та же цель, что и в прогоне. Отказ резолва (URL поверх
        # mock — замок «никогда тихий mock») — человеческая ошибка, не трейсбек.
        try:
            result = run_preflight(scenario_path, target_override=target_override)
        except ValueError as exc:
            console.print(f"[red][БЛОКЕР] {exc}[/red]")
            return 1
        _render_preflight(console, result)
        blockers = [c for c in result.checks if c.status == BLOCKER]
        if blockers:
            # красный preflight = [БЛОКЕР] + check_id, не traceback
            for c in blockers:
                console.print(f"[red][БЛОКЕР] {c.check_id}: {c.text}[/red]")
            console.print("[red]Прогон остановлен: устраните блокеры preflight.[/red]")
            return 1

        if getattr(args, "ping", False):
            _ping_step(console, scenario, yes=yes)

        if until_proven:
            _render_until_proven_budget(console, scenario, repetitions, judge_enabled=judge_enabled)

        if not yes and not _confirm(console, "Запустить прогон?", default=True):
            console.print("Отменено.")
            return 0

        out_dir = _resolve_run_output(getattr(args, "output", None), scenario.id)
        # §4: «до проникновения» — штатный campaign со stop_on_success; иначе один run.
        if until_proven and campaign_command is not None:
            rc = campaign_command(_build_campaign_namespace(args, str(scenario_path), out_dir, repetitions))
        else:
            rc = run_command(_build_run_namespace(args, str(scenario_path), out_dir))

        console.rule("[bold]ПОПЫТКИ[/bold] (таймеры P12 из attempts.jsonl)")
        lines = attempt_lines(out_dir)
        if lines:
            for line in lines:
                console.print(line)
        else:
            console.print("  (записей попыток нет)")
        if until_proven:
            _render_until_proven_summary(console, out_dir, load_campaign, repetitions)

        stamp: str | None = None
        threat_path: Path | None = None
        if (out_dir / "campaign.json").exists():
            try:
                threat_path, report = write_threat_report(out_dir, None, load_campaign=load_campaign)
                stamp = report.stamp + (f" ({report.severity})" if report.severity else "")
            except (OSError, ValueError) as exc:
                console.print(f"[yellow]threat-report не собран: {exc}[/yellow]")

        _render_after_card(console, rc, stamp, out_dir / "report" / "report.html", threat_path, run_dir=out_dir)

        if threat_path is not None and not yes and _confirm(console, "Открыть threat-report.html?", default=False):
            _open_path(threat_path)
        return rc
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем (Ctrl+C).[/yellow]")
        return 130


def _confirm_live(console: Console, scenario: Scenario, target_override: str | None,
                  *, yes: bool, live_ack: bool) -> bool:
    """Непропускаемое подтверждение живого стенда (спотыкание №1, обратная
    сторона). В тихом режиме (--yes) требуется явный --live-ack; иначе —
    интерактивный вопрос с дефолтом «нет». Возврат True = бить живой можно."""
    goal = target_goal_line(scenario, target_override)
    if yes:
        if live_ack:
            return True
        console.print("[red][БЛОКЕР] тихий режим (--yes) по ЖИВОМУ стенду требует явного --live-ack "
                      f"(подтверждение «да, это живой»: {goal}). Mock (smoke) такого не требует.[/red]")
        return False
    if live_ack:
        return True
    if _confirm(console, f"Это ЖИВОЙ стенд ({goal}) — бьём по-настоящему. Подтвердите: да?", default=False):
        return True
    console.print("Отменено (живой стенд не подтверждён).")
    return False
