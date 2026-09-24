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


def _ensure_registry() -> dict[str, Any]:
    """Импорт пакета атак регистрирует семейства (base.__init_subclass__)."""
    import memnotsafe.attacks  # noqa: F401 — сайд-эффект регистрации
    from memnotsafe.attacks.base import ATTACK_REGISTRY

    return ATTACK_REGISTRY


def _registry_name(registry: dict[str, Any], family: str) -> str | None:
    cls = registry.get(family)
    return cls.metadata.name if cls is not None else None


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
        ))
    return entries


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
def before_card(scenario: Scenario, *, repetitions: int = 1, online: bool = False) -> dict[str, Any]:
    """Данные карточки «до». Потолок судьи — из resolve_max_calls; фактический
    расход честно UNKNOWN, если есть платный канал (судья/онлайн)."""
    judge_on = scenario.judge.enabled
    ceiling = scenario.judge.resolve_max_calls(repetitions) if judge_on else 0
    paid = judge_on or online
    return {
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


def _build_run_namespace(args: argparse.Namespace, scenario_path: str, out_dir: Path) -> argparse.Namespace:
    """Namespace для штатного `run`: копия флагов мастера + фиксация scenario/
    output. run идёт в тихом режиме (quiet) — результат показывает мастер; движок
    и контракт run не затрагиваются."""
    d = dict(vars(args))
    d.update(scenario=str(scenario_path), output=str(out_dir), iterations=None, quiet=True, json=False)
    d.setdefault("target", None)
    return argparse.Namespace(**d)


def _confirm(console: Console, prompt: str, *, default: bool) -> bool:
    try:
        return bool(Confirm.ask(prompt, default=default, console=console))
    except EOFError:
        return default


def _interactive_pick(catalog: list[CatalogEntry], console: Console) -> str | None:
    """Нумерованный каталог по адаптерам; выбор — по номеру. None = отмена."""
    if not catalog:
        console.print("[red]Не найдено ни одного сценария в scenarios/.[/red]")
        return None
    groups = group_by_adapter(catalog)
    ordered: list[CatalogEntry] = []
    console.print("[bold]Каталог сценариев[/bold] (по стенду):")
    for adapter, entries in groups.items():
        console.print(f"\n[bold]стенд: {adapter}[/bold]")
        for e in entries:
            ordered.append(e)
            tag = " [dim](контроль)[/dim]" if e.is_control else ""
            console.print(f"  {len(ordered):>2}. {e.name}{tag}")
    try:
        choice = IntPrompt.ask("Номер сценария (0 — отмена)", default=0, console=console)
    except EOFError:
        return None
    if not 1 <= choice <= len(ordered):
        return None
    return str(ordered[choice - 1].path)


def _render_before_card(console: Console, scenario: Scenario, scenario_path: str,
                        *, repetitions: int, online: bool) -> None:
    registry = _ensure_registry()
    card = before_card(scenario, repetitions=repetitions, online=online)
    console.rule("[bold]ДО ПРОГОНА[/bold]")
    console.print(f"  стенд:      {card['stand']}")
    console.print(f"  сценарий:   {human_name(scenario, registry)}")
    console.print(f"  попыток:    {card['attempts']}")
    if card["judge_enabled"]:
        console.print(f"  судья:      включён, потолок вызовов ≤ {card['judge_ceiling']}")
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


def _render_after_card(console: Console, rc: int, stamp: str | None,
                       report_html: Path, threat_path: Path | None) -> None:
    console.rule("[bold]ПОСЛЕ ПРОГОНА[/bold]")
    if stamp:
        console.print(f"  вердикт:         {stamp}")
    console.print(f"  код прогона:     {rc}")
    if report_html.exists():
        console.print(f"  report.html:     {report_html}")
    if threat_path is not None:
        console.print(f"  threat-report:   {threat_path}")


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
           load_campaign: CampaignLoader, console: Console | None = None) -> int:
    """Точка входа мастера. Возвращает код штатного `run` (или 1/2/130 на
    контрактных отказах / Ctrl+C). Ничего в движке не меняет."""
    _reconfigure_stdout_utf8()
    console = console or Console(no_color=getattr(args, "no_color", False))
    yes = bool(getattr(args, "yes", False))
    try:
        applied = load_dotenv(Path(".env"), os.environ)
        if applied:
            console.print("[dim].env: подхвачены переменные (имена): " + ", ".join(applied) + "[/dim]")

        scenario_path = getattr(args, "scenario", None)
        if not scenario_path:
            if yes:
                console.print("[red]--yes требует --scenario: в тихом режиме каталог не выбирают.[/red]")
                return 2
            scenario_path = _interactive_pick(build_catalog("scenarios"), console)
            if scenario_path is None:
                console.print("Отменено.")
                return 0

        try:
            scenario = load_scenario(scenario_path)
        except (OSError, ValueError, KeyError, FileNotFoundError) as exc:
            console.print(f"[red]Сценарий не загружается: {exc}[/red]")
            return 1

        online = bool(getattr(args, "online", False))
        _render_before_card(console, scenario, str(scenario_path), repetitions=1, online=online)

        result = run_preflight(scenario_path)
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

        if not yes and not _confirm(console, "Запустить прогон?", default=True):
            console.print("Отменено.")
            return 0

        out_dir = _resolve_run_output(getattr(args, "output", None), scenario.id)
        rc = run_command(_build_run_namespace(args, str(scenario_path), out_dir))

        console.rule("[bold]ПОПЫТКИ[/bold] (таймеры P12 из attempts.jsonl)")
        lines = attempt_lines(out_dir)
        if lines:
            for line in lines:
                console.print(line)
        else:
            console.print("  (записей попыток нет)")

        stamp: str | None = None
        threat_path: Path | None = None
        if (out_dir / "campaign.json").exists():
            try:
                threat_path, report = write_threat_report(out_dir, None, load_campaign=load_campaign)
                stamp = report.stamp + (f" ({report.severity})" if report.severity else "")
            except (OSError, ValueError) as exc:
                console.print(f"[yellow]threat-report не собран: {exc}[/yellow]")

        _render_after_card(console, rc, stamp, out_dir / "report" / "report.html", threat_path)

        if threat_path is not None and not yes and _confirm(console, "Открыть threat-report.html?", default=False):
            _open_path(threat_path)
        return rc
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем (Ctrl+C).[/yellow]")
        return 130
