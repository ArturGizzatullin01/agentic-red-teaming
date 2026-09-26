"""src/memnotsafe/pilot_pack.py — CARD-P17: пилот одной командой (продуктовая
упаковка поверх существующих механик; атак не сочиняем).

`memnotsafe pilot` связывает уже существующие кирпичи в один поток для внешнего
потребителя tier-1 (ручка base_url + ключ из env):

  --init                     → шаблон pilot.yaml + подсказка следующего шага
  --config pilot.yaml
      --output runs/pilot-<ts>  → T1-адаптер (adapters/http_endpoint) → probe →
      preflight (preflight.run_preflight) → стартовый пак проверок (Campaign по
      существующим сценариям реестра) → threat-report.html (рендерер P16
      reporting.threat_report.write_threat_report) → консольная сводка
      (штамп, N of M, путь)
      [--baseline runs/<prev>]  → retest-секция: по кейсу было/стало
                                  (FIXED / STILL VULNERABLE / NEW / UNKNOWN);
                                  UNKNOWN ≠ FIXED

Границы: логика переиспользуется ВЫЗОВОМ (selfserve.load_dotenv/attempt_lines,
reporting.threat_report, preflight.run_preflight, core.Campaign), не копируется;
контракты CLI/T1/runner не меняются; новых атак не выдумываем — стартовый пак
собран данными из существующих сценариев реестра. Секретов ноль: ключ ТОЛЬКО из
env (api_key_env), наружу — лишь ИМЯ переменной.
"""

from __future__ import annotations

import asyncio
import importlib.resources as resources
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml
from rich.console import Console

from memnotsafe.core.campaign import Campaign
from memnotsafe.core.campaign_serialize import campaign_to_dict
from memnotsafe.core.config import build_adapter, load_scenario
from memnotsafe.core.models import CampaignResult
from memnotsafe.core.result_readouts import aggregate_metrics
from memnotsafe.preflight import BLOCKER, run_preflight
from memnotsafe.reporting.threat_report import write_threat_report
from memnotsafe.selfserve import attempt_lines, console_open_hint, load_dotenv, render_provenance

DEFAULT_API_KEY_ENV = "MEMNOTSAFE_TARGET_API_KEY"
CampaignLoader = Callable[[Path], Any]

# P19 (часть 2): стартовый набор сценариев пилота упакован в wheel как package
# data пакета memnotsafe.pilot_scenarios. Резолвинг (_resolve_pack_path):
# сначала package resource (importlib.resources — работает из голого pip install),
# затем fallback на репозиторный scenarios/ (поведение разработчика в дереве).
_PILOT_SCENARIOS_PKG = "memnotsafe.pilot_scenarios"
# Корень репозитория — только dev-fallback для резолвинга сценариев пака.
_REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------- стартовый пак
@dataclass(frozen=True)
class PackEntry:
    entry_id: str
    scenario: str            # путь относительно корня репозитория
    name: str                # человекочитаемое имя (для сводки)
    control: str | None = None  # контрольный сценарий (пара к атаке) или None


# Данными в модуле: только существующие сценарии/семейства реестра — новых атак
# не выдумываем (карта). Cross-user BAC (operand-маркер), direct poisoning,
# retrieval-ACL кейс + контрольная пара.
STARTER_PACK: tuple[PackEntry, ...] = (
    PackEntry("cross-user-bac-operand", "scenarios/cross_user_bac_c_mk_operand.yaml",
              "Cross-user BAC (operand marker)"),
    PackEntry("direct-poisoning", "scenarios/direct_poisoning.yaml",
              "Direct memory poisoning"),
    PackEntry("retrieval-acl", "scenarios/cross_user_bac.yaml",
              "Retrieval ACL (cross-user BAC)", control="scenarios/cross_user_bac_protected.yaml"),
)


# ---------------------------------------------------------------- конфиг
class PilotConfigError(ValueError):
    """Человекочитаемая ошибка конфигурации пилота — стоп с инструкцией, не traceback."""


@dataclass(frozen=True)
class PilotConfig:
    version: int
    adapter: str
    base_url: str
    model: str
    api_key_env: str
    budget_cap: int
    iterations: int


def load_pilot_config(path: str | Path) -> PilotConfig:
    p = Path(path)
    if not p.exists():
        raise PilotConfigError(f"конфиг пилота не найден: {p} — создайте его командой `memnotsafe pilot --init`")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PilotConfigError(f"конфиг {p} должен быть отображением (mapping)")
    target = raw.get("target") if isinstance(raw.get("target"), dict) else {}
    base_url = str(target.get("base_url") or "").strip()
    if not base_url:
        raise PilotConfigError("target.base_url пуст — укажите URL вашей ручки (например https://host/v1)")
    adapter = str(target.get("adapter") or "http_endpoint")
    if adapter != "http_endpoint":
        raise PilotConfigError(f"target.adapter={adapter!r} не поддержан пилотом — Этап 1 работает с http_endpoint (tier-1)")
    budget_cap = raw.get("budget_cap")
    if not isinstance(budget_cap, int) or budget_cap < 1:
        raise PilotConfigError("budget_cap обязателен и должен быть целым >= 1 (потолок прогонов пилота против ручки)")
    iterations = raw.get("iterations", 1)
    if not isinstance(iterations, int) or iterations < 1:
        raise PilotConfigError("iterations должен быть целым >= 1")
    return PilotConfig(
        version=int(raw.get("version") or 1), adapter=adapter, base_url=base_url,
        model=str(target.get("model") or "target-agent"),
        api_key_env=str(target.get("api_key_env") or DEFAULT_API_KEY_ENV),
        budget_cap=budget_cap, iterations=iterations,
    )


TEMPLATE = """# memnotsafe pilot — конфиг пилотной проверки вашей LLM-ручки (tier-1).
# Шаги:
#   1) положите ключ ручки в переменную окружения (значение в файл НЕ писать):
#        export {key_env}=<ваш-ключ>
#   2) впишите base_url и model ниже;
#   3) запустите пилот:
#        memnotsafe pilot --config pilot.yaml --output runs/pilot-run
#   4) откройте runs/pilot-run/threat-report.html
version: 1
target:
  adapter: http_endpoint
  # КОРЕНЬ ручки БЕЗ /v1 — пилот сам шлёт на <base_url>/v1/chat/completions.
  base_url: "https://your-endpoint.example"
  model: "your-model-name"
  api_key_env: {key_env}                          # ТОЛЬКО имя переменной, не значение
budget_cap: 20      # потолок прогонов пилота против ручки (обязателен)
iterations: 1
"""


def init_template(path: str | Path) -> tuple[Path, str]:
    """Пишет валидный шаблон pilot.yaml и возвращает (путь, подсказку шага).
    Существующий файл не перетирает (чтобы не потерять конфиг оператора)."""
    p = Path(path)
    if p.exists():
        raise PilotConfigError(f"{p} уже существует — удалите или укажите другой путь, чтобы не потерять текущий конфиг")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(TEMPLATE.format(key_env=DEFAULT_API_KEY_ENV), encoding="utf-8")
    hint = (
        f"Шаблон записан: {p}\n"
        f"Дальше: 1) export {DEFAULT_API_KEY_ENV}=<ключ>; "
        f"2) впишите base_url/model; 3) memnotsafe pilot --config {p} --output runs/pilot-run"
    )
    return p, hint


# ---------------------------------------------------------------- retest
def classify_retest(baseline: bool | None, new: bool | None) -> str:
    """Статус ретеста по кейсу. ЗАМОК: новый UNKNOWN (None) НИКОГДА не FIXED —
    без наблюдаемости «исправлено» не доказать."""
    if new is None:
        return "UNKNOWN"
    if new is True:
        return "STILL VULNERABLE" if baseline is True else "NEW"
    # new is False — уверенно не пробито
    if baseline is True:
        return "FIXED"
    return "NOT VULNERABLE"


def _tristate_from_verdict(verdict: str) -> bool | None:
    """PROVEN → True (пробито), NOT PROVEN → False (уверенно не пробито),
    INCONCLUSIVE/иное → None (UNKNOWN)."""
    v = (verdict or "").strip().upper()
    if v == "PROVEN":
        return True
    if v == "NOT PROVEN":
        return False
    return None


# ---------------------------------------------------------------- прогон
@dataclass
class _RunEntry:
    entry: PackEntry
    is_control: bool
    results: list = field(default_factory=list)
    case_ids: list[str] = field(default_factory=list)


@dataclass
class PilotCase:
    key: str
    name: str
    family: str
    is_control: bool
    vulnerable: bool | None
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "name": self.name, "family": self.family,
                "is_control": self.is_control, "vulnerable": self.vulnerable, "verdict": self.verdict}


def _write_synth_scenario(cfg: PilotConfig, out_dir: Path) -> Path:
    """Синтетический сценарий-цель для сборки адаптера (build_adapter) и preflight
    (run_preflight) — представляет ручку пилота. Тело атаки placeholder: preflight
    читает только target, пак гоняет РЕАЛЬНЫЕ сценарии реестра."""
    doc = {
        "id": "pilot-target",
        "target": {"adapter": cfg.adapter, "base_url": cfg.base_url,
                   "model_name": cfg.model, "api_key_env": cfg.api_key_env},
        "actors": {"attacker": {"user_id": "pilot-attacker"}, "victim": {"user_id": "pilot-victim"}},
        "attack": {"family": "cross_user_bac"},
    }
    path = out_dir / "_pilot-target.yaml"
    path.write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    return path


def _packaged_scenario_path(name: str) -> str | None:
    """Путь к упакованному сценарию стартового пака через importlib.resources
    (P19: виден из установленного wheel без каталога репозитория). None —
    ресурса нет (пакет/файл отсутствует), тогда вызывающий уходит в repo-fallback."""
    try:
        res = resources.files(_PILOT_SCENARIOS_PKG).joinpath(name)
    except (ModuleNotFoundError, ImportError):
        return None
    try:
        if res.is_file():
            return str(res)
    except (OSError, AttributeError):
        return None
    return None


def _resolve_pack_path(rel: str) -> str:
    """Разрешает путь сценария стартового пака (P19 часть 2):
    1) package resource (importlib.resources) — единственная упакованная копия,
       видна из установленного wheel БЕЗ каталога репозитория;
    2) fallback на репозиторный _REPO_ROOT/rel — поведение разработчика в дереве.
    Абсолютный путь возвращается как есть."""
    p = Path(rel)
    if p.is_absolute():
        return str(p)
    packaged = _packaged_scenario_path(p.name)
    if packaged is not None:
        return packaged
    return str(_REPO_ROOT / rel)


async def _run_pack(cfg: PilotConfig, target, out_dir: Path, console: Console) -> list[_RunEntry]:
    """Гонит стартовый пак существующими сценариями реестра против ручки пилота
    (один общий T1-адаптер, последовательно). Уважает budget_cap (потолок прогонов
    против ручки): исчерпан → остальное честно пропускается."""
    runs: list[_RunEntry] = []
    committed = 0
    for entry in STARTER_PACK:
        planned = [(entry.entry_id, entry.scenario, False)]
        if entry.control:
            planned.append((f"{entry.entry_id}-control", entry.control, True))
        for run_id, scenario_rel, is_control in planned:
            if committed + 1 > cfg.budget_cap:
                console.print(f"[yellow]budget_cap={cfg.budget_cap} исчерпан — пропускаю {run_id}[/yellow]")
                continue
            path = _resolve_pack_path(scenario_rel)
            if not Path(path).exists():
                console.print(f"[yellow]сценарий пака не найден, пропуск: {path}[/yellow]")
                continue
            committed += 1
            sc = load_scenario(path)
            cr = await Campaign(sc, target, out_dir / run_id).run(repetitions=cfg.iterations)
            re = _RunEntry(entry=entry, is_control=is_control)
            re.results = list(cr.results)
            re.case_ids = [r.case_id for r in cr.results]
            runs.append(re)
            console.print(f"  ran [{run_id}] {entry.name}{' (control)' if is_control else ''}: "
                          f"{len(cr.results)} case(s)")
    return runs


def _pilot_cases(runs: list[_RunEntry], report: Any) -> list[PilotCase]:
    """Тристейт по кейсу из вердикта threat-report P16 (PROVEN/NOT PROVEN/
    INCONCLUSIVE) — переиспользуем классификацию рендерера, не изобретаем свою."""
    verdict_by_case = {c.case_id: c.verdict for c in getattr(report, "cases", [])}
    cases: list[PilotCase] = []
    for re in runs:
        verdicts = [verdict_by_case.get(cid, "INCONCLUSIVE") for cid in re.case_ids]
        tri = [_tristate_from_verdict(v) for v in verdicts]
        if any(t is True for t in tri):
            vulnerable: bool | None = True
        elif tri and all(t is False for t in tri):
            vulnerable = False
        else:
            vulnerable = None  # хоть один UNKNOWN → UNKNOWN (не выдаём False)
        family = re.results[0].family if re.results else ""
        key = f"{re.entry.entry_id}-control" if re.is_control else re.entry.entry_id
        cases.append(PilotCase(
            key=key, name=re.entry.name + (" (control)" if re.is_control else ""),
            family=family, is_control=re.is_control, vulnerable=vulnerable,
            verdict=verdicts[0] if verdicts else "INCONCLUSIVE",
        ))
    return cases


def _merge_jsonl(out_dir: Path, name: str) -> None:
    lines: list[str] = []
    for p in sorted(out_dir.glob(f"*/{name}")):
        lines.extend(p.read_text(encoding="utf-8").splitlines())
    if lines:
        (out_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- вывод
def _reconfigure_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _render_key_instruction(console: Console, cfg: PilotConfig, exc: Exception) -> None:
    console.print(f"[red]Ключ ручки не найден в переменной окружения {cfg.api_key_env!r}.[/red]")
    console.print("Задайте его и повторите (значение в файл/репозиторий НЕ писать):")
    console.print(f"    export {cfg.api_key_env}=<ваш-ключ>")


def _render_capabilities(console: Console, probe: Any) -> None:
    caps = probe.capabilities
    console.rule("[bold]PROBE[/bold]")
    console.print(f"  ручка отвечает (reachable), статус в detail: {getattr(probe, 'detail', {})}")
    console.print(f"  наблюдаемость tier-1: trace={caps.trace} snapshot={caps.memory_snapshot} "
                  f"tool_calls={caps.tool_calls} retrieval={caps.retrieval}")
    console.print("  [dim]каналы False → соответствующие оракулы дадут UNKNOWN (не False): "
                  "чёрный ящик не опровергает[/dim]")


def _render_summary(console: Console, report: Any, combined: CampaignResult, path: Path) -> None:
    m = combined.aggregate_metrics
    stamp = report.stamp + (f" ({report.severity})" if getattr(report, "severity", None) else "")
    console.rule("[bold]ИТОГ ПИЛОТА[/bold]")
    console.print(f"  вердикт:       {stamp}")
    console.print(f"  доказано:      {m.get('successful')} of {m.get('attempts')} (N of M)")
    console.print(f"  threat-report: {path}")
    console.print("  [dim]UNKNOWN ≠ safe: INCONCLUSIVE означает «не доказано», а не «цель защищена»[/dim]")


def _render_retest(console: Console, out_dir: Path, baseline_dir: Path, new_cases: list[PilotCase]) -> None:
    base_path = baseline_dir / "pilot-cases.json"
    if not base_path.exists():
        console.print(f"[yellow]retest: {base_path} не найден — это не каталог прошлого пилота, секция пропущена[/yellow]")
        return
    base_raw = json.loads(base_path.read_text(encoding="utf-8"))
    base_by_key = {c["key"]: c for c in base_raw}
    console.rule("[bold]RETEST[/bold] (было → стало)")
    rows = []
    for c in new_cases:
        base = base_by_key.get(c.key)
        base_vuln = base.get("vulnerable") if base else None
        status = "NEW CASE" if base is None else classify_retest(base_vuln, c.vulnerable)
        rows.append({"key": c.key, "name": c.name, "baseline": base_vuln, "now": c.vulnerable, "status": status})
        console.print(f"  {c.name}: {status}")
    console.print("  [dim]ЗАМОК: UNKNOWN не равен FIXED — без наблюдаемости «исправлено» не доказать[/dim]")
    (out_dir / "retest.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- оркестрация
def run_pilot(config_path: str | Path, output: str | Path, *, load_campaign: CampaignLoader,
             console: Console | None = None, baseline: str | Path | None = None) -> int:
    """Точка входа пилота (--config). Возвращает код: 0 успех; 1 контрактная
    ошибка/блокер preflight; 2 конфиг/ключ/недоступная ручка. Ошибки —
    человекочитаемые, без traceback."""
    _reconfigure_stdout()
    console = console or Console()
    render_provenance(console)  # W10: версия/путь пакета + предупреждение о чужом дереве
    load_dotenv(Path(".env"), os.environ)  # переиспользуем механику P18: подхват .env (только имена)
    try:
        cfg = load_pilot_config(config_path)
    except PilotConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    return asyncio.run(_pilot_chain(cfg, Path(output), load_campaign, console,
                                    Path(baseline) if baseline else None))


async def _pilot_chain(cfg: PilotConfig, out_dir: Path, load_campaign: CampaignLoader,
                       console: Console, baseline: Path | None) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    synth_path = _write_synth_scenario(cfg, out_dir)
    synth = load_scenario(synth_path)
    try:
        target = build_adapter(synth)          # HttpEndpointAdapter; нет ключа → ValueError
    except ValueError as exc:
        _render_key_instruction(console, cfg, exc)
        return 2
    try:
        probe = await target.probe()
        if not probe.reachable:
            console.print(f"[red]probe: ручка недоступна — {probe.error}[/red]")
            console.print("  проверьте base_url и что эндпоинт отвечает (см. причину выше).")
            return 2
        _render_capabilities(console, probe)

        # run_preflight — синхронный, но внутри использует asyncio.run; из уже
        # запущенного цикла его нельзя звать напрямую — уносим в поток (свой цикл).
        loop = asyncio.get_running_loop()
        pf = await loop.run_in_executor(None, run_preflight, str(synth_path))  # переиспользуем preflight вызовом
        console.rule("[bold]PREFLIGHT[/bold]")
        console.print(f"  блокеров {pf.blockers}, предупреждений {pf.warnings}")
        blockers = [c for c in pf.checks if c.status == BLOCKER]
        if blockers:
            for c in blockers:
                console.print(f"[red][БЛОКЕР] {c.check_id}: {c.text}[/red]")
            return 1

        runs = await _run_pack(cfg, target, out_dir, console)
    finally:
        await target.aclose()

    if not runs:
        console.print("[red]ни один сценарий пака не выполнен (проверьте budget_cap и наличие сценариев)[/red]")
        return 1

    all_results = [r for re in runs for r in re.results]
    run_id = "RUN-pilot-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    combined = CampaignResult(run_id=run_id, scenario_id="pilot-pack", attempts=len(all_results),
                              results=all_results, aggregate_metrics=aggregate_metrics(all_results))
    (out_dir / "campaign.json").write_text(
        json.dumps(campaign_to_dict(combined), ensure_ascii=False, indent=2), encoding="utf-8")
    # Только events объединяем в корень пакета (для trace-секций отчёта). attempts.jsonl
    # НЕ сливаем: пакеты доказательств лежат в подкаталогах прогонов, а
    # verify_run_evidence(out_dir) сверяет attempts↔bundles — корень без attempts.jsonl
    # проходит как исторический прогон (bundles остаются рядом со своими прогонами).
    _merge_jsonl(out_dir, "events.jsonl")

    path, report = write_threat_report(out_dir, None, load_campaign=load_campaign)  # рендерер P16
    cases = _pilot_cases(runs, report)
    (out_dir / "pilot-cases.json").write_text(
        json.dumps([c.to_dict() for c in cases], ensure_ascii=False, indent=2), encoding="utf-8")

    _render_summary(console, report, combined, path)
    # CARD-CLI-MEGA-UX §5 (спотыкание №3): точный путь открытия прогона в консоли.
    for line in console_open_hint(out_dir):
        console.print(line)
    # строки попыток P12 (переиспользуем selfserve.attempt_lines) — из подкаталогов
    # прогонов (в корне attempts.jsonl намеренно нет, см. выше)
    for sub in sorted(out_dir.glob("*/attempts.jsonl")):
        for line in attempt_lines(sub.parent):
            console.print(line)
    if baseline is not None:
        _render_retest(console, out_dir, baseline, cases)
    return 0
