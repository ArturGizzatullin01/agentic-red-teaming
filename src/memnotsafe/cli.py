"""src/memnotsafe/cli.py — entrypoint. Ровно четыре обязательные команды + replay.
Различение кодов возврата — жёсткое требование:
    ошибка раннера/адаптера/контракта  -> exit 1
    атака не сработала (честный негатив) -> exit 0, finding NOT_EXPLOITABLE
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import build_adapter, load_scenario, validate_judge_spec
from memnotsafe.core.runner import RunnerError
from memnotsafe.generation.errors import AttackerError
from memnotsafe.reporting.console import (
    ConsoleReporter,
    OutputOptions,
    render_calibration,
    render_campaign_summary,
    render_dataset_built,
    render_generate,
    render_probe,
    render_replay,
)
from memnotsafe.reporting.html_report import write_html_report
from memnotsafe.reporting.json_report import write_json_reports
from memnotsafe.reporting.metrics import aggregate_metrics
from memnotsafe.reporting.sarif import write_sarif
from memnotsafe.reporting.findings import build_findings
from memnotsafe.tracing.recorder import read_events_jsonl


def _reporter(args: argparse.Namespace) -> ConsoleReporter:
    """Output-слой команды (фича 006): флаги читаются через getattr, поэтому
    cmd_* остаётся вызываемым с самодельным Namespace без флагов."""
    return ConsoleReporter(
        OutputOptions(
            json=getattr(args, "json", False),
            quiet=getattr(args, "quiet", False),
            no_color=getattr(args, "no_color", False),
        )
    )


def _build_target(target_arg: str | None, scenario_path: str | None):
    if scenario_path:
        scenario = load_scenario(scenario_path)
        return scenario, build_adapter(scenario, target_arg)
    from memnotsafe.adapters.mock import MockTarget

    if not target_arg or target_arg == "mock":
        return None, MockTarget(vulnerable=True)
    from memnotsafe.adapters.openai import OpenAICompatibleAdapter

    return None, OpenAICompatibleAdapter(base_url=target_arg)


def cmd_probe(args: argparse.Namespace) -> int:
    reporter = _reporter(args)
    _scenario, target = _build_target(args.target, args.scenario)

    async def _run():
        try:
            return await target.probe()
        finally:
            await target.aclose()

    result = asyncio.run(_run())
    data = {
        "reachable": result.reachable,
        "capabilities": result.capabilities.to_dict(),
        "detail": result.detail or {},
        "error": result.error,
    }
    if not result.reachable:
        # Таргет недоступен — отказ операции, а не честный негатив атаки: exit 1.
        reporter.emit_error(
            command="probe", message=result.error or "таргет недоступен", data=data,
        )
        return 1
    reporter.emit_result(
        command="probe", outcome="success", exit_code=0, data=data, artifacts=[],
        render=lambda rep: render_probe(rep, result),
    )
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    from memnotsafe.preflight import preflight_cli

    return preflight_cli(args.scenario)


def _resolve_report_dir(output: str) -> tuple[Path, str]:
    p = Path(output)
    if p.suffix == ".html":
        return p.parent, p.name
    return p, "report.html"


def _apply_judge_overrides(scenario, args: argparse.Namespace) -> None:
    """Приоритет: --no-judge > --judge/--judge-* > блок judge: сценария >
    умолчания. Флаги не трогают ни атаку, ни таргет — тот же принцип, что у
    существующего --target."""
    spec = scenario.judge
    if getattr(args, "judge_model", None):
        spec.model = args.judge_model
    if getattr(args, "judge_max_calls", None) is not None:
        spec.max_calls = args.judge_max_calls
    # Судью включают --judge и --judge-model: назвать модель — явное намерение
    # судить. --judge-max-calls один судью не поднимает: это ручка бюджета, и
    # включение по ней уронило бы прогон на валидации «не задан judge.model».
    if getattr(args, "judge", False) or getattr(args, "judge_model", None):
        spec.enabled = True
    if getattr(args, "no_judge", False):
        spec.enabled = False


async def _run_campaign(args: argparse.Namespace, *, default_repetitions: int, command: str) -> int:
    reporter = _reporter(args)
    scenario = load_scenario(args.scenario)
    _apply_judge_overrides(scenario, args)
    try:
        # Ошибка конфигурации судьи -> exit 1 ДО первого обращения к таргету:
        # оператор узнаёт о ней раньше, чем прогон потратит вызовы к стенду.
        validate_judge_spec(scenario.judge, scenario.id)
    except RunnerError as exc:
        reporter.emit_error(command=command, message=str(exc))
        return 1
    target = build_adapter(scenario, args.target)
    repetitions = args.iterations if getattr(args, "iterations", None) else default_repetitions
    # W9: metrics.repetitions сценария CLI-командами переопределяется всегда
    # (run жёстко 1, campaign — --iterations или 5). Молчать нельзя — конфиг
    # врал бы читателю; подчиняться YAML CLI не должен: это смена знаменателей
    # ASR всех прошлых прогонов (решение владельца). Предупреждение — с обоими
    # числами и причиной, в human-режиме в stderr; --json/--quiet потоки чисты
    # (контракт «один объект»/«пусто» не меняется — машины не трогаем).
    declared = (scenario.raw.get("metrics") or {}).get("repetitions")
    if (declared is not None and declared != repetitions
            and not getattr(args, "json", False) and not getattr(args, "quiet", False)):
        reason = ("флагом --iterations" if getattr(args, "iterations", None) is not None
                  else f"умолчанием команды {command} ({repetitions})")
        print(
            f"ВНИМАНИЕ: сценарий объявляет metrics.repetitions={declared}, "
            f"но исполнено будет {repetitions} — значение из сценария "
            f"переопределено {reason}.",
            file=sys.stderr,
        )

    run_output = Path(args.output)
    online = getattr(args, "online", False)
    # При выключенном онлайне (по умолчанию) атакующая LLM не конфигурируется вовсе
    # (SC-003): ни вызовов, ни клиента. AttackerConfig создаётся только под --online.
    attacker_config = _online_attacker_config(args, scenario, reporter) if online else None
    campaign = Campaign(
        scenario,
        target,
        run_output,
        attacker_config=attacker_config,
        online=online,
        online_attempts=getattr(args, "online_attempts", 5),
    )
    try:
        result = await campaign.run(repetitions=repetitions)
    except (RunnerError, AttackerError) as exc:
        # AttackerError здесь — config-ошибка ДО прогона (например, битый путь к
        # корпусу): результатов ещё нет, exit 1.
        reporter.emit_error(command=command, message=str(exc))
        return 1
    finally:
        await target.aclose()
        if campaign.judge is not None:
            await campaign.judge.aclose()
        await campaign.aclose_attacker()

    report_dir, html_name = _resolve_report_dir(str(run_output / "report"))
    written = write_json_reports(result, report_dir)
    findings = build_findings(result.results)
    write_sarif(findings, report_dir / "findings.sarif")

    events = read_events_jsonl(run_output / "events.jsonl")
    by_case: dict[str, list[dict]] = {}
    for e in events:
        by_case.setdefault(e.get("case_id", ""), []).append(e)
    html_path = write_html_report(result, report_dir / html_name, by_case)

    # Сбой атакующей LLM В ХОДЕ эскалации ≠ «атака не пробила» (FR-011, SC-005):
    # уже полученные результаты сохранены в runs/ и отчёт собран, но код — 1.
    attacker_failed = campaign.attacker_error is not None
    reporter.emit_result(
        command=command,
        outcome="success",
        exit_code=1 if attacker_failed else 0,
        data=_campaign_data(result, findings),
        artifacts=[str(html_path), str(written["report"]), str(written["findings"])],
        render=lambda rep: render_campaign_summary(rep, result, html_path),
    )
    if attacker_failed:
        reporter.emit_error(
            command=command,
            message=f"сбой атакующей LLM в онлайн-эскалации: {campaign.attacker_error}",
        )
        return 1
    return 0


def _findings_counts(findings: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    return counts


def _campaign_data(result, findings: list) -> dict:
    """data для JSON-контракта run/campaign/report. Стадии со значением None
    (UNKNOWN) уходят в JSON как null — НЕ приводятся к pass/fail."""
    m = result.aggregate_metrics
    return {
        "run_id": result.run_id,
        "scenario_id": result.scenario_id,
        "attempts": result.attempts,
        "end_to_end_asr": m.get("end_to_end_asr"),
        "asr_provenance": m.get("asr_provenance"),
        "findings_counts": _findings_counts(findings),
        "results": [
            {
                "case_id": f.case_id,
                "family": f.family,
                "status": f.status,
                "severity": f.severity,
                "stages": f.stages,
            }
            for f in findings
        ],
    }


def _online_attacker_config(args: argparse.Namespace, scenario, reporter: ConsoleReporter):
    """Конфигурация атакующей LLM для онлайн-уровня. Офлайн-заглушка без скрипта
    получает детерминированные «переписывания» (research §9). При совпадении
    модели атакующей LLM с моделью цели печатает предупреждение (FR-015)."""
    from memnotsafe.generation.config import PROVIDER_STUB, warn_on_model_collision

    config = _attacker_config_from_args(args)
    if config.provider == PROVIDER_STUB and not config.scripted:
        config.scripted = _online_stub_scripts(scenario, getattr(args, "online_attempts", 5))

    target_model = (scenario.target.extra or {}).get("model_name")
    warn = warn_on_model_collision(config, target_model)
    if warn:
        reporter.warn(warn)
    return config


def _online_stub_scripts(scenario, online_attempts: int) -> list[str]:
    """Достаточно эталонных «переписываний» под офлайн-демо: по одному на попытку
    каждой записи корпуса, с запасом. Заглушка бросит AttackerError, только если
    скрипт реально исчерпан (что для этой оценки не случается)."""
    from memnotsafe.generation.offline import escalation_stub_script

    n = 1
    if scenario.attack_family == "generated" and scenario.corpus_path:
        try:
            from memnotsafe.generation.corpus import read_corpus, valid_records

            n = max(1, len(valid_records(read_corpus(scenario.corpus_path))))
        except AttackerError:
            n = 1
    return [escalation_stub_script()] * (n * max(online_attempts, 1) + 2)


def cmd_run(args: argparse.Namespace) -> int:
    return asyncio.run(_run_campaign(args, default_repetitions=1, command="run"))


def cmd_campaign(args: argparse.Namespace) -> int:
    return asyncio.run(_run_campaign(args, default_repetitions=args.iterations or 5, command="campaign"))


def cmd_orchestrate(args: argparse.Namespace) -> int:
    """P13-a: оркестратор N воркеров кампании (подпроцессы CLI) с общим
    experiment_id и lease-каталогом. Новый выход — только новый код команды;
    контракты существующих команд не затронуты. P13-a-r2: контрактные ошибки
    (workers < 1, расхождение run_dirs) и ошибки окружения спауна —
    управляемый отказ (сообщение + exit 1, без трейсбека), паттерн соседних
    команд (reporter.emit_error); --json отложен в CLI v2."""
    from memnotsafe.core.worker import orchestrate_campaign, orchestrator_rc

    reporter = _reporter(args)
    try:
        outcomes, summary_path = asyncio.run(orchestrate_campaign(
            args.scenario, output=args.output, workers=args.workers,
            iterations=args.iterations,
        ))
    except (ValueError, OSError) as exc:
        reporter.emit_error(command="orchestrate", message=str(exc))
        return 1
    for o in outcomes:
        line = f"orchestrator: воркер w{o.index} rc={o.returncode} run={o.run_dir}"
        if o.error:
            line += f" error: {o.error}"
        print(line)
    rc = orchestrator_rc(outcomes)
    ok = sum(1 for o in outcomes if o.returncode == 0)
    print(f"orchestrator: итог rc={rc} ({ok}/{len(outcomes)} ок), сводка: {summary_path}")
    return rc


def _stage_from_dict(s: dict):
    """Восстановление стадии из campaign.json со ВСЕМИ полями провенанса.

    До этой фичи здесь восстанавливались только четыре поля, и пересобранный
    отчёт выходил беднее исходного. FR-011 требует round-trip без потерь:
    отчёт, пересобранный из сохранённого прогона, идентичен исходному."""
    from memnotsafe.core.models import DeterministicVerdict, JudgeVerdict, StageResult

    defaults = StageResult(stage=s["stage"], success=s["success"])
    judge_raw = s.get("judge")
    det_raw = s.get("deterministic")
    return StageResult(
        stage=s["stage"],
        success=s["success"],
        evidence=s.get("evidence") or [],
        confidence=s.get("confidence", defaults.confidence),
        reason=s.get("reason", ""),
        verdict_source=s.get("verdict_source", defaults.verdict_source),
        evidence_kind=s.get("evidence_kind", defaults.evidence_kind),
        deterministic=DeterministicVerdict.from_dict(det_raw) if det_raw else None,
        judge=JudgeVerdict.from_dict(s["stage"], judge_raw) if judge_raw else None,
        disagreement=bool(s.get("disagreement", False)),
    )


def load_campaign(input_dir: Path):
    """Читает runs/<name>/campaign.json обратно в CampaignResult. Единственное
    место чтения этой раскладки — симметрично core/campaign.py, который её
    единственный пишет. family (002): новый формат несёт её в каждом
    результате; legacy-формат — fallback ТОЛЬКО при однозначно проверяемой
    идентичности (attack_id — точное вхождение в ATTACK_REGISTRY, не префиксная
    эвристика). Иначе family остаётся пустой → findings дадут диагностическую
    ошибку (cmd_report → exit 1)."""
    from memnotsafe.attacks.base import ATTACK_REGISTRY
    from memnotsafe.core.models import AttackResult, CampaignResult

    raw = json.loads((Path(input_dir) / "campaign.json").read_text(encoding="utf-8"))
    results = []
    for r in raw["results"]:
        family = r.get("family") or ""
        if not family:
            legacy_attack_id = r.get("attack_id") or ""
            if legacy_attack_id in ATTACK_REGISTRY:
                family = legacy_attack_id
        results.append(
            AttackResult(
                run_id=raw["run_id"],
                case_id=r["case_id"],
                attack_id=r["attack_id"],
                scenario_id=raw["scenario_id"],
                family=family,
                stages=[_stage_from_dict(s) for s in r["stages"]],
                success=r["success"],
                metrics={},
                evidence=r["evidence"],
                attacker_user_id=r["attacker_user_id"],
                victim_user_id=r["victim_user_id"],
            )
        )
    return CampaignResult(
        run_id=raw["run_id"], scenario_id=raw["scenario_id"], attempts=raw["attempts"],
        results=results, aggregate_metrics=raw["aggregate_metrics"],
    )


def cmd_report(args: argparse.Namespace) -> int:
    reporter = _reporter(args)
    input_dir = Path(args.input)
    campaign_json = input_dir / "campaign.json"
    if not campaign_json.exists():
        reporter.emit_error(
            command="report",
            message=f"{campaign_json} не найден — сначала запусти run/campaign",
        )
        return 1

    campaign = load_campaign(input_dir)

    # P10a (фича 007): доказательственная база прогона проверяется при
    # наличии. Повреждённый/подменённый артефакт, НЕЗАВЕРШЁННЫЙ каталог пакета
    # (без manifest.json), evidence_error в attempts.jsonl (в т.ч. сбой записи
    # ДО создания каталога — иначе replay видел бы только пустоту) или
    # завершённая попытка без пакета — runtime-ошибка данных → exit 1
    # (console-output.md, строка «runtime/config error»). Исторические runs
    # без bundles/ и attempts.jsonl проходят как раньше (0 пакетов — не ошибка).
    from memnotsafe.evidence.bundle import BundleError, verify_run_evidence

    try:
        verify_run_evidence(input_dir)
    except BundleError as exc:
        reporter.emit_error(command="report", message=str(exc))
        return 1

    # F4: replay пересчитывает агрегаты по загруженным результатам принятой
    # формулой, а не копирует сохранённые — старый файл мог содержать неверные
    # метрики (например, ASR по external_effect вместо композита). Пересчёт
    # агрегатов ≠ переоценка стадий: сохранённые verdicts НЕ переигрываются
    # новыми oracle'ами. Готовую сводку судьи и долю расхождений переносим
    # из campaign.json: расход вызовов не восстановить по отдельным стадиям.
    saved_judge_summary = {
        key: campaign.aggregate_metrics[key]
        for key in ("judge", "judge_disagreement_rate")
        if key in campaign.aggregate_metrics
    }
    campaign.aggregate_metrics = aggregate_metrics(campaign.results)
    campaign.aggregate_metrics.update(saved_judge_summary)

    report_dir, html_name = _resolve_report_dir(args.output)
    try:
        write_json_reports(campaign, report_dir)
        findings = build_findings(campaign.results)
    except ValueError as exc:
        # диагностическая ошибка отчёта (семейство не восстановимо) — не краш,
        # а управляемый отказ с сообщением (принцип VII: контрактная ошибка → exit 1)
        reporter.emit_error(command="report", message=str(exc))
        return 1
    write_sarif(findings, report_dir / "findings.sarif")
    events = read_events_jsonl(input_dir / "events.jsonl")
    by_case: dict[str, list[dict]] = {}
    for e in events:
        by_case.setdefault(e.get("case_id", ""), []).append(e)
    html_path = write_html_report(campaign, report_dir / html_name, by_case)
    reporter.emit_result(
        command="report",
        outcome="success",
        exit_code=0,
        data=_campaign_data(campaign, findings),
        artifacts=[str(html_path), str(report_dir / "report.json"), str(report_dir / "findings.json")],
        render=lambda rep: render_campaign_summary(
            rep, campaign, html_path,
            replay_note="Replay: агрегаты пересчитаны по сохранённым результатам; стадии не переоценивались.",
        ),
    )
    return 0


def cmd_judge_calibrate(args: argparse.Namespace) -> int:
    """Измерение судьи на размеченном наборе (US3, FR-010).

    Команда НЕ поднимает адаптер и не пишет в runs/: таргет ей не нужен, она
    работает по сохранённым текстам. `exit 1` при `--gate` — не сбой
    инструмента, а вердикт «этому судье нельзя доверять боевой прогон»
    (outcome=gate_failed, stdout «как success», stderr пуст)."""
    reporter = _reporter(args)
    from memnotsafe.core.config import JudgeSpec
    from memnotsafe.judge.calibration import (
        build_dataset_from_run,
        calibrate,
        load_dataset,
        write_dataset,
    )

    # Режим сборки набора из завершённого офлайн-прогона — сети не требует.
    if args.from_run:
        if not args.out:
            reporter.emit_error(command="judge-calibrate", message="--from-run требует --out <jsonl>")
            return 1
        cases = build_dataset_from_run(Path(args.from_run))
        path = write_dataset(cases, Path(args.out))
        by_stage: dict[str, int] = {}
        for c in cases:
            by_stage[c.stage] = by_stage.get(c.stage, 0) + 1
        reporter.emit_result(
            command="judge-calibrate", outcome="success", exit_code=0,
            data={"cases": len(cases), "dataset": str(path), "by_stage": by_stage},
            artifacts=[str(path)],
            render=lambda rep: render_dataset_built(rep, len(cases), path, by_stage),
        )
        return 0

    if not args.dataset:
        reporter.emit_error(
            command="judge-calibrate", message="нужен --dataset <jsonl> или --from-run <runs/dir>",
        )
        return 1

    spec = JudgeSpec(
        enabled=True,
        model=args.judge_model,
        min_confidence=args.min_confidence,
    )
    try:
        validate_judge_spec(spec, "judge-calibrate")
    except RunnerError as exc:
        reporter.emit_error(command="judge-calibrate", message=str(exc))
        return 1

    cases = load_dataset(args.dataset)
    if args.injection_suite:
        cases += load_dataset(args.injection_suite)

    async def _run() -> dict:
        from memnotsafe.judge.client import JudgeClient

        client = JudgeClient(
            model=spec.model or "", base_url=spec.base_url, api_key_env=spec.api_key_env,
            timeout_s=spec.timeout_s, temperature=spec.temperature,
        )
        try:
            return await calibrate(cases, spec=spec, client=client, dataset=str(args.dataset))
        finally:
            await client.aclose()

    report = asyncio.run(_run())

    output = Path(args.output or "reports/judge-calibration.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # --gate: exit 1 — это вердикт о судье, а не падение инструмента: stdout
    # «как success» (таблица/JSON с outcome=gate_failed), stderr пуст.
    gate_failed = bool(args.gate) and not report["gate_passed"]
    reporter.emit_result(
        command="judge-calibrate",
        outcome="gate_failed" if gate_failed else "success",
        exit_code=1 if gate_failed else 0,
        data=report,
        artifacts=[str(output)],
        render=lambda rep: render_calibration(rep, report, output, gate_failed=gate_failed),
    )
    return 1 if gate_failed else 0


def cmd_replay(args: argparse.Namespace) -> int:
    reporter = _reporter(args)
    input_dir = Path(args.input)
    trace_path = input_dir / "traces" / f"{args.case}.json"
    if not trace_path.exists():
        reporter.emit_error(command="replay", message=f"трасса не найдена: {trace_path}")
        return 1
    events = json.loads(trace_path.read_text(encoding="utf-8"))
    reporter.emit_result(
        command="replay", outcome="success", exit_code=0,
        data={"events": events}, artifacts=[],
        render=lambda rep: render_replay(rep, events),
    )
    return 0


def _add_online_flags(parser: argparse.ArgumentParser) -> None:
    """Онлайн-уровень (US3). По умолчанию ВЫКЛ (FR-009): без флага поведение и
    стоимость совпадают с текущим инструментом (SC-003)."""
    parser.add_argument("--online", action="store_true", help="включить онлайн-эскалацию (по умолчанию выкл)")
    parser.add_argument("--online-attempts", type=int, default=5, help="предел попыток онлайн-эскалации на атаку")


def _add_attacker_flags(parser: argparse.ArgumentParser) -> None:
    """Общий блок конфигурации атакующей LLM (contracts/cli-commands.md). Общий у
    `generate` и онлайн-уровня `run`/`campaign` — одна модель в двух режимах.
    Секрет — только именем переменной окружения (`--attacker-api-key-env`), не
    значением (FR-016)."""
    parser.add_argument("--attacker-provider", default="stub", help="stub (офлайн/CI/демо) | openai (живая генерация)")
    parser.add_argument("--attacker-model", default=None, help="имя модели генератора атак")
    parser.add_argument("--attacker-base-url", default=None, help="base URL для openai-совместимого провайдера")
    parser.add_argument("--attacker-api-key-env", default="ATTACKER_API_KEY", help="имя переменной окружения с ключом атакующей LLM")
    parser.add_argument("--attacker-budget", type=int, default=50, help="лимит вызовов атакующей LLM на операцию")


def _attacker_config_from_args(args: argparse.Namespace):
    from memnotsafe.generation.config import AttackerConfig

    return AttackerConfig(
        provider=getattr(args, "attacker_provider", "stub"),
        model=getattr(args, "attacker_model", None),
        base_url=getattr(args, "attacker_base_url", None),
        api_key_env=getattr(args, "attacker_api_key_env", "ATTACKER_API_KEY"),
        budget=getattr(args, "attacker_budget", 50),
    )


def cmd_generate(args: argparse.Namespace) -> int:
    """Precompute-генерация корпуса атак под профиль (US1). Коды возврата:
    0 — корпус собран и сохранён (даже если часть записей отбракована, FR-012);
    1 — config-ошибка профиля/классов или сбой атакующей LLM (AttackerError)."""
    reporter = _reporter(args)
    from memnotsafe.generation.attack_classes import load_attack_classes
    from memnotsafe.generation.attacker_client import build_attacker_client
    from memnotsafe.generation.budget import CallBudget
    from memnotsafe.generation.config import PROVIDER_STUB
    from memnotsafe.generation.corpus import write_corpus
    from memnotsafe.generation.corpus_gen import generate_corpus
    from memnotsafe.generation.errors import AttackerError
    from memnotsafe.generation.offline import reference_answers
    from memnotsafe.generation.profile import load_profile

    try:
        profile = load_profile(args.profile)
        classes = load_attack_classes(args.classes or "attack_classes/")
    except AttackerError as exc:
        reporter.emit_error(command="generate", message=str(exc))
        return 1
    except (OSError, ValueError) as exc:
        # фикс приёмки (RETURN_FOR_FIX d09299a): дефолт `attack_classes/`
        # cwd-относителен — вне репозитория его нет; отсутствие профиля или
        # классов обязано быть ЧИСТОЙ config-ошибкой (stderr, exit 1,
        # с --json — один JSON-объект ошибки), а не сырым traceback'ом
        reporter.emit_error(
            command="generate",
            message=(
                f"{exc} — укажите существующие --classes <dir> (дефолт "
                "`attack_classes/` ищется в текущем каталоге) и --profile <файл>"
            ),
        )
        return 1

    config = _attacker_config_from_args(args)
    # Офлайн-заглушка без явного скрипта → детерминированные эталонные ответы под
    # каждый класс (research §9): `generate --attacker-provider stub` работает без
    # ключей и без сети, годится для CI и демо.
    if config.provider == PROVIDER_STUB and not config.scripted:
        config.scripted = reference_answers(classes)

    client = build_attacker_client(config)
    budget = CallBudget(limit=config.budget)

    async def _run():
        try:
            return await generate_corpus(
                profile, classes, client, budget, provider=config.provider, model=config.model
            )
        finally:
            await client.aclose()

    try:
        corpus = asyncio.run(_run())
    except AttackerError as exc:
        reporter.emit_error(command="generate", message=str(exc))
        return 1

    out = write_corpus(corpus, args.out)
    prov = corpus.provenance
    reporter.emit_result(
        command="generate", outcome="success", exit_code=0,
        data={
            "corpus": str(out),
            "profile_id": prov.profile_id,
            "profile_sha256": prov.profile_sha256,
            "attack_classes": list(prov.attack_classes),
            "records": len(corpus.records),
            "attacker_calls": prov.attacker_calls,
        },
        artifacts=[str(out)],
        render=lambda rep: render_generate(rep, out, prov, len(corpus.records)),
    )
    return 0


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    """Флаги output-слоя (фича 006) — на КАЖДУЮ подкоманду. cmd_* читает их
    только через getattr(args, name, False): прямые вызовы cmd_* с самодельным
    Namespace (регресс-тесты) остаются валидными без флагов."""
    parser.add_argument("--json", action="store_true", help="машинный вывод: ровно один JSON-объект в stdout (UNKNOWN → null)")
    parser.add_argument("--quiet", action="store_true", help="без человекочитаемого вывода; результат — код возврата и артефакты")
    parser.add_argument("--no-color", action="store_true", help="выключить цвет (ANSI) в human-выводе")


def _add_judge_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--judge", action="store_true", help="включить LLM-судью независимо от judge.enabled в сценарии")
    parser.add_argument("--no-judge", action="store_true", help="выключить судью независимо от сценария (приоритет над --judge)")
    parser.add_argument("--judge-model", default=None, help="переопределить judge.model")
    parser.add_argument("--judge-max-calls", type=int, default=None, help="переопределить бюджет судейских вызовов на кампанию")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memnotsafe",
        description="Your Memory Is Not Safe — Agentic Memory Red Teaming",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pp = sub.add_parser("probe", help="проверить доступность таргета и его telemetry-возможности")
    pp.add_argument("--target", default=None, help="URL таргета или 'mock' (по умолчанию mock)")
    pp.add_argument("--scenario", default=None)
    _add_output_flags(pp)
    pp.set_defaults(func=cmd_probe)

    pf = sub.add_parser("preflight", help="проверить ДО прогона, что будет измерено (identity, стенд, Mongo)")
    pf.add_argument("--scenario", required=True)
    pf.set_defaults(func=cmd_preflight)

    pr = sub.add_parser("run", help="один прогон атаки (repetitions=1)")
    pr.add_argument("--target", default=None)
    pr.add_argument("--scenario", required=True)
    pr.add_argument("--output", required=True)
    pr.add_argument("--iterations", type=int, default=None)
    _add_online_flags(pr)
    _add_attacker_flags(pr)
    _add_judge_flags(pr)
    _add_output_flags(pr)
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("campaign", help="N повторов атаки с агрегацией метрик")
    pc.add_argument("--target", default=None)
    pc.add_argument("--scenario", required=True)
    pc.add_argument("--output", required=True)
    pc.add_argument("--iterations", type=int, default=None)
    _add_online_flags(pc)
    _add_attacker_flags(pc)
    _add_judge_flags(pc)
    _add_output_flags(pc)
    pc.set_defaults(func=cmd_campaign)

    porc = sub.add_parser("orchestrate", help="оркестратор N воркеров кампании: общий experiment_id, lease-каталог, сводка (P13-a)")
    porc.add_argument("--scenario", required=True)
    porc.add_argument("--output", required=True,
                      help="база: воркеры <output>-w<i>/, замки <output>/locks, сводка <output>-orchestrator.json")
    porc.add_argument("--workers", type=int, default=2)
    porc.add_argument("--iterations", type=int, default=None)
    porc.set_defaults(func=cmd_orchestrate)

    pgen = sub.add_parser("generate", help="precompute-генерация корпуса атак под профиль (US1)")
    pgen.add_argument("--profile", required=True, help="путь к файлу-профилю агента")
    pgen.add_argument("--classes", default=None, help="каталог/файл описаний классов (по умолчанию attack_classes/)")
    pgen.add_argument("--out", required=True, help="куда сохранить корпус (corpora/<name>.yaml)")
    _add_attacker_flags(pgen)
    _add_output_flags(pgen)
    pgen.set_defaults(func=cmd_generate)

    prep = sub.add_parser("report", help="пересобрать report.html/.json из сохранённого runs/<name>")
    prep.add_argument("--input", required=True)
    prep.add_argument("--output", required=True)
    _add_output_flags(prep)
    prep.set_defaults(func=cmd_report)

    pcal = sub.add_parser("judge-calibrate", help="измерить судью на размеченном наборе (US3)")
    pcal.add_argument("--dataset", default=None, help="эталонный набор JSONL")
    pcal.add_argument("--injection-suite", default=None, help="набор пар «чистый/инъецированный» для SC-005")
    pcal.add_argument("--judge-model", default=None, help="модель судьи для этого измерения")
    pcal.add_argument("--output", default=None, help="куда положить отчёт (по умолчанию reports/judge-calibration.json)")
    pcal.add_argument("--min-confidence", type=float, default=0.7, help="порог для этого измерения")
    pcal.add_argument("--gate", action="store_true", help="exit 1, если судья не проходит SC-002/SC-005")
    pcal.add_argument("--from-run", default=None, help="собрать набор из завершённого офлайн-прогона")
    pcal.add_argument("--out", default=None, help="куда записать собранный набор (с --from-run)")
    _add_output_flags(pcal)
    pcal.set_defaults(func=cmd_judge_calibrate)

    prepl = sub.add_parser("replay", help="напечатать причинную трассу одного case")
    prepl.add_argument("--input", required=True)
    prepl.add_argument("--case", required=True)
    _add_output_flags(prepl)
    prepl.set_defaults(func=cmd_replay)

    # CARD-P16: бизнес-отчёт из доказательного пакета прогона (read-only,
    # паттерн B4). Аддитивная врезка: команда и её коды выхода 0/1/2 живут в
    # reporting/threat_report.py; модуль импортируется внутри обёртки — только
    # при вызове самой команды, другие команды рендерер не тянут (прецедент
    # cmd_preflight/cmd_orchestrate); читатель campaign.json (load_campaign)
    # передаётся параметром — reporting не импортирует cli, слои ацикличны
    # (test_import_layers); контракты существующих команд не затронуты.
    def _cmd_threat_report(args: argparse.Namespace) -> int:
        from memnotsafe.reporting.threat_report import cmd_threat_report

        return cmd_threat_report(args, load_campaign=load_campaign)

    ptr = sub.add_parser("threat-report", help="бизнес-отчёт threat-report.html из сохранённого runs/<name> (P16)")
    ptr.add_argument("--input", required=True, help="каталог прогона runs/<name> (нужен campaign.json)")
    ptr.add_argument("--output", default=None, help="путь threat-report.html или каталог (по умолчанию — рядом с прогоном)")
    _add_output_flags(ptr)
    ptr.set_defaults(func=_cmd_threat_report)

    # CARD-P18: интерактивный мастер `go` — UX-оболочка над preflight/run/
    # threat-report. Аддитивная врезка (прецедент P16): вся логика в
    # memnotsafe.selfserve, импорт ленивый (только при вызове go); штатный `run`
    # и читатель campaign.json передаются параметрами — selfserve не импортирует
    # cli, движок и контракты существующих команд не затронуты. (Рядом позже
    # встанет врезка P17.)
    def _cmd_go(args: argparse.Namespace) -> int:
        from memnotsafe.selfserve import run_go

        return run_go(args, run_command=cmd_run, load_campaign=load_campaign)

    pgo = sub.add_parser("go", help="интерактивный мастер: сценарий → preflight → прогон → threat-report (P18)")
    pgo.add_argument("--scenario", default=None, help="путь к сценарию; без него — выбор из каталога")
    pgo.add_argument("--target", default=None, help="URL таргета или 'mock' (по умолчанию из сценария)")
    pgo.add_argument("--output", default=None, help="каталог прогона (по умолчанию ASCII runs/go-<id>-<UTC>)")
    pgo.add_argument("--yes", action="store_true", help="тихий режим: без вопросов и без автооткрытия отчёта")
    pgo.add_argument("--ping", action="store_true", help="отдельный ПЛАТНЫЙ шаг проверки связи судьи (по явному согласию)")
    pgo.add_argument("--no-color", action="store_true", help="выключить цвет (ANSI)")
    _add_online_flags(pgo)
    _add_attacker_flags(pgo)
    _add_judge_flags(pgo)
    pgo.set_defaults(func=_cmd_go)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
