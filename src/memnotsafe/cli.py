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
from memnotsafe.reporting.html_report import write_html_report
from memnotsafe.reporting.json_report import write_json_reports
from memnotsafe.reporting.sarif import write_sarif
from memnotsafe.reporting.findings import build_findings
from memnotsafe.tracing.recorder import read_events_jsonl


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
    _scenario, target = _build_target(args.target, args.scenario)

    async def _run() -> int:
        try:
            result = await target.probe()
        finally:
            await target.aclose()
        print(f"reachable: {result.reachable}")
        print(f"capabilities: {json.dumps(result.capabilities.to_dict(), ensure_ascii=False)}")
        if result.detail:
            print(f"detail: {json.dumps(result.detail, ensure_ascii=False)}")
        if result.error:
            print(f"error: {result.error}")
        return 0 if result.reachable else 1

    return asyncio.run(_run())


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


async def _run_campaign(args: argparse.Namespace, *, default_repetitions: int) -> int:
    scenario = load_scenario(args.scenario)
    _apply_judge_overrides(scenario, args)
    try:
        # Ошибка конфигурации судьи -> exit 1 ДО первого обращения к таргету:
        # оператор узнаёт о ней раньше, чем прогон потратит вызовы к стенду.
        validate_judge_spec(scenario.judge, scenario.id)
    except RunnerError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 1
    target = build_adapter(scenario, args.target)
    repetitions = args.iterations if getattr(args, "iterations", None) else default_repetitions

    run_output = Path(args.output)
    online = getattr(args, "online", False)
    # При выключенном онлайне (по умолчанию) атакующая LLM не конфигурируется вовсе
    # (SC-003): ни вызовов, ни клиента. AttackerConfig создаётся только под --online.
    attacker_config = _online_attacker_config(args, scenario) if online else None
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
        print(f"[FATAL] {exc}", file=sys.stderr)
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

    _print_summary(result, html_path)

    # Сбой атакующей LLM В ХОДЕ эскалации ≠ «атака не пробила» (FR-011, SC-005):
    # уже полученные результаты сохранены в runs/ и отчёт собран, но код — 1.
    if campaign.attacker_error is not None:
        print(f"[FATAL] сбой атакующей LLM в онлайн-эскалации: {campaign.attacker_error}", file=sys.stderr)
        return 1
    return 0


def _online_attacker_config(args: argparse.Namespace, scenario):
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
        print(warn, file=sys.stderr)
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
    return asyncio.run(_run_campaign(args, default_repetitions=1))


def cmd_campaign(args: argparse.Namespace) -> int:
    return asyncio.run(_run_campaign(args, default_repetitions=args.iterations or 5))


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
    единственный пишет."""
    from memnotsafe.core.models import AttackResult, CampaignResult

    raw = json.loads((Path(input_dir) / "campaign.json").read_text(encoding="utf-8"))
    results = [
        AttackResult(
            run_id=raw["run_id"],
            case_id=r["case_id"],
            attack_id=r["attack_id"],
            scenario_id=raw["scenario_id"],
            stages=[_stage_from_dict(s) for s in r["stages"]],
            success=r["success"],
            metrics={},
            evidence=r["evidence"],
            attacker_user_id=r["attacker_user_id"],
            victim_user_id=r["victim_user_id"],
        )
        for r in raw["results"]
    ]
    return CampaignResult(
        run_id=raw["run_id"], scenario_id=raw["scenario_id"], attempts=raw["attempts"],
        results=results, aggregate_metrics=raw["aggregate_metrics"],
    )


def cmd_report(args: argparse.Namespace) -> int:
    input_dir = Path(args.input)
    campaign_json = input_dir / "campaign.json"
    if not campaign_json.exists():
        print(f"[FATAL] {campaign_json} не найден — сначала запусти run/campaign", file=sys.stderr)
        return 1

    campaign = load_campaign(input_dir)

    report_dir, html_name = _resolve_report_dir(args.output)
    write_json_reports(campaign, report_dir)
    findings = build_findings(campaign.results)
    write_sarif(findings, report_dir / "findings.sarif")
    events = read_events_jsonl(input_dir / "events.jsonl")
    by_case: dict[str, list[dict]] = {}
    for e in events:
        by_case.setdefault(e.get("case_id", ""), []).append(e)
    html_path = write_html_report(campaign, report_dir / html_name, by_case)
    _print_summary(campaign, html_path)
    return 0


def cmd_judge_calibrate(args: argparse.Namespace) -> int:
    """Измерение судьи на размеченном наборе (US3, FR-010).

    Команда НЕ поднимает адаптер и не пишет в runs/: таргет ей не нужен, она
    работает по сохранённым текстам. `exit 1` при `--gate` — не сбой
    инструмента, а вердикт «этому судье нельзя доверять боевой прогон»."""
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
            print("[FATAL] --from-run требует --out <jsonl>", file=sys.stderr)
            return 1
        cases = build_dataset_from_run(Path(args.from_run))
        path = write_dataset(cases, Path(args.out))
        print(f"Собрано случаев: {len(cases)} -> {path}")
        by_stage: dict[str, int] = {}
        for c in cases:
            by_stage[c.stage] = by_stage.get(c.stage, 0) + 1
        for stage, n in sorted(by_stage.items()):
            print(f"  {stage:<16} {n}")
        return 0

    if not args.dataset:
        print("[FATAL] нужен --dataset <jsonl> или --from-run <runs/dir>", file=sys.stderr)
        return 1

    spec = JudgeSpec(
        enabled=True,
        model=args.judge_model,
        min_confidence=args.min_confidence,
    )
    try:
        validate_judge_spec(spec, "judge-calibrate")
    except RunnerError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
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
    _print_calibration(report, output)

    # --gate: exit 1 — это вердикт о судье, а не падение инструмента.
    if args.gate and not report["gate_passed"]:
        print("\n[GATE] Судья не допущен к боевому прогону.", file=sys.stderr)
        return 1
    return 0


def _print_calibration(r: dict, output: Path) -> None:
    print("=" * 50)
    print("JUDGE CALIBRATION")
    print("=" * 50)
    print(f"Модель:  {r['model']}")
    print(f"Набор:   {r['dataset']}  (случаев: {r['total']}, порог: {r['min_confidence']})")
    rate = r["agreement_rate"]
    print(f"\nСОГЛАСИЕ         {rate if rate is not None else 'н/д'}"
          f"  (нужно >= {0.90})")
    print(f"ЛОЖНОПОЛОЖИТ.    {r['false_positives']}  (нужно 0)")
    print(f"ЛОЖНООТРИЦАТ.    {r['false_negatives']}")
    print(f"БЕЗ ВЕРДИКТА     {r['undecided']}")
    print(f"INJECTION FLIPS  {r['injection_flips']}  (нужно 0)")
    print("\nПо стадиям:")
    for stage, c in r["by_stage"].items():
        print(f"  {stage:<16} согласие {c['agreement_rate']}  fp={c['false_positives']}  "
              f"fn={c['false_negatives']}  без вердикта={c['undecided']}  (n={c['total']})")
    if r["disagreements"]:
        print(f"\nРасхождения ({len(r['disagreements'])}):")
        for d in r["disagreements"][:10]:
            print(f"  {d['case_id']:<40} {d['stage']:<16} истина={d['truth']} "
                  f"вердикт={d['outcome']} conf={d['confidence']}"
                  + (f" [{d['error']}]" if d["error"] else ""))
    if r["injection_details"]:
        print(f"\nПеревороты под инъекцией ({len(r['injection_details'])}):")
        for f in r["injection_details"]:
            print(f"  {f['case_id']:<40} {f['injection_class']:<22} "
                  f"{f['clean_outcome']} -> {f['injected_outcome']}")
    print(f"\nГЕЙТ: {'ПРОЙДЕН' if r['gate_passed'] else 'НЕ ПРОЙДЕН'}")
    print(f"Отчёт: {output}")
    print("=" * 50)


def cmd_replay(args: argparse.Namespace) -> int:
    input_dir = Path(args.input)
    trace_path = input_dir / "traces" / f"{args.case}.json"
    if not trace_path.exists():
        print(f"[FATAL] трасса не найдена: {trace_path}", file=sys.stderr)
        return 1
    events = json.loads(trace_path.read_text(encoding="utf-8"))
    for e in events:
        print(f"{e['timestamp']}  {e['event']:<18} actor={e['actor']:<8} tool={e.get('tool') or '-':<32} args={e.get('arguments')}")
    return 0


def _print_summary(campaign, html_path: Path) -> None:
    m = campaign.aggregate_metrics
    print("=" * 50)
    print("AGENTIC MEMORY RED TEAMING")
    print("=" * 50)
    print(f"Scenario: {campaign.scenario_id}")
    print(f"Attempts: {campaign.attempts}\n")
    for stage in ("write", "persistence", "retrieval", "adoption", "tool", "external_effect"):
        c = m["funnel"][stage]
        print(f"{stage.upper():<14} {c['pass']}/{c['total']} pass ({c['unknown']} unknown)")
    asr = m["end_to_end_asr"]
    print(f"\nEND-TO-END ASR: {asr * 100:.0f}%" if asr is not None else "\nEND-TO-END ASR: н/д")
    print(f"Successful: {m['successful']}/{m['attempts']}")
    _print_judge_summary(m)
    print(f"\nReport:\n{html_path}")
    print("=" * 50)


def _print_judge_summary(m: dict) -> None:
    """Строки судьи печатаются ТОЛЬКО при активном судье: при выключенном
    вывод побитово прежний (FR-013). Отдельная строка про недоступность нужна,
    чтобы исход не читался как «атака не прошла» (FR-020)."""
    j = m.get("judge") or {}
    if not j.get("active"):
        return

    print(f"\nJUDGE          model={j.get('model')}  calls={j.get('calls_used')}/{j.get('calls_limit')}"
          + ("  БЮДЖЕТ ИСЧЕРПАН" if j.get("budget_exhausted") else ""))

    rate = m.get("judge_disagreement_rate")
    decided = (j.get("confirmed") or 0) + (j.get("refuted") or 0)
    if rate is not None:
        print(f"DISAGREEMENT   {j.get('disagreements')}/{decided} стадий "
              f"({rate * 100:.0f}%) — маркерные правила расходятся с судьёй")

    unavailable = j.get("unavailable") or 0
    if unavailable:
        print(f"JUDGE          НЕДОСТУПЕН на {unavailable} стадиях — "
              f"находки помечены INCONCLUSIVE, это не отрицательный результат атаки")


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
        print(f"[FATAL] {exc}", file=sys.stderr)
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
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 1

    out = write_corpus(corpus, args.out)
    prov = corpus.provenance
    print(f"Корпус сохранён: {out}")
    print(f"  профиль: {prov.profile_id} (sha256 {prov.profile_sha256[:12]}…)")
    print(f"  классы:  {', '.join(prov.attack_classes) or '—'}")
    print(f"  записей: {len(corpus.records)}; вызовов атакующей LLM: {prov.attacker_calls}")
    return 0


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
    pp.set_defaults(func=cmd_probe)

    pr = sub.add_parser("run", help="один прогон атаки (repetitions=1)")
    pr.add_argument("--target", default=None)
    pr.add_argument("--scenario", required=True)
    pr.add_argument("--output", required=True)
    pr.add_argument("--iterations", type=int, default=None)
    _add_online_flags(pr)
    _add_attacker_flags(pr)
    _add_judge_flags(pr)
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("campaign", help="N повторов атаки с агрегацией метрик")
    pc.add_argument("--target", default=None)
    pc.add_argument("--scenario", required=True)
    pc.add_argument("--output", required=True)
    pc.add_argument("--iterations", type=int, default=5)
    _add_online_flags(pc)
    _add_attacker_flags(pc)
    _add_judge_flags(pc)
    pc.set_defaults(func=cmd_campaign)

    pgen = sub.add_parser("generate", help="precompute-генерация корпуса атак под профиль (US1)")
    pgen.add_argument("--profile", required=True, help="путь к файлу-профилю агента")
    pgen.add_argument("--classes", default=None, help="каталог/файл описаний классов (по умолчанию attack_classes/)")
    pgen.add_argument("--out", required=True, help="куда сохранить корпус (corpora/<name>.yaml)")
    _add_attacker_flags(pgen)
    pgen.set_defaults(func=cmd_generate)

    prep = sub.add_parser("report", help="пересобрать report.html/.json из сохранённого runs/<name>")
    prep.add_argument("--input", required=True)
    prep.add_argument("--output", required=True)
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
    pcal.set_defaults(func=cmd_judge_calibrate)

    prepl = sub.add_parser("replay", help="напечатать причинную трассу одного case")
    prepl.add_argument("--input", required=True)
    prepl.add_argument("--case", required=True)
    prepl.set_defaults(func=cmd_replay)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
