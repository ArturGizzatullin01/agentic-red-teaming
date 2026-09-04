"""src/memred/cli.py — entrypoint. Ровно четыре обязательные команды + replay.
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

from memred.core.campaign import Campaign
from memred.core.config import build_adapter, load_scenario
from memred.core.runner import RunnerError
from memred.reporting.html_report import write_html_report
from memred.reporting.json_report import write_json_reports
from memred.reporting.sarif import write_sarif
from memred.reporting.findings import build_findings
from memred.tracing.recorder import read_events_jsonl


def _build_target(target_arg: str | None, scenario_path: str | None):
    if scenario_path:
        scenario = load_scenario(scenario_path)
        return scenario, build_adapter(scenario, target_arg)
    from memred.adapters.mock import MockTarget

    if not target_arg or target_arg == "mock":
        return None, MockTarget(vulnerable=True)
    from memred.adapters.openai import OpenAICompatibleAdapter

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


async def _run_campaign(args: argparse.Namespace, *, default_repetitions: int) -> int:
    scenario = load_scenario(args.scenario)
    target = build_adapter(scenario, args.target)
    repetitions = args.iterations if getattr(args, "iterations", None) else default_repetitions

    run_output = Path(args.output)
    campaign = Campaign(scenario, target, run_output)
    try:
        result = await campaign.run(repetitions=repetitions)
    except RunnerError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 1
    finally:
        await target.aclose()

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
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    return asyncio.run(_run_campaign(args, default_repetitions=1))


def cmd_campaign(args: argparse.Namespace) -> int:
    return asyncio.run(_run_campaign(args, default_repetitions=args.iterations or 5))


def cmd_report(args: argparse.Namespace) -> int:
    input_dir = Path(args.input)
    campaign_json = input_dir / "campaign.json"
    if not campaign_json.exists():
        print(f"[FATAL] {campaign_json} не найден — сначала запусти run/campaign", file=sys.stderr)
        return 1

    from memred.core.models import AttackResult, CampaignResult, StageResult

    raw = json.loads(campaign_json.read_text(encoding="utf-8"))
    results = [
        AttackResult(
            run_id=raw["run_id"],
            case_id=r["case_id"],
            attack_id=r["attack_id"],
            scenario_id=raw["scenario_id"],
            stages=[StageResult(stage=s["stage"], success=s["success"], evidence=s["evidence"], reason=s["reason"]) for s in r["stages"]],
            success=r["success"],
            metrics={},
            evidence=r["evidence"],
            attacker_user_id=r["attacker_user_id"],
            victim_user_id=r["victim_user_id"],
        )
        for r in raw["results"]
    ]
    campaign = CampaignResult(
        run_id=raw["run_id"], scenario_id=raw["scenario_id"], attempts=raw["attempts"],
        results=results, aggregate_metrics=raw["aggregate_metrics"],
    )

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
    print(f"\nReport:\n{html_path}")
    print("=" * 50)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="memred", description="Agentic Memory Red Teaming")
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
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("campaign", help="N повторов атаки с агрегацией метрик")
    pc.add_argument("--target", default=None)
    pc.add_argument("--scenario", required=True)
    pc.add_argument("--output", required=True)
    pc.add_argument("--iterations", type=int, default=5)
    pc.set_defaults(func=cmd_campaign)

    prep = sub.add_parser("report", help="пересобрать report.html/.json из сохранённого runs/<name>")
    prep.add_argument("--input", required=True)
    prep.add_argument("--output", required=True)
    prep.set_defaults(func=cmd_report)

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
