"""cli.py — точка входа. CLI/скрипт, без веб-UI/MCP (по решению кейсодателя).

Команды:
  python cli.py list                          — какие атаки подхватились из attacks/
  python cli.py run <attack_id> [--victim ID --witness ID --session ID --seed N]
  python cli.py run-all [--victim ID --witness ID]   — прогнать все паки + их variants()
  python cli.py reload                         — сбросить и заново просканировать attacks/
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import yaml

import attacks_loader
from adapters.genai_invest_stand import MongoEvidenceSource, MongoEvidenceSourceConfig
from core.attack_base import AttackContext
from core.llm_client import LLMClient, LLMClientConfig
from core.report import human_summary, write_json_report
from core.runner import run_attack
from core.target import TargetConfig, TargetPool
from core.tracer import CompositeTracer


def _load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _build_target_pool(cfg: dict) -> TargetPool:
    t = cfg["target"]
    configs = {}
    for user_id, identity in cfg["identities"].items():
        configs[user_id] = TargetConfig(
            base_url=t["base_url"],
            api_key_env=identity["api_key_env"],
            chat_path=t.get("chat_path", "/v1/chat/completions"),
            finalize_path_template=t.get("finalize_path_template"),
            finalize_via_chat_keyword=t.get("finalize_via_chat_keyword"),
            request_extra_fields=t.get("request_extra_fields", {}),
            timeout_s=t.get("timeout_s", 60),
            retries=t.get("retries", 2),
        )
    return TargetPool(configs)


def _build_evidence_source(cfg: dict) -> MongoEvidenceSource:
    e = cfg["evidence"]
    if e.get("adapter", "mongo_direct") != "mongo_direct":
        raise NotImplementedError(f"Адаптер {e.get('adapter')!r} пока не реализован.")
    return MongoEvidenceSource(MongoEvidenceSourceConfig(mongo_uri=e["mongo_uri"], mongo_db=e["mongo_db"]))


def _build_llm(cfg: dict, role: str) -> LLMClient:
    r = cfg[role]
    kwargs = dict(
        base_url=r["base_url"], api_key_env=r["api_key_env"], model=r["model"],
        temperature=r.get("temperature", 0.0), auth_scheme=r.get("auth_scheme", "Bearer"),
    )
    if "max_tokens" in r:
        kwargs["max_tokens"] = r["max_tokens"]
    return LLMClient(LLMClientConfig(**kwargs))


async def _run_many(attack_classes: list, ctx: AttackContext, cfg: dict) -> None:
    """Прогнать один или несколько паков (каждый — со своими variants()) на общих
    target/evidence/judge/tracer, собрать ОДИН отчёт. Используется и `run` (список из
    одного класса), и `run-all` (весь реестр) — не дублируем оркестрацию прогона."""
    targets = _build_target_pool(cfg)
    evidence_source = _build_evidence_source(cfg)
    judge_llm = _build_llm(cfg, "judge")
    tracer = CompositeTracer(traces_dir=cfg.get("traces_dir", "traces"))

    results = []
    try:
        for attack_cls in attack_classes:
            attack = attack_cls()
            for variant_ctx in attack.variants(ctx):
                result = await run_attack(
                    attack, variant_ctx,
                    targets=targets, evidence_source=evidence_source,
                    judge_llm=judge_llm, tracer=tracer,
                )
                results.append((result, attack.metadata))
    finally:
        await targets.aclose()
        await judge_llm.aclose()
        evidence_source.close()

    report_path = write_json_report(results, cfg.get("report_path", "reports/latest.json"))
    print(human_summary(results))
    print(f"\nJSON-отчёт: {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic memory red-teaming tool (Команда 7)")
    parser.add_argument("--config", default="config.yaml", help="путь к config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="список подхваченных атак")

    run_p = sub.add_parser("run", help="прогнать одну атаку")
    run_p.add_argument("attack_id")
    run_p.add_argument("--victim", default="1001")
    run_p.add_argument("--witness", default="1002")
    run_p.add_argument("--session", default=None)
    run_p.add_argument("--seed", type=int, default=42)

    run_all_p = sub.add_parser("run-all", help="прогнать ВСЕ подхваченные атаки (+их variants())")
    run_all_p.add_argument("--victim", default="1001")
    run_all_p.add_argument("--witness", default="1002")
    run_all_p.add_argument("--session", default=None)
    run_all_p.add_argument("--seed", type=int, default=42)

    sub.add_parser("reload", help="сбросить реестр и заново просканировать attacks/")

    args = parser.parse_args()

    if not Path(args.config).exists() and args.command != "list":
        print(f"Конфиг {args.config} не найден — скопируй config.example.yaml -> config.yaml "
              f"и заполни ENV-имена ключей.", file=sys.stderr)

    if args.command == "list":
        registry = attacks_loader.discover()
        if not registry:
            print("Атак не найдено — проверь, что attacks/ содержит паки с AttackBase-подклассами.")
            return
        for attack_id, cls in sorted(registry.items()):
            m = cls.metadata
            print(f"{attack_id:45s} {m.channel.value:16s} {m.mpbench_class.value:32s} {m.signal_strength.value}")
        return

    if args.command == "reload":
        registry = attacks_loader.reload()
        print(f"Перезагружено: {len(registry)} атак(и).")
        return

    if args.command in ("run", "run-all"):
        cfg = _load_config(args.config)
        if args.command == "run":
            attack_classes = [attacks_loader.load(args.attack_id)]
        else:
            registry = attacks_loader.discover()
            if not registry:
                print("Атак не найдено — нечего прогонять.", file=sys.stderr)
                return
            attack_classes = list(registry.values())
        session_id = args.session or f"attack-{uuid.uuid4().hex[:8]}"
        ctx = AttackContext(
            victim_user_id=args.victim,
            session_id=session_id,
            run_seed=args.seed,
            witness_user_id=args.witness,
        )
        asyncio.run(_run_many(attack_classes, ctx, cfg))
        return


if __name__ == "__main__":
    main()
