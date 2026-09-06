"""src/memnotsafe/core/campaign.py — повторяет один сценарий N раз, каждый прогон
изолирован (reset -> baseline -> attack -> save, без self-reinforcement
между попытками, если сценарий явно не просит обратного). Пишет полную
структуру runs/<name>/ — единственное место, которое знает эту
раскладку файлов; report/ читает её обратно, не полагаясь на in-memory объекты.
"""

from __future__ import annotations

import json
from pathlib import Path

from memnotsafe.adapters.base import TargetAdapter
from memnotsafe.attacks.base import AttackContext, get_attack
from memnotsafe.core.config import Scenario
from memnotsafe.core.models import AttackResult, CampaignResult
from memnotsafe.core.runner import RunnerError, new_case_id, new_run_id, run_attack
from memnotsafe.reporting.metrics import aggregate_metrics
from memnotsafe.reporting.proof import build_proof
from memnotsafe.tracing.recorder import TraceRecorder


class Campaign:
    def __init__(self, scenario: Scenario, target: TargetAdapter, output_dir: str | Path, *, judge=None):
        self.scenario = scenario
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Судья конструируется здесь и живёт на кампанию, а не на случай:
        # бюджет вызовов считается за кампанию (FR-012). При выключенном судье
        # объект не создаётся, каталог judge/ не появляется, сеть не трогается.
        self.judge = judge if judge is not None else self._build_judge()

    def _build_judge(self):
        spec = self.scenario.judge
        if not spec.enabled:
            return None
        from memnotsafe.judge.runtime import LLMJudge

        return LLMJudge(
            spec,
            repetitions=self.scenario.repetitions,
            artifacts_dir=self.output_dir / "judge",
        )

    async def run(self, repetitions: int | None = None) -> CampaignResult:
        repetitions = repetitions or self.scenario.repetitions
        run_id = new_run_id()
        attack_cls = get_attack(self.scenario.attack_family)
        attack = attack_cls()

        recorder = TraceRecorder(
            events_path=self.output_dir / "events.jsonl",
            traces_dir=self.output_dir / "traces",
        )
        evidence_dir = self.output_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        cases_path = self.output_dir / "cases.jsonl"
        baseline_path = self.output_dir / "baseline.json"

        results: list[AttackResult] = []
        baselines: list[dict] = []
        for attempt in range(1, repetitions + 1):
            case_id = new_case_id(attack.metadata.id, attempt)
            ctx = AttackContext(
                attacker_user_id=self.scenario.attacker.user_id,
                victim_user_id=self.scenario.victim.user_id,
                run_seed=attempt,
                case_id=case_id,
            )
            try:
                result = await run_attack(
                    attack, ctx, self.target, run_id=run_id, recorder=recorder, judge=self.judge
                )
            except RunnerError:
                raise  # раннер-ошибка — не глотаем, CLI обязан вернуть exit 1

            results.append(result)
            baselines.append({"case_id": case_id, "response": result.evidence.get("baseline_response")})

            with cases_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(_case_summary(result), ensure_ascii=False) + "\n")
            (evidence_dir / f"{case_id}-before.json").write_text(
                json.dumps(result.evidence.get("before"), ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (evidence_dir / f"{case_id}-after.json").write_text(
                json.dumps(result.evidence.get("after"), ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (evidence_dir / f"{case_id}-diff.json").write_text(
                json.dumps(result.evidence.get("diff"), ensure_ascii=False, indent=2), encoding="utf-8"
            )
            if result.success:
                # Proof artifact — только для подтверждённых находок:
                # достаточно, чтобы предъявить/воспроизвести finding без повторного
                # прогона и без поиска по всему run'у.
                proof = build_proof(result, scenario_id=self.scenario.id, trace_events=recorder.case_events(case_id))
                (evidence_dir / f"{case_id}-proof.json").write_text(
                    json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8"
                )

            # Ранний выход по бюджету N (FR-013): конфиг-управляемый, target-agnostic,
            # по умолчанию выключен → mock-демо и офлайн-тесты считают все N как раньше.
            if self.scenario.stop_on_success and result.success:
                break

        baseline_path.write_text(json.dumps(baselines, ensure_ascii=False, indent=2), encoding="utf-8")

        aggregate = aggregate_metrics(
            results, judge_metadata=self.judge.metadata() if self.judge is not None else None
        )
        campaign_result = CampaignResult(
            run_id=run_id,
            scenario_id=self.scenario.id,
            attempts=len(results),
            results=results,
            aggregate_metrics=aggregate,
        )
        (self.output_dir / "campaign.json").write_text(
            json.dumps(
                _campaign_to_dict(campaign_result, self._run_metadata(run_id, len(results))),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return campaign_result

    def _run_metadata(self, run_id: str, attempts: int) -> dict:
        """Метаданные прогона для campaign.json (FR-007/FR-012, data-model §7).
        run_metadata() — опциональное расширение контракта адаптера (duck-typed,
        не target-specific ветвление в ядре): mock его не имеет → поля null."""
        run_meta = self.target.run_metadata() if hasattr(self.target, "run_metadata") else {}
        return {
            "run_id": run_id,
            "adapter": self.scenario.target.adapter,
            "target": run_meta.get("target") or self.scenario.target.base_url or self.scenario.target.adapter,
            "reset_available": run_meta.get("reset_available"),
            "evidence_channel": run_meta.get("evidence_channel"),
            "attempts": attempts,
            # Роль судьи в прогоне. При неактивном судье — РОВНО {"active": false}:
            # ни модели, ни рубрик, ни нулевых счётчиков, которые читались бы как
            # «судья работал и ничего не нашёл» (FR-013).
            "judge": self.judge.metadata() if self.judge is not None else {"active": False},
        }


def _stage_to_dict(s) -> dict:
    """Сериализация стадии с провенансом (contracts/report-provenance.md).

    Ни одно существующее поле не переименовано и не удалено — только добавлены
    новые. При выключенном судье `judge` и `deterministic` равны null, а
    `verdict_source` — "deterministic": отчёт остаётся читаемым тем же кодом,
    что читал его до фичи."""
    return {
        "stage": s.stage,
        "success": s.success,
        "reason": s.reason,
        "evidence": s.evidence,
        "confidence": s.confidence,
        "verdict_source": s.verdict_source,
        "evidence_kind": s.evidence_kind,
        "disagreement": s.disagreement,
        "deterministic": s.deterministic.to_dict() if s.deterministic else None,
        "judge": s.judge.to_dict() if s.judge else None,
    }


def _case_summary(result: AttackResult) -> dict:
    return {
        "case_id": result.case_id,
        "attack_id": result.attack_id,
        "success": result.success,
        "stages": {s.stage: s.success for s in result.stages},
        "attacker_user_id": result.attacker_user_id,
        "victim_user_id": result.victim_user_id,
    }


def _campaign_to_dict(cr: CampaignResult, metadata: dict | None = None) -> dict:
    return {
        "run_id": cr.run_id,
        "scenario_id": cr.scenario_id,
        "attempts": cr.attempts,
        "metadata": metadata or {},
        "aggregate_metrics": cr.aggregate_metrics,
        "results": [
            {
                "case_id": r.case_id,
                "attack_id": r.attack_id,
                "success": r.success,
                "stages": [_stage_to_dict(s) for s in r.stages],
                "attacker_user_id": r.attacker_user_id,
                "victim_user_id": r.victim_user_id,
                "evidence": r.evidence,
            }
            for r in cr.results
        ],
    }
