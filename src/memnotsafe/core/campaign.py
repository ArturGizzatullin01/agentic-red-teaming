"""src/memnotsafe/core/campaign.py — повторяет один сценарий N раз, каждый прогон
изолирован (reset -> baseline -> attack -> save, без self-reinforcement
между попытками, если сценарий явно не просит обратного). Пишет полную
структуру runs/<name>/ — единственное место, которое знает эту
раскладку файлов; report/ читает её обратно, не полагаясь на in-memory объекты.

Фича 004 добавляет ДВА аддитивных слоя вокруг немодифицированного `run_attack`
(SC-008): прогон корпуса (family="generated" — каждая валидная запись корпуса
исполняется `GeneratedAttack` через `AttackContext.params`) и онлайн-эскалацию
(при `--online` и неуспехе атака переписывается атакующей LLM и пробуется снова).
Провенанс происхождения и стоимости пишется здесь, в `evidence`/`metadata`, —
раннер и модели ядра остаются нетронутыми (research §12).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from memnotsafe.adapters.base import TargetAdapter
from memnotsafe.attacks.base import AttackBase, AttackContext, get_attack
from memnotsafe.core.config import Scenario
from memnotsafe.core.models import AttackResult, CampaignResult
from memnotsafe.core.runner import RunnerError, new_case_id, new_run_id, run_attack
from memnotsafe.reporting.metrics import aggregate_metrics
from memnotsafe.reporting.proof import build_proof
from memnotsafe.tracing.recorder import TraceRecorder

# Происхождение атаки в провенансе (FR-013). Рукописный пак / заранее
# сгенерированный корпус / онлайн-адаптация — читает reporting/findings.py.
ORIGIN_HANDWRITTEN = "handwritten"
ORIGIN_CORPUS = "corpus"
ORIGIN_ONLINE = "online"


class Campaign:
    def __init__(
        self,
        scenario: Scenario,
        target: TargetAdapter,
        output_dir: str | Path,
        *,
        judge=None,
        attacker_config=None,
        online: bool = False,
        online_attempts: int = 5,
    ):
        self.scenario = scenario
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Судья конструируется здесь и живёт на кампанию, а не на случай:
        # бюджет вызовов считается за кампанию (FR-012). При выключенном судье
        # объект не создаётся, каталог judge/ не появляется, сеть не трогается.
        self.judge = judge if judge is not None else self._build_judge()
        # Онлайн-уровень (US2/US3). По умолчанию ВЫКЛ (FR-009): атакующая LLM не
        # инстанцируется, стоимость и поведение совпадают с текущим (SC-003).
        self.attacker_config = attacker_config
        self.online = online
        self.online_attempts = online_attempts
        self._attacker_client = None
        self._budget = None
        self.attacker_calls = 0  # суммарные онлайн-вызовы за прогон (FR-014)
        self.budget_exhausted = False
        # Сбой атакующей LLM в ходе эскалации (FR-011): фиксируется, чтобы CLI
        # вернул exit 1, но уже полученные результаты успели сохраниться (FR-010).
        self.attacker_error: str | None = None

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

    def _ensure_attacker(self):
        """Ленивое создание атакующего клиента и бюджета — только когда онлайн-
        уровень реально включён. Без `--online` этот путь не исполняется (SC-003)."""
        if self._attacker_client is not None:
            return
        from memnotsafe.generation.attacker_client import build_attacker_client
        from memnotsafe.generation.budget import CallBudget
        from memnotsafe.generation.config import AttackerConfig

        config = self.attacker_config or AttackerConfig()
        self.attacker_config = config
        self._attacker_client = build_attacker_client(config)
        self._budget = CallBudget(limit=config.budget)

    async def run(self, repetitions: int | None = None) -> CampaignResult:
        repetitions = repetitions or self.scenario.repetitions
        run_id = new_run_id()

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
        for attack, ctx, provenance in self._plan_cases(repetitions):
            try:
                result = await run_attack(
                    attack, ctx, self.target, run_id=run_id, recorder=recorder, judge=self.judge,
                    require_case_marker=self.scenario.require_case_marker,
                )
            except RunnerError:
                raise  # раннер-ошибка — не глотаем, CLI обязан вернуть exit 1

            # Провенанс происхождения — слоем кампании, а не раннером (research §12).
            result.evidence["provenance"] = dict(provenance)

            # Онлайн-эскалация (US2): вокруг немодифицированного run_attack. При
            # выключенном онлайн-уровне возвращает result как есть (SC-003).
            result = await self._maybe_escalate(attack, ctx, result, run_id=run_id, recorder=recorder)

            self._persist_case(result, recorder, evidence_dir, cases_path)
            results.append(result)
            baselines.append({"case_id": result.case_id, "response": result.evidence.get("baseline_response")})

            # Сбой атакующей LLM в эскалации — прекращаем прогон, но уже собранные
            # результаты сохраняем ниже (FR-010): campaign.json запишется штатно.
            if self.attacker_error is not None:
                break

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

    # ------------------------------------------------------------------ планирование случаев

    def _plan_cases(self, repetitions: int) -> Iterator[tuple[AttackBase, AttackContext, dict]]:
        """Порождает случаи прогона. Для обычной атаки — один класс, N повторов
        (как было). Для family='generated' — каждая валидная запись корпуса как
        отдельный случай через AttackContext.params (research §1)."""
        if self.scenario.attack_family == "generated":
            yield from self._corpus_cases(repetitions)
            return

        attack_cls = get_attack(self.scenario.attack_family)
        attack = attack_cls()
        for attempt in range(1, repetitions + 1):
            case_id = new_case_id(attack.metadata.id, attempt)
            ctx = AttackContext(
                attacker_user_id=self.scenario.attacker.user_id,
                victim_user_id=self.scenario.victim.user_id,
                run_seed=attempt,
                case_id=case_id,
                params=self.scenario.raw.get("params", {}) or {},
            )
            provenance = {"origin": ORIGIN_HANDWRITTEN, "attack_class": self.scenario.attack_family}
            yield attack, ctx, provenance

    def _corpus_cases(self, repetitions: int) -> Iterator[tuple[AttackBase, AttackContext, dict]]:
        from memnotsafe.attacks.generated import PARAM_CORPUS_ID, PARAM_RECORD, GeneratedAttack
        from memnotsafe.generation.corpus import read_corpus, valid_records

        if not self.scenario.corpus_path:
            raise RunnerError(
                f"Сценарий {self.scenario.id}: family=generated требует attack.corpus (путь к корпусу)"
            )
        corpus = read_corpus(self.scenario.corpus_path)
        records = valid_records(corpus)
        corpus_id = corpus.provenance.profile_id or Path(self.scenario.corpus_path).stem

        n = 0
        for attempt in range(1, repetitions + 1):
            for record in records:
                n += 1
                attack = GeneratedAttack()  # свежий экземпляр: metadata подменяется в generate()
                case_id = new_case_id(record.attack_class, n)
                ctx = AttackContext(
                    attacker_user_id=self.scenario.attacker.user_id,
                    victim_user_id=self.scenario.victim.user_id,
                    run_seed=attempt,
                    case_id=case_id,
                    params={PARAM_RECORD: record.to_dict(), PARAM_CORPUS_ID: corpus_id},
                )
                provenance = {
                    "origin": ORIGIN_CORPUS,
                    "attack_class": record.attack_class,
                    "corpus_id": corpus_id,
                }
                yield attack, ctx, provenance

    # ------------------------------------------------------------------ онлайн-эскалация

    async def _maybe_escalate(
        self,
        attack: AttackBase,
        ctx: AttackContext,
        result: AttackResult,
        *,
        run_id: str,
        recorder: TraceRecorder,
    ) -> AttackResult:
        """Онлайн-уровень (US2/US3). Реализация цикла — в core/escalation.py; здесь
        только точка вызова при `--online` и `success=False`. При выключенном
        онлайне (по умолчанию) возвращает result без изменений (SC-003)."""
        if not self.online or result.success:
            return result

        self._ensure_attacker()
        from memnotsafe.core.escalation import escalate
        from memnotsafe.generation.errors import AttackerError

        try:
            outcome = await escalate(
                attack,
                ctx,
                self.target,
                result,
                limit=self.online_attempts,
                client=self._attacker_client,
                budget=self._budget,
                run_id=run_id,
                recorder=recorder,
            )
        except AttackerError as exc:
            # Сбой атакующей LLM ≠ «атака не пробила защиту» (FR-011). Фиксируем
            # ошибку (CLI вернёт exit 1), но возвращаем уже полученный результат —
            # он и всё собранное до него сохранятся в runs/ (FR-010, SC-005).
            self.attacker_error = str(exc)
            self.attacker_calls = self._budget.used if self._budget else self.attacker_calls
            prov = dict(result.evidence.get("provenance") or {})
            prov["attacker_error"] = str(exc)
            result.evidence["provenance"] = prov
            return result

        self.attacker_calls = self._budget.used if self._budget else self.attacker_calls
        if outcome.budget_exhausted:
            self.budget_exhausted = True
        return outcome.result

    # ------------------------------------------------------------------ запись артефактов случая

    def _persist_case(
        self,
        result: AttackResult,
        recorder: TraceRecorder,
        evidence_dir: Path,
        cases_path: Path,
    ) -> None:
        case_id = result.case_id
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
        (evidence_dir / f"{case_id}-transcript.json").write_text(
            json.dumps(result.evidence.get("transcript"), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if result.success:
            # Proof artifact — только для подтверждённых находок:
            # достаточно, чтобы предъявить/воспроизвести finding без повторного
            # прогона и без поиска по всему run'у.
            proof = build_proof(
                result, scenario_id=self.scenario.id, trace_events=recorder.case_events(case_id)
            )
            (evidence_dir / f"{case_id}-proof.json").write_text(
                json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8"
            )

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
            # Стоимость онлайн-уровня (FR-014). При выключенном онлайне — РОВНО
            # {"active": false}: ни вызовов, ни бюджета, которые читались бы как
            # «эскалация работала». Симметрично блоку судьи.
            "attacker": self._attacker_metadata(),
        }

    def _attacker_metadata(self) -> dict:
        if not self.online or self.attacker_config is None:
            return {"active": False}
        return {
            "active": True,
            "provider": self.attacker_config.provider,
            "model": self.attacker_config.model,
            "online_attempts_limit": self.online_attempts,
            "calls_used": self.attacker_calls,
            "budget_limit": self.attacker_config.budget,
            "budget_exhausted": self.budget_exhausted,
        }

    async def aclose_attacker(self) -> None:
        if self._attacker_client is not None:
            await self._attacker_client.aclose()


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
