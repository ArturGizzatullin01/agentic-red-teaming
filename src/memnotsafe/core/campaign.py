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
from collections.abc import Callable, Iterator
from pathlib import Path

from memnotsafe.adapters.base import TargetAdapter
from memnotsafe.attacks.base import AttackBase, AttackContext, get_attack
from memnotsafe.core.attempt import (
    OUTCOME_BUDGET_EXHAUSTED,
    OUTCOME_REGISTERED,
    OUTCOME_TRANSPORT_ERROR,
    AttemptHistory,
    outcome_of_result,
    sessions_from_transcript,
)
from memnotsafe.core.campaign_backend import campaign_backend
from memnotsafe.core.campaign_construction import CampaignConstructionMixin
from memnotsafe.core.campaign_escalation import CampaignEscalationMixin
from memnotsafe.core.campaign_persistence import CampaignPersistenceMixin
from memnotsafe.core.campaign_serialize import campaign_to_dict as _campaign_to_dict
from memnotsafe.core.campaign_trace import ExportingRecorder as _ExportingRecorder
from memnotsafe.core.config import Scenario
from memnotsafe.core.goal_contract import goal_digest_or_none
from memnotsafe.core.ledger import (
    OP_JUDGE_LLM,
    OP_TARGET_CALL,
    PHASE_EXECUTED,
    PHASE_UNKNOWN_OUTCOME,
    BudgetLedger,
)
from memnotsafe.core.models import AttackResult, CampaignResult
from memnotsafe.core.runner import RunnerError, new_case_id, new_run_id, run_attack
from memnotsafe.reporting.metrics import aggregate_metrics
from memnotsafe.tracing.langfuse_sink import build_langfuse_exporter
from memnotsafe.tracing.recorder import TraceRecorder

# Происхождение атаки в провенансе (FR-013). Рукописный пак / заранее
# сгенерированный корпус / онлайн-адаптация — читает reporting/findings.py.
ORIGIN_HANDWRITTEN = "handwritten"
ORIGIN_CORPUS = "corpus"
ORIGIN_ONLINE = "online"


class Campaign(CampaignConstructionMixin, CampaignEscalationMixin, CampaignPersistenceMixin):
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
        clock: Callable[[], float] | None = None,
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
        # P10b (фича 007): experiment_id появляется в run() и связывает пакеты
        # доказательств и историю попыток с конфигурацией эксперимента.
        self.experiment_id: str | None = None
        # CARD-CAMPAIGN-CLOCK: источник времени таймеров P12, проводится в
        # каждый вызов run_attack. None (дефолт) — run_attack сам резолвит в
        # time.perf_counter: продукционное поведение не меняется; в артефакты
        # clock не пишется. Только программный слой — без CLI/конфига.
        self._clock = clock

    async def run(self, repetitions: int | None = None) -> CampaignResult:
        repetitions = repetitions or self.scenario.repetitions
        run_id = new_run_id()

        # P10b (фича 007): конфигурация эксперимента фиксируется ДО первого
        # случая — experiment_id свяжет пакеты доказательств и историю попыток
        # с этой конфигурацией. Летучие поля и секреты в digest не входят.
        from memnotsafe.core.experiment import build_experiment_spec, write_experiment

        # P09-full: версия стенда — duck-typed наблюдение (факты адаптера);
        # в volatile, на digest не влияет.
        stand_version: str | None = None
        facts_getter = getattr(self.target, "context_tool_evidence", None)
        if callable(facts_getter):
            try:
                stand_version = facts_getter().get("stand_version")
            except Exception:  # noqa: BLE001 — телеметрия среды не роняет прогон
                stand_version = None

        spec = build_experiment_spec(
            self.scenario,
            attacker_config=self.attacker_config,
            online=self.online,
            online_attempts=self.online_attempts,
            stand_version=stand_version,
        )
        self.experiment_id = spec.experiment_id
        write_experiment(self.output_dir, spec)

        # P10b (фича 007): полная история попыток — кандидаты, rewrite,
        # транспортные ошибки, бюджетные стопы. Метрики не меняются (см.
        # докстринг core/attempt.py о связи с ASR).
        history = AttemptHistory(
            self.output_dir / "attempts.jsonl", experiment_id=self.experiment_id, run_id=run_id
        )
        # P10b: леджер расходов — наблюдатель существующих бюджетов; решений
        # о лимитах не принимает (см. докстринг core/ledger.py).
        ledger = BudgetLedger(
            self.output_dir / "budget-ledger.jsonl", experiment_id=self.experiment_id, run_id=run_id
        )

        recorder = TraceRecorder(
            events_path=self.output_dir / "events.jsonl",
            traces_dir=self.output_dir / "traces",
        )
        # P11-3: экспорт трасс — за env-флагом, в точке сборки recorder.
        # Без MEMNOTSAFE_TRACE_EXPORT=1 — ноль изменений: сборщик возвращает
        # None, recorder остаётся тем же объектом (локальный JSONL — источник
        # истины, пишется первым и полностью). С флагом каждое событие
        # дублируется в exporter.record() (маска на входе — P11-2; сбой
        # доставки уходит в спул — P11-1); поведение прогона не меняется.
        exporter = build_langfuse_exporter(self.output_dir / "trace-export-spool")
        if exporter is not None:
            recorder = _ExportingRecorder(recorder, exporter)
        evidence_dir = self.output_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        cases_path = self.output_dir / "cases.jsonl"
        baseline_path = self.output_dir / "baseline.json"

        results: list[AttackResult] = []
        baselines: list[dict] = []
        for attack, ctx, provenance in self._plan_cases(repetitions):
            # Требование маркера включает и сценарий, и заявку самой записи
            # корпуса (record.case_marker): токен записи, не дошедший до
            # доставки, иначе тихо ушёл бы в legacy-settle по первым 60
            # символам payload (P04). Рукописные атаки не проверяются —
            # у них предзаданный case_marker не обязан быть в тексте (opt-in
            # 005, test_system_log_case_marker_is_opt_in).
            require_marker = self.scenario.require_case_marker or self._record_declares_marker(ctx)
            # История: кандидат зарегистрирован до обращения к target.
            history.record(
                case_id=ctx.case_id,
                candidate_id=ctx.case_id,
                outcome=OUTCOME_REGISTERED,
                attempt_no=0,
                case_marker=ctx.case_marker,
                goal_digest=goal_digest_or_none(attack.expected_effect(ctx)),
                seed=ctx.run_seed,
            )
            try:
                result = await run_attack(
                    attack, ctx, self.target, run_id=run_id, recorder=recorder, judge=self.judge,
                    require_case_marker=require_marker,
                    clock=self._clock,
                )
            except RunnerError as exc:
                # Транспортный сбой target: в историю как transport_error
                # (повтор той же попытки не создаёт нового кандидата), затем
                # НЕ глотаем — CLI обязан вернуть exit 1 (exit-контракт).
                ledger.record(
                    OP_TARGET_CALL, PHASE_UNKNOWN_OUTCOME,
                    case_id=ctx.case_id, candidate_id=ctx.case_id,
                    attempt_no=1, error=str(exc),
                )
                history.record(
                    case_id=ctx.case_id,
                    candidate_id=ctx.case_id,
                    outcome=OUTCOME_TRANSPORT_ERROR,
                    attempt_no=1,
                    case_marker=ctx.case_marker,
                    seed=ctx.run_seed,
                    error=str(exc),
                )
                raise  # раннер-ошибка — не глотаем, CLI обязан вернуть exit 1

            ledger.record(
                OP_TARGET_CALL, PHASE_EXECUTED,
                case_id=ctx.case_id, candidate_id=ctx.case_id, attempt_no=1,
            )
            history.record(
                case_id=ctx.case_id,
                candidate_id=ctx.case_id,
                outcome=outcome_of_result(result),
                attempt_no=1,
                case_marker=result.evidence.get("case_marker") or ctx.case_marker,
                goal_digest=goal_digest_or_none((result.evidence.get("candidate") or {}).get("expected_effect")),
                seed=ctx.run_seed,
                session_ids=sessions_from_transcript(result.evidence.get("transcript")),
                # P12: стадийные таймеры попытки едут в строку исхода
                # аддитивным полем (раннер их уже посчитал).
                timing=result.evidence.get("timing"),
            )
            # P10a (фикс приёмки): пакет доказательств — на КАЖДУЮ попытку на
            # target, а не только на финальный результат: начальная попытка
            # получает свой bundle здесь, повторы эскалации — через
            # bundle_writer в цикле эскалации (attempt_no/parent совпадают с
            # историей попыток).
            self._write_evidence_bundle(
                result, recorder,
                logical_case=ctx.case_id, candidate_id=ctx.case_id,
                parent_candidate_id=None, attempt_no=1, history=history,
            )

            # Провенанс происхождения — слоем кампании, а не раннером (research §12).
            # Заметки телеметрии P09-full (context_tool_evidence_error), уже
            # лежащие в evidence.provenance, не затираются — сливаются аддитивно.
            prov_final = dict(provenance)
            prov_final.update({
                k: v for k, v in (result.evidence.get("provenance") or {}).items()
                if k not in prov_final
            })
            result.evidence["provenance"] = prov_final

            # Онлайн-эскалация (US2): вокруг немодифицированного run_attack. При
            # выключенном онлайн-уровне возвращает result как есть (SC-003).
            def _bundle_writer(res, candidate, parent, attempt_no, _ctx=ctx, _rec=recorder, _h=history):
                self._write_evidence_bundle(
                    res, _rec,
                    logical_case=_ctx.case_id, candidate_id=candidate,
                    parent_candidate_id=parent, attempt_no=attempt_no, history=_h,
                )

            result = await self._maybe_escalate(
                attack, ctx, result, run_id=run_id, recorder=recorder, require_case_marker=require_marker,
                history=history, ledger=ledger, bundle_writer=_bundle_writer,
            )

            if (result.evidence.get("provenance") or {}).get("budget_exhausted"):
                # Штатный стоп по бюджету атакующей LLM — в историю (не в ASR).
                history.record(
                    case_id=ctx.case_id,
                    candidate_id=result.case_id,
                    outcome=OUTCOME_BUDGET_EXHAUSTED,
                    attempt_no=0,
                )

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
        if hasattr(self.target, "acollect_run_observations"): await self.target.acollect_run_observations()
        (self.output_dir / "campaign.json").write_text(
            json.dumps(
                _campaign_to_dict(campaign_result, self._run_metadata(run_id, len(results))),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        # P10b: judge-расход за кампанию — summary-записью, сверяемой с
        # JudgeBudget (ledger не списывает сам, расхождений нет).
        judge_budget = getattr(self.judge, "budget", None) if self.judge is not None else None
        if judge_budget is not None:
            ledger.record(
                OP_JUDGE_LLM, PHASE_EXECUTED,
                usage={"calls_used": judge_budget.used, "calls_limit": judge_budget.limit},
                note="summary",
            )
        # P11-3: финальная попытка доставки экспорта. flush() исключений не
        # бросает; недоставленное остаётся в спуле (output_dir/
        # trace-export-spool) — прогресс и артефакты прогона от этого не
        # зависят, локальный evidence уже полный.
        if exporter is not None:
            exporter.flush()
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
        backend = campaign_backend()

        if not self.scenario.corpus_path:
            raise RunnerError(
                f"Сценарий {self.scenario.id}: family=generated требует attack.corpus (путь к корпусу)"
            )
        corpus = backend.read_corpus(self.scenario.corpus_path)
        records = backend.valid_records(corpus)
        corpus_id = corpus.provenance.profile_id or Path(self.scenario.corpus_path).stem

        n = 0
        for attempt in range(1, repetitions + 1):
            for record in records:
                n += 1
                attack = backend.new_generated_attack()  # свежий экземпляр: metadata подменяется в generate()
                case_id = new_case_id(record.attack_class, n)
                ctx = AttackContext(
                    attacker_user_id=self.scenario.attacker.user_id,
                    victim_user_id=self.scenario.victim.user_id,
                    run_seed=attempt,
                    case_id=case_id,
                    params=backend.new_generated_case_params(record.to_dict(), corpus_id),
                    # Маркер, заявленный записью, едет в контекст ДО раннера:
                    # None → раннер выведет CM-<6hex> из case_id (плейсхолдер
                    # {case_marker} подставит GeneratedAttack). Раннер требует
                    # фактического присутствия заявленного маркера в доставке.
                    case_marker=record.case_marker,
                )
                provenance = {
                    "origin": ORIGIN_CORPUS,
                    "attack_class": record.attack_class,
                    "corpus_id": corpus_id,
                }
                yield attack, ctx, provenance

    # ------------------------------------------------------------------ онлайн-эскалация

    @staticmethod
    def _record_declares_marker(ctx: AttackContext) -> bool:
        """Запись корпуса в params заявила собственный маркер (P04)."""
        raw = (ctx.params or {}).get("record")
        return isinstance(raw, dict) and raw.get("case_marker") is not None

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
            "target_sampling": run_meta.get("target_sampling"),
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
