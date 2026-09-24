"""src/memnotsafe/core/campaign_persistence.py — ARC-2: запись артефактов случая и
пакет доказательств (персистенс/экспорт, вынесены из core/campaign.py при
расщеплении). Миксин к Campaign: методы работают через `self`
(output_dir/target/scenario/experiment_id — заданы в Campaign.__init__).
Периферию не тянет; поведение и форматы прежние — тела перенесены дословно.
Метаданные прогона (_run_metadata/_attacker_metadata) остались в core/campaign.py
(замок doc↔code sync: контракт адаптера сверяется грепом self.target по
campaign.py).
"""

from __future__ import annotations

import json

from memnotsafe.core.attempt import OUTCOME_EVIDENCE_ERROR, AttemptHistory
from memnotsafe.core.campaign_serialize import case_summary as _case_summary
from memnotsafe.core.goal_contract import goal_digest_or_none
from memnotsafe.core.models import AttackResult
from memnotsafe.core.result_readouts import build_proof
from memnotsafe.tracing.recorder import TraceRecorder


class CampaignPersistenceMixin:
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

    def _write_evidence_bundle(
        self,
        result: AttackResult,
        recorder: TraceRecorder,
        *,
        logical_case: str,
        candidate_id: str,
        parent_candidate_id: str | None,
        attempt_no: int,
        history: AttemptHistory | None = None,
    ) -> None:
        """P10a (фича 007): пакет доказательств для КАЖДОЙ попытки на target
        (фикс приёмки: не только финальный результат) — каталог
        bundles/<candidate_id>, attempt_no/parent_candidate_id согласованы с
        attempts.jsonl. Слоты без телеметрии честно получают unavailable (не
        «доказанное отсутствие»). Сбой записи НЕ роняет прогон (вердикты уже
        сохранены штатно), но НЕ остаётся невидимым: сбой фиксируется в
        attempts.jsonl, а недописанный каталог виден replay через
        verify_run_bundles → exit 1."""
        from memnotsafe.evidence.bundle import write_bundle

        ev = result.evidence
        phases = ev.get("phases") or {}
        candidate = ev.get("candidate") or {}
        tool_events = [e for e in recorder.case_events(candidate_id) if e.get("tool")]
        trace_file = self.output_dir / "traces" / f"{candidate_id}.json"
        # рукописная/нестандартная цель → None: digest не выдумываем
        goal_digest = goal_digest_or_none(candidate.get("expected_effect"))
        # P09-full: слот context_tool_evidence — ФАКТЫ эффективного контекста
        # и аргументов (адаптер/фактические), фазы — из транскрипта раннера.
        # Адаптер без канала → слот не упоминается (absent, «не предусмотрен»);
        # канал есть, данных нет → unavailable; сбой канала → unavailable +
        # причина в provenance. Никакая телеметрия не роняет прогон.
        ctx_tool: dict | None = None
        facts_getter = getattr(self.target, "context_tool_evidence", None)
        if callable(facts_getter):
            from memnotsafe.evidence.telemetry import (
                baseline_sessions_from_transcript,
                build_context_tool_evidence,
                session_phases_from_transcript,
            )

            transcript = ev.get("transcript")
            try:
                facts = facts_getter()
                if facts is None:
                    # канал заявлен, но фактов нет (у investment_stand канал
                    # телеметрии отсутствует): unavailable с точной причиной,
                    # НЕ absent и не синтетические «факты»
                    ctx_tool = None
                    prov = dict(ev.get("provenance") or {})
                    prov["context_tool_evidence_error"] = (
                        "адаптер заявил канал context_tool_evidence, но фактов не отдал "
                        "(телеметрия стенда недоступна) — слот unavailable, "
                        "effective_context/actual args остаются UNKNOWN"
                    )
                    ev["provenance"] = prov
                else:
                    ctx_tool = build_context_tool_evidence(
                        facts,
                        session_phase=session_phases_from_transcript(transcript),
                        excluded_sessions=baseline_sessions_from_transcript(transcript),
                    )
            except Exception as exc:  # noqa: BLE001 — телеметрия не роняет прогон
                prov = dict(ev.get("provenance") or {})
                prov["context_tool_evidence_error"] = f"{type(exc).__name__}: {exc}"
                ev["provenance"] = prov
                ctx_tool = None
        try:
            write_bundle(
                self.output_dir / "bundles" / candidate_id,
                run_id=result.run_id,
                case_id=logical_case,
                attempt_no=attempt_no,
                experiment_id=getattr(self, "experiment_id", None),
                candidate_id=candidate_id,
                parent_candidate_id=parent_candidate_id,
                goal_digest=goal_digest,
                payloads={
                    "m0": ev.get("before"),
                    "m1": phases.get("m1"),
                    "m2": phases.get("m2"),
                    "m3": ev.get("after"),
                    "transcript": ev.get("transcript"),
                    "settle": ev.get("settle"),
                    "candidate": candidate or None,
                    "memory_diff": ev.get("diff_m0_m1"),
                    "tool_events": tool_events or None,
                    **({"context_tool_evidence": ctx_tool} if facts_getter is not None else {}),
                },
                files={"trace": trace_file if trace_file.exists() else None},
            )
        except OSError as exc:
            # Диск/права — прогон важнее пакета, но сбой обязан быть виден:
            # запись в историю + недописанный каталог (без манифеста) рано или
            # поздно срежется верификацией replay.
            if history is not None:
                history.record(
                    case_id=logical_case,
                    candidate_id=candidate_id,
                    outcome=OUTCOME_EVIDENCE_ERROR,
                    attempt_no=attempt_no,
                    error=f"пакет доказательств не записан: {exc}",
                )
            return
        result.evidence["evidence_bundle"] = f"bundles/{candidate_id}"
