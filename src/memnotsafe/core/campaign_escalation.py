"""src/memnotsafe/core/campaign_escalation.py — ARC-2: эскалационный клей кампании
(вынесен из core/campaign.py при расщеплении). Миксин к Campaign: точка вызова
онлайн-уровня при `--online` и `success=False`. Сам цикл — в core/escalation.py
(ленивый импорт, как было). Тип ошибки атакующей LLM берётся из шва
core/campaign_backend — периферия (generation.errors) ядром не импортируется.
Поведение прежнее — тело перенесено дословно, изменены только строки границы
generation (импорт AttackerError → backend.attacker_error).
"""

from __future__ import annotations

from memnotsafe.attacks.base import AttackBase, AttackContext
from memnotsafe.core.attempt import OUTCOME_ABORTED, AttemptHistory
from memnotsafe.core.campaign_backend import campaign_backend
from memnotsafe.core.ledger import BudgetLedger
from memnotsafe.core.models import AttackResult
from memnotsafe.tracing.recorder import TraceRecorder


class CampaignEscalationMixin:
    async def _maybe_escalate(
        self,
        attack: AttackBase,
        ctx: AttackContext,
        result: AttackResult,
        *,
        run_id: str,
        recorder: TraceRecorder,
        require_case_marker: bool = False,
        history: AttemptHistory | None = None,
        ledger: BudgetLedger | None = None,
        bundle_writer=None,
    ) -> AttackResult:
        """Онлайн-уровень (US2/US3). Реализация цикла — в core/escalation.py; здесь
        только точка вызова при `--online` и `success=False`. При выключенном
        онлайне (по умолчанию) возвращает result без изменений (SC-003)."""
        if not self.online or result.success:
            return result

        self._ensure_attacker()
        backend = campaign_backend()
        from memnotsafe.core.escalation import escalate

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
                # тот же судья, что судил первую попытку: иначе вердикты попыток
                # одного случая несопоставимы (см. докстринг core/escalation.py)
                judge=self.judge,
                # и то же требование маркера: повтор получает НОВЫЙ маркер
                # (case_id новый), но наличие его в доставке проверяется так же
                # строго, как у первой попытки (единый план P04)
                require_case_marker=require_case_marker,
                history=history,
                ledger=ledger,
                bundle_writer=bundle_writer,
            )
        except backend.attacker_error as exc:
            # Сбой атакующей LLM ≠ «атака не пробила защиту» (FR-011). Фиксируем
            # ошибку (CLI вернёт exit 1), но возвращаем уже полученный результат —
            # он и всё собранное до него сохранятся в runs/ (FR-010, SC-005).
            self.attacker_error = str(exc)
            self.attacker_calls = self._budget.used if self._budget else self.attacker_calls
            prov = dict(result.evidence.get("provenance") or {})
            prov["attacker_error"] = str(exc)
            result.evidence["provenance"] = prov
            if history is not None:
                history.record(
                    case_id=ctx.case_id,
                    candidate_id=result.case_id,
                    outcome=OUTCOME_ABORTED,
                    attempt_no=0,
                    error=str(exc),
                )
            return result

        self.attacker_calls = self._budget.used if self._budget else self.attacker_calls
        if outcome.budget_exhausted:
            self.budget_exhausted = True
        return outcome.result

    # ------------------------------------------------------------------ запись артефактов случая
