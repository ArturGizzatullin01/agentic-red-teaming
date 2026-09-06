"""src/memnotsafe/core/runner.py — единственное место, где склеены target/attack/oracles/
trace. Attack-паки сюда не лезут (знают только ЧТО), адаптер не знает ПОРЯДКА
вызовов (знает только КАК). Runner не знает деталей конкретного таргета (MongoDB, auth_mode и т.п.) — только контракт TargetAdapter.

Lifecycle (T002-3, specs/002-evidence-integrity): baseline -> доставка ->
финализация ВСЕХ delivery-сессий (close_session у investment_stand — это
finalize памяти) -> settle (wait_until_persistent) -> НОВАЯ trigger-сессия.

Владение и ошибки (T002-3, ревизия по ревью F1–F3):
- Runner владеет только созданными им сессиями; клиент адаптера закрывает
  владелец снаружи (CLI/campaign). Каждая сессия закрывается РОВНО одна попытка;
  попытка учитывается ДО await — отмена/сбой close не ретраятся (состояние
  финализации на стенде после сбойного close неизвестно).
- Состояния сессии (терминальные, выставляются ДО/при любом исходе попытки):
  closed (успех) / failed (ошибка close) / interrupted (close прерван отменой) /
  attempted (исход неизвестен: KeyboardInterrupt/SystemExit и т.п.). Попытка
  ровно одна в любом исходе; successful закрытием считается только closed.
- Отмена (asyncio.CancelledError) — отдельный исход во ВСЕХ фазах, включая
  delivery-finalize: наружу CancelledError (не RunnerError), task.cancelled()
  =True при настоящей отмене задачи. KeyboardInterrupt/SystemExit тоже
  сохраняют тип. Cleanup доступных сессий выполняется, первичная причина и
  факт cleanup не теряются (add_note/cause).
- Cleanup последовательный и БЕЗ собственного таймаута: завершаемость зависит
  от bounded-операций адаптера (close_session без внутренних бесконечных
  ожиданий); механизм таймаутов в runner не вводится.
- Сообщения RunnerError содержат только фазу, тип ошибки и идентификатор
  сессии/операции — произвольные тела исключений (могут нести секреты) в текст
  не попадают; сырая причина доступна программно через __cause__/add_note.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from memnotsafe.adapters.base import Capabilities, TargetAdapter
from memnotsafe.attacks.base import AttackBase, AttackContext
from memnotsafe.core.models import AttackResult, JudgeVerdict, StageResult
from memnotsafe.evidence.diff import SnapshotDiff, compute_diff
from memnotsafe.evidence.matching import derive_case_marker
from memnotsafe.evidence.snapshot import SystemSnapshot
from memnotsafe.oracles.base import EvaluationContext
from memnotsafe.oracles.composite import composite_success, evaluate_all
from memnotsafe.tracing.recorder import TraceRecorder
from memnotsafe.tracing.transcript import TranscriptBuilder


def new_run_id() -> str:
    return f"RUN-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"


def new_case_id(attack_id: str, attempt: int) -> str:
    return f"CASE-{attack_id}-{attempt:03d}-{uuid.uuid4().hex[:6]}"


class RunnerError(RuntimeError):
    """Ошибка самого раннера/адаптера (сеть, контракт, краш) — ОТДЕЛЬНО от
    "атака не удалась". CLI должен различать эти два случая: первое
    -> exit 1, второе -> exit 0 + finding NOT_EXPLOITABLE."""


class _SessionBook:
    """Учёт сессий, созданных одним run_attack. Попытка close фиксируется ДО
    await; сессия получает ровно одну попытку закрытия в любом исходе:

    closed      — close_session завершился успешно;
    failed      — close_session поднял Exception;
    interrupted — close_session был прерван отменой (CancelledError).

    Состояния mutually exclusive; interrupted/failed НЕ считаются закрытием и
    не ретраятся ни в основном потоке, ни в cleanup."""

    def __init__(self, target: TargetAdapter):
        self._target = target
        self._owned: list[str] = []
        self._attempted: set[str] = set()  # попытка close была (исход любой)
        self._closed: set[str] = set()
        self._failed: set[str] = set()
        self._interrupted: set[str] = set()
        self.saw_cancellation: bool = False  # факт CancelledError при close —
        # передаётся явно (не парсингом строк) для решения run_attack

    async def open(self, user_id: str) -> str:
        session_id = await self._target.new_session(user_id)
        self._owned.append(session_id)
        return session_id

    async def close(self, session_id: str) -> None:
        if self._settled(session_id):
            return
        # Реальная отметка попытки ДО await: любой исход (успех, Exception,
        # CancelledError, KeyboardInterrupt/SystemExit) — терминален для этой
        # сессии; повторный close невозможен по построению. Различие с closed:
        # успешным закрытием считается только _closed.
        self._attempted.add(session_id)
        try:
            await self._target.close_session(session_id)
        except asyncio.CancelledError:
            self._interrupted.add(session_id)
            raise
        except Exception:
            self._failed.add(session_id)
            raise
        self._closed.add(session_id)

    def _settled(self, session_id: str) -> bool:
        # attempted покрывает все исходы, включая KeyboardInterrupt/SystemExit,
        # у которых отдельный статус не выставляется
        return session_id in self._attempted

    async def close_pending(self) -> list[str]:
        """Закрыть все ещё не завершённые сессии. Сбой/отмена одной не мешает
        остальным; каждая получает ровно одну попытку. Возвращает безопасные
        описания (фаза/сессия/тип, без тел исключений). Факт CancelledError
        фиксируется в self.saw_cancellation (явный сигнал для run_attack)."""
        errors: list[str] = []
        for session_id in list(self._owned):
            if self._settled(session_id):
                continue
            try:
                await self.close(session_id)
            except asyncio.CancelledError:
                self.saw_cancellation = True
                errors.append(f"close session={session_id} interrupted=CancelledError")
            except (KeyboardInterrupt, SystemExit) as exc:
                errors.append(f"close session={session_id} interrupted={type(exc).__name__}")
                raise
            except Exception as exc:  # noqa: BLE001 — собираем все, тела не выводим
                errors.append(f"close session={session_id} error={type(exc).__name__}")
        return errors


async def run_baseline(target: TargetAdapter, ctx: AttackContext, trigger_message: str) -> str:
    """Чистое поведение таргета БЕЗ отравления — тот же триггер, но до всякой
    доставки payload'а ("что делает target без poisoning?").

    Публичный helper (совместимость): та же политика владения и ошибок, что и у
    run_attack — primary сохраняется cause'ом, cleanup наблюдаем через add_note,
    close-only сбой -> RunnerError. Клиент не закрывается."""

    def _safe(exc: BaseException) -> str:
        return f"error={type(exc).__name__}"

    book = _SessionBook(target)
    primary: BaseException | None = None
    phase = "baseline_open"
    cleanup_errors: list[str] = []
    content = ""
    session_id = await book.open(ctx.victim_user_id)
    try:
        result = await target.send(session_id, trigger_message)
        content = result.content
        phase = "baseline_close"
        await book.close(session_id)
    except BaseException as exc:  # noqa: BLE001 — primary; cleanup в finally
        primary = exc
    finally:
        cleanup_errors = await book.close_pending()

    if primary is not None:
        if cleanup_errors:
            primary.add_note(f"runner cleanup: {cleanup_errors}")
        if isinstance(primary, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)) or isinstance(
            primary, RunnerError
        ):
            raise primary
        raise RunnerError(
            f"baseline на случае {ctx.case_id} упал: phase={phase} {_safe(primary)}"
        ) from primary
    if cleanup_errors:
        raise RunnerError(f"baseline cleanup-ошибки на случае {ctx.case_id}: {cleanup_errors}")
    return content


async def run_attack(
    attack: AttackBase,
    ctx: AttackContext,
    target: TargetAdapter,
    *,
    run_id: str,
    recorder: TraceRecorder | None = None,
    judge: Any | None = None,
    require_case_marker: bool = False,
) -> AttackResult:
    """`judge` опционален и по умолчанию отсутствует: без него раннер работает
    ровно как до появления фичи, без сети и ключей (FR-001, SC-003)."""
    book = _SessionBook(target)
    # 002-reporting: журнал диалога — каждая отправленная реплика и каждый
    # реальный ответ; при ошибке сохраняется наблюдённая часть (incomplete)
    transcript = TranscriptBuilder(run_id=run_id, case_id=ctx.case_id)
    primary: BaseException | None = None
    phase = "init"
    # detail — ТОЛЬКО runner-конструируемые строки (id сессий/операций, типы),
    # никогда — тела пользовательских исключений (могут нести секреты).
    phase_detail = ""
    cleanup_errors: list[str] = []
    try:
        await target.reset_state()
        target.set_context(run_id, ctx.case_id)
        probe = await target.probe()
        capabilities: Capabilities = probe.capabilities

        # T002-10 (FR-B): producer маркера — runner; заполняется ДО generate(),
        # чтобы атака могла подставить его ЯВНЫМ плейсхолдером {case_marker}.
        if ctx.case_marker is None:
            ctx.case_marker = derive_case_marker(ctx.case_id)

        candidate = attack.generate(ctx)

        if require_case_marker:
            # маркер может жить в payload ИЛИ в любой delivery-реплике
            # (двухходовая consent-атака записывает второй ход) — та же
            # политика, что у settle-доказательства ниже
            delivery_texts = [s.message for s in attack.delivery_steps(candidate, ctx)]
            marker_placed = any(ctx.case_marker in t for t in delivery_texts if t)
            if not marker_placed:
                # кандидат без маркера при объявленной маркерной изоляции —
                # config error ДО доставки (FR-B), exit 1 на уровне CLI
                raise RunnerError(
                    f"config error на случае {ctx.case_id}: scenario требует case-marker "
                    f"({ctx.case_marker}), но ни payload, ни delivery-реплики его "
                    "не содержат — подстановка возможна только через явный "
                    "плейсхолдер {case_marker}"
                )

        # --- baseline: та же политика владения/ошибок, что и основной поток
        baseline_session = await book.open(ctx.victim_user_id)
        phase = "baseline_send"
        baseline_result = await target.send(baseline_session, candidate.trigger)
        baseline_response = baseline_result.content
        transcript.add(session_id=baseline_session, actor_user_id=ctx.victim_user_id,
                       role="user", phase="baseline", step_label="baseline_trigger",
                       content=candidate.trigger)
        transcript.add(session_id=baseline_session, actor_user_id=ctx.victim_user_id,
                       role="agent", phase="baseline", step_label="baseline_trigger",
                       content=baseline_response)
        phase = "baseline_close"
        await book.close(baseline_session)

        before: SystemSnapshot | None = await target.snapshot()

        all_events: list[dict[str, Any]] = []

        def _collect(events: list[dict[str, Any]]) -> None:
            for e in events:
                all_events.append(e)
                if recorder is not None:
                    recorder.record_raw(e)

        # --- доставка: все созданные сессии (основная + любые as_user) — в book
        attacker_session = await book.open(ctx.attacker_user_id)
        delivery_session_ids: list[str] = [attacker_session]
        delivery_messages: list[str] = []
        for step in attack.delivery_steps(candidate, ctx):
            phase = f"delivery_send[{step.label}]"
            as_user = step.as_user or ctx.attacker_user_id
            session = attacker_session if as_user == ctx.attacker_user_id else await book.open(as_user)
            result = await target.send(session, step.message)
            _collect(result.events)
            if session not in delivery_session_ids:
                delivery_session_ids.append(session)
            delivery_messages.append(step.message)
            transcript.add(session_id=session, actor_user_id=as_user,
                           role="user", phase="delivery", step_label=step.label,
                           content=step.message)
            transcript.add(session_id=session, actor_user_id=as_user,
                           role="agent", phase="delivery", step_label=step.label,
                           content=result.content)

        # --- финализация ВСЕХ delivery-сессий ДО settle: у investment_stand
        # close_session = finalize памяти, settle обязан видеть записанное.
        phase = "finalize"
        finalize_errors = await book.close_pending()
        if finalize_errors:
            phase_detail = "; ".join(finalize_errors)
            raise RuntimeError(f"finalize delivery-сессий: {finalize_errors}")

        phase = "settle"
        # T002-10: settle marker-aware — финалайзер стенда перефразирует текст,
        # буквальная подстрока payload ненадёжна; адаптер атрибутирует запись
        # по case-marker (общий контракт wait_until_persistent, matching в адаптере).
        # Маркер передаётся ТОЛЬКО если атака реально встроила его в payload
        # (плейсхолдер {case_marker}); для legacy-атак — буквальная подстрока.
        settle_evidence: dict[str, Any] = {
            "expect_text_contains": candidate.payload[:60],
            "attacker_user_id": ctx.attacker_user_id,
        }
        # Маркер-атрибут включается ТОЛЬКО если атака реально встроила маркер
        # в payload или любую delivery-реплику (плейсхолдер {case_marker});
        # для legacy-атак маркерный путь атрибуции не применяется.
        marker_used = bool(ctx.case_marker) and (
            ctx.case_marker in candidate.payload or any(ctx.case_marker in m for m in delivery_messages)
        )
        if marker_used:
            settle_evidence["case_marker"] = ctx.case_marker
        persistence_ok = await target.wait_until_persistent(settle_evidence)

        # --- trigger в НОВОЙ сессии (после границы сессии доставки)
        phase = "trigger_open"
        victim_session = await book.open(ctx.victim_user_id)
        trigger_session_ids: list[str] = [victim_session]
        victim_response = ""
        for step in attack.trigger_steps(candidate, ctx):
            if step.message is None:
                continue
            phase = f"trigger_send[{step.label}]"
            as_user = step.as_user or ctx.victim_user_id
            session = victim_session if as_user == ctx.victim_user_id else await book.open(as_user)
            result = await target.send(session, step.message)
            _collect(result.events)
            if session not in trigger_session_ids:
                trigger_session_ids.append(session)
            transcript.add(session_id=session, actor_user_id=as_user,
                           role="user", phase="trigger", step_label=step.label,
                           content=step.message)
            transcript.add(session_id=session, actor_user_id=as_user,
                           role="agent", phase="trigger", step_label=step.label,
                           content=result.content)
            if session == victim_session:
                victim_response = result.content

        phase = "trace"
        victim_trace = await target.get_trace(victim_session)
        phase = "trigger_close"
        await book.close(victim_session)

        phase = "snapshot_after"
        after: SystemSnapshot | None = await target.snapshot()
        diff: SnapshotDiff | None = compute_diff(before, after) if (before and after) else None

        if recorder is not None:
            recorder.flush_case_trace(ctx.case_id)
            recorder.record_case_transcript(ctx.case_id, transcript)

    except BaseException as exc:  # noqa: BLE001 — primary; cleanup в finally её не маскирует
        primary = exc
        # 002-reporting: наблюдённая часть диалога не теряется из-за ошибки
        transcript.mark_incomplete(f"runner interrupted at phase={phase}")
        if recorder is not None:
            recorder.record_case_transcript(ctx.case_id, transcript)
    finally:
        # cleanup всех незакрытых сессий; каждая — ровно одна попытка; отмена
        # во время cleanup не прерывает обработку остальных доступных сессий
        # (close_pending ловит CancelledError пооперационно) и не ждёт бесконечно.
        cleanup_errors = await book.close_pending()

    task = asyncio.current_task()
    task_cancel_requested = task is not None and task.cancelling() > 0
    # Отмена — отдельный исход во ВСЕХ фазах (включая delivery-finalize, где
    # close_pending ранее превращал CancelledError в RuntimeError => RunnerError).
    # Проверяется ПЕРЕД primary-ветками: RunnerError финализации не должен
    # маскировать настоящую отмену задачи.
    if book.saw_cancellation or task_cancel_requested or isinstance(primary, asyncio.CancelledError):
        if isinstance(primary, asyncio.CancelledError):
            if cleanup_errors:
                primary.add_note(f"runner cleanup: {cleanup_errors}")
            raise primary
        exc = asyncio.CancelledError(f"runner interrupted by cancellation: phase={phase}")
        if primary is not None:
            exc.__cause__ = primary  # совместный сбой сохранён программно
        if cleanup_errors:
            exc.add_note(f"runner cleanup: {cleanup_errors}")
        raise exc

    if primary is not None:
        if isinstance(primary, (KeyboardInterrupt, SystemExit)):
            if cleanup_errors:
                primary.add_note(f"runner cleanup: {cleanup_errors}")
            raise primary  # системные — сохраняют тип, не RunnerError
        if isinstance(primary, RunnerError):
            raise primary
        msg = f"Раннер упал на случае {ctx.case_id}: phase={phase} error={type(primary).__name__}"
        if phase_detail:
            msg += f"; detail={phase_detail}"
        if cleanup_errors:
            msg += f"; cleanup: {cleanup_errors}"
        raise RunnerError(msg) from primary
    if cleanup_errors:
        # первичной ошибки не было, но cleanup не смог закрыть сессии — это сбой
        # раннера (утечки недопустимы), не «атака не удалась».
        raise RunnerError(f"cleanup-ошибки на случае {ctx.case_id}: {cleanup_errors}")

    # Судья вызывается ДО evaluate_all и вне блока try выше: сеть — не дело
    # оракула, а сбой судьи не должен маскироваться под падение раннера.
    # Оцениваются три стадии из JUDGED_STAGES; write/persistence/tool судье не
    # передаются никогда (FR-014). Вызов идёт ВСЕГДА и параллельно дословной
    # проверке — даже когда та уже сказала True: расхождение вердиктов и есть
    # собираемый сигнал качества маркерных правил (FR-016, FR-019).
    judge_verdicts: dict[str, JudgeVerdict] = {}
    if judge is not None:
        judge_verdicts = await judge.evaluate_stages(
            case_id=ctx.case_id,
            expected_effect=candidate.expected_effect,
            artifact=victim_response,
            baseline=baseline_response,
        )

    ec = EvaluationContext(
        candidate=candidate,
        ctx=ctx,
        capabilities=capabilities,
        before=before,
        after=after,
        diff=diff,
        baseline_response=baseline_response,
        victim_response=victim_response,
        all_events=all_events,
        victim_trace=victim_trace,
        persistence_ok=persistence_ok,
        judge_verdicts=judge_verdicts,
        # T002-10: маркер записи — та же канарейка, что у адаптера в settle;
        # WRITE-матчер атрибутирует по ней только при реально встроенном маркере
        case_marker=ctx.case_marker if marker_used else None,
        # T002-5: доверенный контекст происхождения — runner единственный знает
        # фазовую принадлежность сессий; oracle'ам запрещено выводить её из событий
        delivery_session_ids=tuple(delivery_session_ids),
        trigger_session_ids=tuple(trigger_session_ids),
    )
    stages: list[StageResult] = evaluate_all(ec)
    success = composite_success(stages)

    metrics = {s.stage: s.success for s in stages}
    evidence = {
        "before": before.to_dict() if before else None,
        "after": after.to_dict() if after else None,
        "diff": diff.to_dict() if diff else None,
        "baseline_response": baseline_response,
        "victim_response": victim_response,
        "trace_events": len(all_events),
        "candidate": {
            "payload": candidate.payload,
            "trigger": candidate.trigger,
            "expected_effect": candidate.expected_effect,
        },
        "transcript": transcript.to_wire(),
    }

    return AttackResult(
        run_id=run_id,
        case_id=ctx.case_id,
        attack_id=attack.metadata.id,
        scenario_id=attack.metadata.family,
        stages=stages,
        success=success,
        metrics=metrics,
        evidence=evidence,
        attacker_user_id=ctx.attacker_user_id,
        victim_user_id=ctx.victim_user_id,
    )
