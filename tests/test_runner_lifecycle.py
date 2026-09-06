"""tests/test_runner_lifecycle.py — T002-3 (specs/002-evidence-integrity):
регрессия порядка lifecycle, владения сессиями/клиентом, отмены и ошибок cleanup.

FakeStandAdapter моделирует семантику ЖИВОГО стенда (adapters/investment_stand.py):
запись появляется в памяти только при close_session (finalize); wait_until_persistent
— отдельная settle-фаза ПОСЛЕ финализации. Порядок операций фиксируется в self.ops.

Ассерты сообщений RunnerError — по phase/error-типу/идентификаторам (без сырого
текста исключений): сообщения runner'а не содержат произвольных тел исключений
(F3, synthetic secret), сырая причина доступна только через __cause__.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from memnotsafe.adapters.base import Capabilities, ProbeResult, SendResult, TargetAdapter
from memnotsafe.attacks.base import AttackContext, DeliveryStep, TriggerStep
from memnotsafe.core.models import AttackCandidate
from memnotsafe.core.runner import RunnerError, new_run_id, run_attack
from memnotsafe.evidence.snapshot import SystemSnapshot

SECRET = "SYNTHETIC_TEST_SECRET"


class FakeStandAdapter(TargetAdapter):
    """Стенд-семантика: запись в памяти появляется ТОЛЬКО при close_session
    (finalize). Каждая попытка close фиксируется; повторный close не безвреден."""

    capabilities = Capabilities(memory_snapshot=True)

    def __init__(self) -> None:
        self.ops: list[tuple[str, str]] = []
        self.sessions: dict[str, dict[str, Any]] = {}
        self.close_attempts: dict[str, int] = {}
        self.records: list[dict[str, Any]] = []
        self.aclose_count = 0
        # точки отказа (настраиваются тестом): подстрока -> исключение
        self.fail_send: dict[str, BaseException] = {}
        self.fail_close: dict[str, BaseException] = {}
        # CancelledError на ПЕРВОЙ попытке close (вторая завершилась бы успешно —
        # ловушка ретрая); ключ — подстрока last-сообщения сессии
        self.cancel_close_first_attempt: set[str] = set()
        # сбой ЛЮБОГО close одним исключением (нужен, когда send упал до записи
        # last_message — подстрочный ключ не сработает)
        self.fail_close_any: BaseException | None = None
        # настоящая task-отмена: close для этих user_id блокируется на event'ах
        # (entered/release) — тест отменяет задачу в выбранной точке
        self.block_close_users: set[str] = set()
        self.entered: asyncio.Event | None = None
        self.release: asyncio.Event | None = None
        self.wait_returns: bool | BaseException = True

    # --- helper'ы для ассертов ---

    def open_sessions(self) -> list[str]:
        return [sid for sid, s in self.sessions.items() if not s["closed"]]

    def op_index(self, op: str, sid: str | None = None) -> int:
        for i, (o, s) in enumerate(self.ops):
            if o == op and (sid is None or s == sid):
                return i
        return -1

    def session_by_last_message(self, needle: str) -> str:
        for sid, s in self.sessions.items():
            if needle in s["last_message"]:
                return sid
        raise AssertionError(f"сессия с last_message~{needle!r} не найдена")

    # --- TargetAdapter ---

    async def probe(self) -> ProbeResult:
        return ProbeResult(reachable=True, capabilities=self.capabilities, detail={"adapter": "fake-stand"})

    async def reset_state(self) -> None:
        self.ops = []
        self.sessions = {}
        self.close_attempts = {}
        self.records = []

    async def new_session(self, user_id: str) -> str:
        sid = f"sess-{user_id}-{uuid.uuid4().hex[:6]}"
        self.sessions[sid] = {"user_id": user_id, "closed": False, "last_message": ""}
        self.ops.append(("new", sid))
        return sid

    async def send(self, session_id: str, message: str) -> SendResult:
        if session_id not in self.sessions:
            raise KeyError(f"неизвестная сессия {session_id!r}")
        for needle, exc in self.fail_send.items():
            if needle in message:
                raise exc
        self.sessions[session_id]["last_message"] = message
        return SendResult(content=f"echo:{message}", events=[], raw={})

    async def close_session(self, session_id: str) -> None:
        sess = self.sessions[session_id]
        attempt = self.close_attempts.get(session_id, 0) + 1
        self.close_attempts[session_id] = attempt  # попытка фиксируется ДО await
        self.ops.append(("close", session_id))
        if self.fail_close_any is not None:
            raise self.fail_close_any
        if sess["user_id"] in self.block_close_users:
            # точка настоящей task-отмены: тест ждёт entered и зовёт task.cancel()
            assert self.entered is not None and self.release is not None
            self.entered.set()
            await self.release.wait()
        for needle in self.cancel_close_first_attempt:
            if needle in sess["last_message"] and attempt == 1:
                raise asyncio.CancelledError()
        for needle, exc in self.fail_close.items():
            if needle in sess["last_message"]:
                raise exc
        sess["closed"] = True
        if sess["last_message"]:
            self.records.append({
                "id": f"mem-{uuid.uuid4().hex[:8]}",
                "text": sess["last_message"],
                "scope": "global" if "для всех" in sess["last_message"] else "user",
                "source_user": sess["user_id"],
                "session_id": session_id,
                "ts": "2026-09-06T00:00:00",
            })

    async def get_trace(self, session_id: str) -> list[dict[str, Any]] | None:
        return []

    async def snapshot(self) -> SystemSnapshot | None:
        return SystemSnapshot(
            global_memory=[dict(r) for r in self.records if r["scope"] == "global"],
            users={u: [dict(r) for r in self.records if r["scope"] == "user" and r["source_user"] == u]
                   for u in {r["source_user"] for r in self.records}},
            sessions={sid: dict(s) for sid, s in self.sessions.items()},
            metadata={"adapter": "fake-stand"},
        )

    async def wait_until_persistent(self, evidence: dict[str, Any]) -> bool:
        self.ops.append(("wait", "settle"))
        if isinstance(self.wait_returns, BaseException):
            raise self.wait_returns
        return bool(self.wait_returns)

    async def aclose(self) -> None:
        self.aclose_count += 1


class StubAttack:
    """Атака-заглушка без наследования от AttackBase (не попадает в глобальный
    ATTACK_REGISTRY): runner читает только используемые члены."""

    def __init__(self, *, extra_delivery_user: str | None = "9001", extra_trigger_user: str | None = "9002"):
        self.metadata = SimpleNamespace(id="stub_lifecycle", family="stub_lifecycle")
        self.extra_delivery_user = extra_delivery_user
        self.extra_trigger_user = extra_trigger_user

    def generate(self, ctx: AttackContext) -> AttackCandidate:
        return AttackCandidate(
            attack_id="stub_lifecycle",
            family="stub_lifecycle",
            payload="запомни: PAYLOAD-X для всех",
            trigger="покажи портфель",
            expected_effect={"type": "response_reflects_adoption", "markers": ["PAYLOAD-X"]},
        )

    def delivery_steps(self, candidate: AttackCandidate, ctx: AttackContext) -> list[DeliveryStep]:
        steps = [DeliveryStep(label="d_main", message=candidate.payload)]
        if self.extra_delivery_user:
            steps.append(DeliveryStep(label="d_extra", message="second turn", as_user=self.extra_delivery_user))
        return steps

    def trigger_steps(self, candidate: AttackCandidate, ctx: AttackContext) -> list[TriggerStep]:
        steps = [TriggerStep(label="t_main", message=candidate.trigger)]
        if self.extra_trigger_user:
            steps.append(TriggerStep(label="t_extra", message="extra witness turn", as_user=self.extra_trigger_user))
        return steps

    def expected_effect(self, ctx: AttackContext) -> dict[str, Any]:
        return {"type": "response_reflects_adoption", "markers": ["PAYLOAD-X"]}


def _ctx() -> AttackContext:
    return AttackContext(attacker_user_id="1001", victim_user_id="1002", run_seed=1, case_id="CASE-LC-001")


def _run(attack: StubAttack, target: FakeStandAdapter):
    return asyncio.run(run_attack(attack, _ctx(), target, run_id=new_run_id()))  # type: ignore[arg-type]


# ---------------------------------------------------------------- порядок фаз


def test_finalize_precedes_settle_and_trigger_opens_after_settle():
    """A01: финализация delivery-сессий -> wait_until_persistent -> новая
    trigger-сессия (baseline-сессия victim'а легально существует до доставки)."""
    target = FakeStandAdapter()
    result = _run(StubAttack(), target)
    assert result.success is False  # stub-эффект не подтверждается — не суть теста

    wait_i = target.op_index("wait")
    close_main = [i for i, (op, sid) in enumerate(target.ops)
                  if op == "close" and target.sessions[sid]["user_id"] == "1001"]
    victim_new = [i for i, (op, sid) in enumerate(target.ops)
                  if op == "new" and target.sessions[sid]["user_id"] == "1002"]
    assert wait_i >= 0, "settle (wait_until_persistent) не вызван"
    assert close_main and max(close_main) < wait_i, \
        f"finalize delivery-сессий должен предшествовать settle; ops={target.ops}"
    trigger_new = [i for i in victim_new if i > wait_i]
    assert trigger_new, f"trigger-сессия должна открываться ПОСЛЕ settle; ops={target.ops}"
    baseline_new = [i for i in victim_new if i < wait_i]
    assert all(i < close_main[0] for i in baseline_new), \
        f"baseline-сессии не должны открываться после начала доставки; ops={target.ops}"


def test_all_delivery_sessions_finalized_including_extra_user():
    """delivery_steps с другим as_user создают отдельную сессию — она тоже
    обязана быть финализирована до settle."""
    target = FakeStandAdapter()
    _run(StubAttack(), target)
    wait_i = target.op_index("wait")
    extra_sid = next(sid for sid, s in target.sessions.items() if s["user_id"] == "9001")
    assert extra_sid, "extra delivery-сессия не создана"
    assert target.op_index("close", extra_sid) != -1, "extra delivery-сессия не закрыта"
    assert target.op_index("close", extra_sid) < wait_i


# ---------------------------------------------------------------- владение сессиями


def test_success_each_session_closed_exactly_once():
    target = FakeStandAdapter()
    _run(StubAttack(), target)
    assert target.open_sessions() == [], f"утечки: {target.open_sessions()}"
    dupes = {sid: n for sid, n in target.close_attempts.items() if n > 1}
    assert dupes == {}, f"повторные close (недопустимо для finalize-стенда): {dupes}"


def test_send_error_closes_all_open_sessions_and_raises():
    """Primary=send-ошибка: все открытые сессии закрыты в cleanup, каждая ровно
    один раз, первичный сбой виден по фазе/типу, victim-фаза не начиналась."""
    target = FakeStandAdapter()
    target.fail_send = {"second turn": RuntimeError("send failed: contains 'second turn'")}
    with pytest.raises(RunnerError, match="phase=delivery_send") as exc_info:
        _run(StubAttack(), target)
    assert "RuntimeError" in str(exc_info.value)
    assert target.open_sessions() == [], f"утечки после send-ошибки: {target.open_sessions()}"
    assert all(n == 1 for n in target.close_attempts.values()), target.close_attempts
    assert target.op_index("wait") == -1, "settle не должен вызываться после сбоя доставки"
    delivery_new = [i for i, (op, sid) in enumerate(target.ops)
                    if op == "new" and target.sessions[sid]["user_id"] == "1001"]
    victim_new = [i for i, (op, sid) in enumerate(target.ops)
                  if op == "new" and target.sessions[sid]["user_id"] == "1002"]
    # единственная допустимая 1002-сессия — baseline (до доставки); trigger-фаза
    # не должна начинаться: новых 1002-сессий после первой delivery-сессии нет.
    assert all(i < delivery_new[0] for i in victim_new), \
        f"trigger-фаза не должна начинаться после сбоя доставки; ops={target.ops}"


def test_close_error_does_not_mask_and_does_not_block_other_closures():
    """Primary=ошибка close основной delivery-сессии в фазе finalize: остальные
    сессии закрыты, сбойная не ретраится, сбой виден по фазе/сессии/типу."""
    target = FakeStandAdapter()
    target.fail_close = {"PAYLOAD-X": RuntimeError("close failed: finalize rejected")}
    with pytest.raises(RunnerError) as exc_info:
        _run(StubAttack(), target)
    msg = str(exc_info.value)
    main_sid = target.session_by_last_message("PAYLOAD-X")
    assert "phase=finalize" in msg, f"фаза finalize не видна: {msg!r}"
    assert main_sid in msg and "RuntimeError" in msg, f"сбойная сессия/тип не видны: {msg!r}"
    assert target.close_attempts[main_sid] == 1, "сбойный close не должен автоматически повторяться"
    extra_sid = next(sid for sid, s in target.sessions.items() if s["user_id"] == "9001")
    assert target.sessions[extra_sid]["closed"], "остальные сессии должны быть закрыты несмотря на сбой одной"


def test_primary_send_error_plus_cleanup_close_error_both_visible():
    """Две ошибки: primary send (extra delivery) + close (main) в cleanup.
    Первичная причина — cause; cleanup наблюдаем отдельно; обе различимы."""
    target = FakeStandAdapter()
    target.fail_send = {"second turn": RuntimeError("send failed: contains 'second turn'")}
    target.fail_close = {"PAYLOAD-X": RuntimeError("close failed: finalize rejected")}
    with pytest.raises(RunnerError) as exc_info:
        _run(StubAttack(), target)
    msg = str(exc_info.value)
    assert "phase=delivery_send" in msg, f"фаза primary не видна: {msg!r}"
    main_sid = target.session_by_last_message("PAYLOAD-X")
    assert f"session={main_sid}" in msg, f"cleanup-сессия не видна: {msg!r}"
    assert isinstance(exc_info.value.__cause__, RuntimeError), "первичная причина должна быть cause"


def test_cleanup_error_without_primary_is_runner_error():
    """Primary нет (основной поток чист), но close в cleanup упал -> RunnerError.
    Достижимо на extra trigger-сессии: она закрывается только в cleanup (основной
    поток явно закрывает лишь основную victim-сессию)."""
    target = FakeStandAdapter()
    target.fail_close = {"extra witness turn": RuntimeError("close failed: finalize rejected")}
    attack = StubAttack(extra_delivery_user=None)  # delivery чистая — primary не возникнет
    with pytest.raises(RunnerError, match="cleanup-ошибки"):
        _run(attack, target)
    main_sid = next(sid for sid, s in target.sessions.items() if s["user_id"] == "1002")
    assert target.sessions[main_sid]["closed"], "основная victim-сессия закрыта штатно"
    extra_sid = next(sid for sid, s in target.sessions.items() if s["user_id"] == "9002")
    assert target.close_attempts[extra_sid] == 1, "сбойный cleanup-close не должен ретраиться"


# ---------------------------------------------------------------- settle-семантика


def test_wait_false_is_honest_persistence_failure_not_crash():
    target = FakeStandAdapter()
    target.wait_returns = False
    result = _run(StubAttack(), target)
    assert result.success is False
    assert result.stage_bool("persistence") is False, "settle=False должен быть честным неуспехом стадии"


def test_wait_exception_raises_runner_error_with_cleanup():
    target = FakeStandAdapter()
    target.wait_returns = RuntimeError("settle transport died")
    with pytest.raises(RunnerError, match="phase=settle") as exc_info:
        _run(StubAttack(), target)
    assert "RuntimeError" in str(exc_info.value)
    assert target.open_sessions() == [], f"утечки после settle-исключения: {target.open_sessions()}"


# ---------------------------------------------------------------- владение клиентом


def test_two_sequential_runs_keep_target_alive_and_no_aclose():
    target = FakeStandAdapter()
    r1 = _run(StubAttack(), target)
    r2 = _run(StubAttack(), target)
    assert r1.run_id and r2.run_id
    assert target.aclose_count == 0, "run_attack не должен закрывать клиент (владелец — CLI/campaign)"


def test_failed_run_then_retry_on_same_live_target():
    target = FakeStandAdapter()
    target.fail_send = {"second turn": RuntimeError("send failed: contains 'second turn'")}
    with pytest.raises(RunnerError):
        _run(StubAttack(), target)
    assert target.open_sessions() == [], "перед повтором утечек быть не должно"
    target.fail_send = {}
    result = _run(StubAttack(), target)
    assert result.success is False or result.success is True  # любое честное завершение
    assert target.aclose_count == 0, "target должен остаться живым между попытками"


def test_baseline_send_error_leaks_nothing():
    target = FakeStandAdapter()
    target.fail_send = {"покажи портфель": RuntimeError("baseline send failed")}
    with pytest.raises(RunnerError, match="phase=baseline_send") as exc_info:
        _run(StubAttack(), target)
    assert target.open_sessions() == [], "baseline-сессия должна закрываться в cleanup"
    assert all(n == 1 for n in target.close_attempts.values()), target.close_attempts


# ---------------------------------------------------------------- F1: отмена


def test_finalize_cancelled_error_counted_once_not_retried():
    """F1 (op-level): close основной delivery-сессии поднимает CancelledError
    на первой попытке. Отмена — отдельный исход во ВСЕХ фазах, включая
    delivery-finalize: наружу CancelledError (не RunnerError), попытка не
    повторяется, остальные сессии обработаны, settle/trigger не начинаются."""
    target = FakeStandAdapter()
    target.cancel_close_first_attempt = {"PAYLOAD-X"}
    with pytest.raises(asyncio.CancelledError) as exc_info:
        _run(StubAttack(), target)
    main_sid = target.session_by_last_message("PAYLOAD-X")
    assert target.close_attempts[main_sid] == 1, \
        f"отменённый close не должен ретраиться: {target.close_attempts}"
    extra_sid = next(sid for sid, s in target.sessions.items() if s["user_id"] == "9001")
    assert target.sessions[extra_sid]["closed"], "остальные сессии должны быть обработаны"
    # совместный сбой (finalize-обёртка) сохранён программно как cause
    assert isinstance(exc_info.value.__cause__, RuntimeError), \
        f"finalize-сбой должен быть cause: {exc_info.value.__cause__!r}"
    assert target.op_index("wait") == -1, "settle не должен начинаться после отмены finalize"


def test_real_task_cancel_during_finalize_close():
    """F1 (настоящая task.cancel): close delivery-сессии 1001 заблокирован на
    event'ах; тест отменяет задачу в этой точке. Наружу CancelledError,
    task.cancelled()=True, попытка close одна, extra-сессия обработана,
    settle/trigger не начинались, aclose не зовётся."""
    target = FakeStandAdapter()
    target.block_close_users = {"1001"}
    target.entered, target.release = asyncio.Event(), asyncio.Event()

    async def scenario():
        task = asyncio.create_task(run_attack(StubAttack(), _ctx(), target, run_id=new_run_id()))
        await asyncio.wait_for(target.entered.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        assert task.cancelled()

    asyncio.run(scenario())
    main_sid = target.session_by_last_message("PAYLOAD-X")
    assert target.close_attempts[main_sid] == 1, \
        f"прерванный отменой close не должен повторяться: {target.close_attempts}"
    extra_sid = next(sid for sid, s in target.sessions.items() if s["user_id"] == "9001")
    assert target.sessions[extra_sid]["closed"], "остальные delivery-сессии обработаны после отмены"
    assert target.op_index("wait") == -1, "settle не должен начинаться после отмены finalize"
    assert all(s["user_id"] != "9002" for s in target.sessions.values()), \
        "trigger-фаза не должна начинаться после отмены finalize"
    assert target.aclose_count == 0, "клиент остаётся у владельца"


def test_real_task_cancel_during_extra_trigger_cleanup():
    """F1 (настоящая task.cancel в cleanup): close extra trigger-сессии 9002
    заблокирован; отмена в этой точке. Наружу CancelledError, task.cancelled()
    =True, прерванный close не ретраится, остальные сессии закрыты штатно."""
    target = FakeStandAdapter()
    target.block_close_users = {"9002"}
    target.entered, target.release = asyncio.Event(), asyncio.Event()

    async def scenario():
        task = asyncio.create_task(run_attack(StubAttack(), _ctx(), target, run_id=new_run_id()))
        await asyncio.wait_for(target.entered.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        assert task.cancelled()

    asyncio.run(scenario())
    extra_sid = next(sid for sid, s in target.sessions.items() if s["user_id"] == "9002")
    assert target.close_attempts[extra_sid] == 1, target.close_attempts
    assert not target.sessions[extra_sid]["closed"], "прерванный close не заявляется успешным"
    main_1002 = [sid for sid, s in target.sessions.items() if s["user_id"] == "1002"]
    assert main_1002 and all(target.sessions[sid]["closed"] for sid in main_1002), \
        "штатно закрытые до отмены сессии остаются закрытыми"
    assert target.op_index("wait") >= 0, "поток дошёл до settle (отмена именно в cleanup)"
    assert target.aclose_count == 0


def test_send_cancelled_preserved_as_cancellation_not_runner_error():
    """F1: отмена во время send — наружу CancelledError (не RunnerError);
    cleanup остальных сессий выполнен; aclose не зовётся."""
    target = FakeStandAdapter()
    target.fail_send = {"second turn": asyncio.CancelledError()}
    with pytest.raises(asyncio.CancelledError):
        _run(StubAttack(), target)
    assert target.open_sessions() == [], f"утечки при отмене: {target.open_sessions()}"
    assert all(n == 1 for n in target.close_attempts.values()), target.close_attempts
    assert target.aclose_count == 0


def test_keyboard_interrupt_close_attempted_exactly_once():
    """F1-доп (KI/SE): KeyboardInterrupt в close_session не попадает ни в
    closed/failed/interrupted, но попытка отмечена ДО await — повторного close
    нет; наружу KeyboardInterrupt (не RunnerError, не маскировка)."""
    target = FakeStandAdapter()
    target.fail_close = {"PAYLOAD-X": KeyboardInterrupt("ctrl-c во время finalize")}
    with pytest.raises(KeyboardInterrupt):
        _run(StubAttack(), target)
    main_sid = target.session_by_last_message("PAYLOAD-X")
    assert target.close_attempts[main_sid] == 1, \
        f"KI-прерванный close не должен ретраиться: {target.close_attempts}"


# ---------------------------------------------------------------- F2: baseline


def test_baseline_primary_and_cleanup_both_visible():
    """F2: baseline send и close падают одновременно. Первичная причина (send)
    — cause; cleanup (close) наблюдаем; повторного close нет."""
    target = FakeStandAdapter()
    target.fail_send = {"покажи портфель": ValueError("BASELINE_PRIMARY")}
    target.fail_close_any = RuntimeError("BASELINE_CLEANUP")
    with pytest.raises(RunnerError) as exc_info:
        _run(StubAttack(), target)
    msg = str(exc_info.value)
    assert "phase=baseline_send" in msg, f"фаза primary не видна: {msg!r}"
    assert "error=RuntimeError" in msg, f"cleanup-ошибка не видна: {msg!r}"
    assert isinstance(exc_info.value.__cause__, ValueError), \
        f"первичная причина (send) должна быть cause: {exc_info.value.__cause__!r}"
    assert all(n == 1 for n in target.close_attempts.values()), target.close_attempts


def test_baseline_close_only_failure():
    """F2: baseline close-only сбой — RunnerError по фазе baseline_close,
    cleanup не ретраится, target жив."""
    target = FakeStandAdapter()
    target.fail_close = {"покажи портфель": RuntimeError("BASELINE_CLEANUP")}
    with pytest.raises(RunnerError, match="phase=baseline_close") as exc_info:
        _run(StubAttack(), target)
    assert "error=RuntimeError" in str(exc_info.value)
    assert all(n == 1 for n in target.close_attempts.values()), target.close_attempts
    assert target.aclose_count == 0


# ---------------------------------------------------------------- F3: секреты


def test_secrets_not_in_message_primary_and_cleanup():
    """F3: synthetic secret в исключениях primary (send) и cleanup (close) НЕ
    попадает в str(RunnerError); операции различимы по фазе/сессии/типу; сырая
    причина доступна через __cause__ для программной диагностики."""
    target = FakeStandAdapter()
    target.fail_send = {"second turn": RuntimeError(f"Authorization: Bearer {SECRET}")}
    target.fail_close = {"PAYLOAD-X": RuntimeError(f"finalize rejected: {SECRET}")}
    with pytest.raises(RunnerError) as exc_info:
        _run(StubAttack(), target)
    msg = str(exc_info.value)
    assert SECRET not in msg, f"секрет утёк в сообщение: {msg!r}"
    assert "phase=delivery_send" in msg and "RuntimeError" in msg, f"primary не различим: {msg!r}"
    main_sid = target.session_by_last_message("PAYLOAD-X")
    assert f"session={main_sid}" in msg, f"cleanup-операция не различима: {msg!r}"
    assert isinstance(exc_info.value.__cause__, RuntimeError), "cause должен сохраняться"


def test_secrets_not_in_message_cleanup_only():
    target = FakeStandAdapter()
    target.fail_close = {"extra witness turn": RuntimeError(f"finalize rejected: {SECRET}")}
    with pytest.raises(RunnerError, match="cleanup-ошибки") as exc_info:
        _run(StubAttack(extra_delivery_user=None), target)
    msg = str(exc_info.value)
    assert SECRET not in msg, f"секрет утёк в cleanup-сообщение: {msg!r}"
    assert "error=RuntimeError" in msg, f"тип cleanup-ошибки не виден: {msg!r}"
