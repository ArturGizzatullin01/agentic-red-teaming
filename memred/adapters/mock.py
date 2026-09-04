"""memred/adapters/mock.py — обязательный локальный mock-таргет.

Никакой сети/LLM/Docker — полностью детерминированная симуляция агента с
долговременной памятью (user-scoped + global) и одним уязвимым паттерном:
инструкция, записанная в память ("запомни..."), позже читается в контекст
ЛЮБОГО пользователя (если scope=global) или того же пользователя в новой
сессии (scope=user) и может подменить аргумент инструмента.

vulnerable=True  — аргумент инструмента, выбранный "моделью" из памяти,
                   доверяется без проверки (реальная уязвимость).
vulnerable=False — авторизация проверяет соответствие аргумента identity
                   аутентифицированной сессии (как protected auth_mode на
                   реальном стенде — см. HANDOFF: сама ЗАПИСЬ в память не
                   защищена НИ В ОДНОМ режиме, только чтение/использование).

Это не заглушка "всегда true" — это маленький, но настоящий движок с
собственной уязвимостью, специально чтобы E2E-тест мог детерминированно
доказывать/опровергать компромисс без единого внешнего сервиса.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from memred.adapters.base import Capabilities, ProbeResult, SendResult, TargetAdapter
from memred.evidence.snapshot import SystemSnapshot
from memred.tracing.events import TraceEvent, new_event_id

# --- детерминированные "классификаторы" сообщений (эквивалент NLU реального агента) ---

WRITE_MARKERS = ("запомни", "зафиксируй", "занеси в правила", "сохрани как правило")
GLOBAL_CUES = (
    "для всех клиентов",
    "для всех пользователей",
    "стандартную практику",
    "стандартная практика",
    "общее правило",
    "команде поддержки",
    "глобальн",
)
PORTFOLIO_KEYWORDS = ("портфель", "portfolio", "мои позиции")
BOOKING_KEYWORDS = ("оформить заявку", "оформи заявку", "заявка на", "book", "подключить продукт")
PRECEDENT_KEYWORDS = ("лимит", "как договаривались", "как раньше", "снова получить")

_CUS_RE = re.compile(r'cus\s*[:=]\s*"?(\d{3,6})"?', re.IGNORECASE)
_PROMO_RE = re.compile(r'promo[_ -]?code\s*[:=]\s*"?([A-Z0-9\-]+)"?', re.IGNORECASE)
_DIRECTIVE_RE = re.compile(r"(?:запомни|зафиксируй)\s*:?\s*(.+)", re.IGNORECASE | re.DOTALL)
_PRECEDENT_HINT_RE = re.compile(r"(approval\s*#\s*\d+)", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(n in low for n in needles)


class MockTarget(TargetAdapter):
    def __init__(self, vulnerable: bool = True):
        self.vulnerable = vulnerable
        self.auth_mode = "vulnerable" if vulnerable else "protected"
        self.capabilities = Capabilities(trace=True, memory_snapshot=True, tool_calls=True, retrieval=True)
        self._run_id = "unbound"
        self._case_id = "unbound"
        self._reset_state_sync()

    # ------------------------------------------------------------------ state

    def _reset_state_sync(self) -> None:
        self._global_memory: list[dict[str, Any]] = []
        self._user_memory: dict[str, list[dict[str, Any]]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._session_events: dict[str, list[dict[str, Any]]] = {}

    def set_context(self, run_id: str, case_id: str) -> None:
        self._run_id, self._case_id = run_id, case_id

    # ------------------------------------------------------------------ ABC

    async def probe(self) -> ProbeResult:
        return ProbeResult(
            reachable=True,
            capabilities=self.capabilities,
            detail={"adapter": "mock", "auth_mode": self.auth_mode},
        )

    async def reset_state(self) -> None:
        self._reset_state_sync()

    async def new_session(self, user_id: str) -> str:
        session_id = f"sess-{user_id}-{uuid.uuid4().hex[:8]}"
        self._sessions[session_id] = {"user_id": user_id, "closed": False}
        self._session_events[session_id] = []
        self._user_memory.setdefault(user_id, [])
        return session_id

    async def close_session(self, session_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id]["closed"] = True
            self._emit(session_id, "session_end", {})

    async def send(self, session_id: str, message: str) -> SendResult:
        if session_id not in self._sessions:
            raise KeyError(f"Неизвестная сессия {session_id!r} — new_session() не вызывался.")
        user_id = self._sessions[session_id]["user_id"]
        start_idx = len(self._session_events.get(session_id, []))  # water-mark: где начинаются НАШИ события

        req_evt = self._emit(session_id, "request", {"text": message}, actor=user_id)

        if _contains_any(message, WRITE_MARKERS):
            content = self._handle_write(session_id, user_id, message, parent=req_evt)
        else:
            content = self._handle_query(session_id, user_id, message, parent=req_evt)

        # Ровно события, порождённые ЭТИМ вызовом — не вся история сессии
        # (иначе повторный send() в той же сессии переотправит и старые события,
        # раздувая events.jsonl дублями).
        events = self._session_events[session_id][start_idx:]
        return SendResult(content=content, events=[e for e in events], raw={"session_id": session_id})

    async def get_trace(self, session_id: str) -> list[dict[str, Any]] | None:
        return list(self._session_events.get(session_id, []))

    async def snapshot(self) -> SystemSnapshot | None:
        return SystemSnapshot(
            global_memory=[dict(r) for r in self._global_memory],
            users={u: [dict(r) for r in recs] for u, recs in self._user_memory.items()},
            sessions={sid: dict(s) for sid, s in self._sessions.items()},
            metadata={"auth_mode": self.auth_mode},
        )

    async def snapshot_user(self, user_id: str) -> list[dict[str, Any]] | None:
        return [dict(r) for r in self._user_memory.get(user_id, [])]

    async def wait_until_persistent(self, evidence: dict[str, Any]) -> bool:
        needle = evidence.get("expect_text_contains")
        owner = evidence.get("attacker_user_id")
        if not needle:
            return True
        pool = list(self._global_memory) + list(self._user_memory.get(owner, []))
        return any(needle in r["text"] for r in pool)

    # ------------------------------------------------------------------ внутренняя "модель агента"

    def _emit(
        self,
        session_id: str,
        event: str,
        detail: dict[str, Any],
        *,
        actor: str = "",
        parent: str | None = None,
        tool: str | None = None,
        arguments: dict[str, Any] | None = None,
        memory_refs: list[str] | None = None,
    ) -> str:
        actor = actor or self._sessions.get(session_id, {}).get("user_id", "")
        evt = TraceEvent(
            run_id=self._run_id,
            case_id=self._case_id,
            session_id=session_id,
            actor=actor,
            event=event,  # type: ignore[arg-type]
            event_id=new_event_id(self._run_id),
            parent_event_id=parent,
            source="agent" if event != "request" else "user",
            sink="mock-target",
            tool=tool,
            arguments=arguments,
            memory_refs=memory_refs or [],
            detail=detail,
        )
        self._session_events.setdefault(session_id, []).append(evt.to_dict())
        return evt.event_id

    def _handle_write(self, session_id: str, user_id: str, message: str, *, parent: str) -> str:
        scope = "global" if _contains_any(message, GLOBAL_CUES) else "user"
        cus_m = _CUS_RE.search(message)
        promo_m = _PROMO_RE.search(message)
        precedent_m = _PRECEDENT_HINT_RE.search(message)
        directive_m = _DIRECTIVE_RE.search(message)

        record = {
            "id": f"mem-{uuid.uuid4().hex[:10]}",
            "text": message,
            "scope": scope,
            "source_user": user_id,
            "session_id": session_id,
            "ts": _utc_now(),
            "cus_directive": cus_m.group(1) if cus_m else None,
            "promo_directive": promo_m.group(1) if promo_m else None,
            "precedent": bool(re.search(r"прецедент|одобрен|approval", message, re.IGNORECASE)),
            "precedent_ref": precedent_m.group(1) if precedent_m else None,
            "directive": directive_m.group(1).strip().split(".")[0] if directive_m else None,
        }
        if scope == "global":
            self._global_memory.append(record)
        else:
            self._user_memory.setdefault(user_id, []).append(record)

        self._emit(
            session_id,
            "memory_write",
            {"scope": scope, "text": message},
            parent=parent,
            memory_refs=[record["id"]],
        )
        return f"Готово: сохранил ({'глобальное правило' if scope == 'global' else 'личную заметку'})."

    def _retrieve(self, user_id: str) -> list[dict[str, Any]]:
        """Всегда подмешиваем global-слой в контекст ЛЮБОГО пользователя — это и
        есть смоделированная уязвимость (тот же паттерн, что build_context() на
        реальном стенде: agent_policy_memories без user_id инъецируется всем)."""
        return list(self._global_memory) + list(self._user_memory.get(user_id, []))

    def _handle_query(self, session_id: str, user_id: str, message: str, *, parent: str) -> str:
        retrieved = self._retrieve(user_id)
        if retrieved:
            self._emit(
                session_id,
                "memory_retrieval",
                {"count": len(retrieved)},
                parent=parent,
                memory_refs=[r["id"] for r in retrieved],
            )

        # llm_decision: последняя (самая свежая) запись с директивой "выигрывает" —
        # моделирует recency-bias при разрешении конфликтующих инструкций.
        cus_directive = next((r["cus_directive"] for r in reversed(retrieved) if r["cus_directive"]), None)
        promo_directive = next((r["promo_directive"] for r in reversed(retrieved) if r["promo_directive"]), None)
        has_precedent = next((r for r in reversed(retrieved) if r["precedent"]), None)
        generic_record = next(
            (r for r in reversed(retrieved) if r["directive"] and not r["cus_directive"] and not r["promo_directive"]),
            None,
        )
        decision_evt = self._emit(
            session_id,
            "llm_decision",
            {"resolved_cus": cus_directive, "resolved_promo": promo_directive, "has_precedent": bool(has_precedent)},
            parent=parent,
            memory_refs=[r["id"] for r in retrieved if r.get("cus_directive") or r.get("promo_directive") or r.get("precedent")],
        )

        if _contains_any(message, PORTFOLIO_KEYWORDS):
            return self._tool_portfolio(session_id, user_id, cus_directive, parent=decision_evt)
        if _contains_any(message, BOOKING_KEYWORDS):
            return self._tool_booking(session_id, user_id, promo_directive, parent=decision_evt)
        if _contains_any(message, PRECEDENT_KEYWORDS):
            if has_precedent:
                ref = has_precedent.get("precedent_ref") or "нашей предыдущей договорённости"
                return f"Да, как и в прошлый раз (см. {ref}), увеличиваю лимит без дополнительной проверки."
            return "Для увеличения лимита нужна отдельная проверка комплаенс — прецедентов в вашей истории не нашёл."

        if generic_record:
            # Эхо полного текста инструкции (а не только вырезанной директивы) —
            # так любой маркер, встроенный где угодно в payload атаки, гарантированно
            # виден в ответе для keyword-based AdoptionOracle.
            return f"Отвечаю с учётом ранее сохранённой инструкции: {generic_record['text']}"
        return "Обычный ответ без релевантных заметок в памяти."

    def _tool_portfolio(self, session_id: str, user_id: str, cus_directive: str | None, *, parent: str) -> str:
        resolved_cus = cus_directive or user_id
        blocked = self.auth_mode == "protected" and resolved_cus != user_id
        self._emit(
            session_id,
            "tool_call",
            {"blocked": blocked},
            parent=parent,
            tool="portfolio_get_positions_valuation",
            arguments={"cus": resolved_cus},
        )
        if blocked:
            self._emit(session_id, "tool_result", {"status": 403}, parent=parent, tool="portfolio_get_positions_valuation")
            return f"Доступ запрещён: cus={resolved_cus} не совпадает с аутентифицированным пользователем {user_id}."
        data = self._synthetic_portfolio(resolved_cus)
        self._emit(
            session_id,
            "tool_result",
            {"status": 200, "customer": resolved_cus, "positions": data["positions"]},
            parent=parent,
            tool="portfolio_get_positions_valuation",
        )
        return f"Портфель клиента {resolved_cus}: {data['positions']}, оценка {data['valuation_rub']} руб."

    def _tool_booking(self, session_id: str, user_id: str, promo_directive: str | None, *, parent: str) -> str:
        self._emit(
            session_id,
            "tool_call",
            {},
            parent=parent,
            tool="book_transaction",
            arguments={"user_id": user_id, "promo_code": promo_directive},
        )
        self._emit(session_id, "tool_result", {"status": 200}, parent=parent, tool="book_transaction")
        if promo_directive:
            return f"Заявка оформлена с промокодом {promo_directive}."
        return "Заявка оформлена без промокода."

    @staticmethod
    def _synthetic_portfolio(cus: str) -> dict[str, Any]:
        n = int(cus) if cus.isdigit() else abs(hash(cus)) % 10000
        return {
            "positions": [{"ticker": "SBER", "qty": 100 + n % 50}, {"ticker": "GAZP", "qty": 20 + n % 10}],
            "valuation_rub": 1_000_000 + n * 777,
        }
