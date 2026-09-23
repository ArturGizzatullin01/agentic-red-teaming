"""src/memnotsafe/adapters/http_endpoint.py — CARD-T1: generic HTTP target
adapter (tier-1, линия Влада): «пользователь даёт URL и ключ своего
LLM-эндпоинта в YAML → одна команда → отчёт», уровень простоты promptfoo.

Отличие от adapters/openai.py (черновик без карточки): ключ ТОЛЬКО из env —
отсутствие переменной = ValueError при создании адаптера (паттерн langfuse_sink
P11-3; литерал ключа в YAML/сценарии/параметрах невозможен по построению —
конфиг несёт только ИМЯ переменной api_key_env); история сессий живёт В
АДАПТЕРЕ (эндпоинт stateless — это и есть семантика сессии tier-1);
reset/settle деградируют ЧЕСТНО, наблюдаемость не выдумывается.

Семантика сессии tier-1: `new_session(user_id)` → свой session_id
(`http-{user}-{uuid}`, прецедент именования P13-b); вся история сообщений
держится адаптером и отправляется КАЖДЫМ send (messages=история+текущее) —
эндпоинт ничего не помнит между вызовами.

Честные границы (ноль выдуманной наблюдаемости, UNKNOWN≠False):
  - get_trace/snapshot/snapshot_user = None — каналы не наблюдаемы в tier-1;
    оракулы обязаны уходить в UNKNOWN (capabilities все False);
  - wait_until_persistent → SettleResult.unavailable с именем сигнала —
    НЕ дефолт-ловушка observed из base.py:134 (названа пост-аудитом Opus §6;
    этот адаптер её НЕ наследует молча);
  - reset_state: внешнего сброса у произвольного HTTP-таргета НЕ существует —
    reset_available=False навсегда (прецедент P13-b); очищается только
    ЛОКАЛЬНАЯ история адаптера (это наше состояние, не таргета); изоляцию
    прогонов держат свежие session_id, а не «сброс»;
  - сеть/4xx/5xx → исключение транспорта без ретраев (httpx.TransportError /
    HTTPStatusError; раннер оборачивает в RunnerError → outcome
    transport_error, прецедент campaign.py).

Таймаут конечен и ограничен сверху 30 с (значение больше — громкий
ValueError конфигурации, не молчаливый clamp).
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx

from memnotsafe.adapters.base import Capabilities, ProbeResult, SendResult, SettleResult, TargetAdapter

MAX_TIMEOUT_S = 30.0
DEFAULT_API_KEY_ENV = "MEMNOTSAFE_TARGET_API_KEY"
DEFAULT_CHAT_PATH = "/v1/chat/completions"


class HttpEndpointAdapter(TargetAdapter):
    """OpenAI-совместимая chat-ручка как чёрный ящик tier-1 (goal-driven arch:
    ручка заказчика → контракт TargetAdapter без доступа к памяти цели)."""

    def __init__(
        self,
        base_url: str,
        *,
        model_name: str = "target-agent",
        api_key_env: str = DEFAULT_API_KEY_ENV,
        chat_path: str = DEFAULT_CHAT_PATH,
        timeout_s: float = MAX_TIMEOUT_S,
        request_extra_fields: dict[str, Any] | None = None,
        **_ignored: Any,
    ) -> None:
        if not base_url:
            raise ValueError(
                "HttpEndpointAdapter: base_url обязателен (target.base_url в YAML или --target)"
            )
        if float(timeout_s) > MAX_TIMEOUT_S:
            raise ValueError(
                f"HttpEndpointAdapter: timeout_s={timeout_s} больше допустимых {MAX_TIMEOUT_S} с — "
                "таймаут конечен и ограничен, долгие зависания не настраиваются"
            )
        api_key = os.environ.get(api_key_env, "").strip()
        if not api_key:
            raise ValueError(
                f"HttpEndpointAdapter: ключ эндпоинта не найден в env {api_key_env!r} — "
                "ключ читается ТОЛЬКО из окружения (литерал в YAML/сценарии запрещён §3.8); "
                "положите значение в локальный .env/окружение вне репо"
            )
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.api_key_env = api_key_env
        self.chat_path = chat_path
        self.request_extra_fields = request_extra_fields or {}
        self.capabilities = Capabilities(
            trace=False, memory_snapshot=False, tool_calls=False, retrieval=False,
        )
        # Внешнего сброса у HTTP-таргета не существует — честная деградация.
        self.reset_available = False
        # История сессий — состояние АДАПТЕРА (эндпоинт stateless).
        self._sessions: dict[str, list[dict[str, str]]] = {}
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=float(timeout_s),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )

    # ---------------------------------------------------------------- сессии

    async def new_session(self, user_id: str) -> str:
        session_id = f"http-{user_id}-{uuid.uuid4().hex[:8]}"
        self._sessions[session_id] = []
        return session_id

    async def send(self, session_id: str, message: str) -> SendResult:
        history = self._sessions.get(session_id)
        if history is None:
            raise ValueError(
                f"HttpEndpointAdapter: неизвестная/закрытая сессия {session_id!r} — "
                "история сессий живёт в адаптере и удаляется при close/reset"
            )
        history.append({"role": "user", "content": message})
        body = {
            "model": self.model_name,
            "messages": list(history),
            **self.request_extra_fields,
        }
        resp = await self._client.post(self.chat_path, json=body)
        resp.raise_for_status()  # 4xx/5xx → транспортная ошибка, без ретраев
        raw = resp.json()
        try:
            content = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(
                f"HttpEndpointAdapter: ответ не OpenAI-совместим (нет choices[0].message.content): "
                f"{type(exc).__name__}"
            ) from exc
        history.append({"role": "assistant", "content": str(content)})
        return SendResult(content=str(content), events=[], raw=raw)

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    # ---------------------------------------------------------------- probe

    async def probe(self) -> ProbeResult:
        try:
            resp = await self._client.post(
                self.chat_path,
                json={"model": self.model_name,
                      "messages": [{"role": "user", "content": "ping"}]},
            )
            return ProbeResult(
                reachable=resp.status_code < 500,
                capabilities=self.capabilities,
                detail={"status": resp.status_code},
            )
        except httpx.TransportError as exc:
            return ProbeResult(
                reachable=False, capabilities=self.capabilities,
                error=f"ручка {self.base_url}{self.chat_path} недоступна: {exc}",
            )

    # ------------------------------------------------- сброс и наблюдаемость

    async def reset_state(self) -> None:
        # Внешнего сброса нет (reset_available=False навсегда); очищаем только
        # собственную историю сессий — это состояние адаптера, не таргета.
        self._sessions.clear()

    async def get_trace(self, session_id: str) -> list[dict[str, Any]] | None:
        return None  # трасса решений таргета в tier-1 не наблюдаема

    async def snapshot(self) -> None:  # type: ignore[override]
        return None  # доступ к памяти цели отсутствует — оракулы уходят в UNKNOWN

    async def snapshot_user(self, user_id: str) -> None:  # type: ignore[override]
        return None

    async def wait_until_persistent(self, evidence: dict[str, Any]) -> SettleResult:
        # СИГНАЛ, а не дефолт-ловушка observed (base.py:134 названа пост-аудитом
        # Opus §6): память цели не читается — settle не доказуем, оракул обязан
        # ответить UNKNOWN, а не success/timeout.
        return SettleResult(
            outcome="unavailable",
            reason=(
                "tier-1 http_endpoint: память цели не наблюдаема (snapshot=None) — "
                "персистентность не доказуема, честный UNKNOWN, не observed"
            ),
        )

    async def aclose(self) -> None:
        await self._client.aclose()
