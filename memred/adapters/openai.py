"""memred/adapters/openai.py — generic black-box adapter поверх OpenAI-совместимого
`/v1/chat/completions` контракта. Взято из практики "Андрей тулы" (core/target.py),
адаптировано под TargetAdapter ABC. Настоящий сетевой HTTP-клиент — не мок.

Black-box по умолчанию: нет доступа к памяти/трассе таргета, поэтому
capabilities = все False; retrieval/tool/adoption/external_effect на реальном
таргете без доп. evidence-канала будут UNKNOWN, кроме response_reflects_adoption
(наблюдаемый ответ агента — не telemetry, доступен всегда).

Не покрыт тестами в этом репозитории (нужен реально поднятый таргет) — это
интеграционная точка расширения, не часть проверяемого P0-вертикального среза.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx

from memred.adapters.base import Capabilities, ProbeResult, SendResult, TargetAdapter


class OpenAICompatibleAdapter(TargetAdapter):
    def __init__(
        self,
        base_url: str,
        *,
        api_key_env: str = "TARGET_API_KEY",
        chat_path: str = "/v1/chat/completions",
        model_name: str = "target-agent",
        request_extra_fields: dict[str, Any] | None = None,
        timeout_s: float = 60.0,
        **_ignored: Any,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env
        self.chat_path = chat_path
        self.model_name = model_name
        self.request_extra_fields = request_extra_fields or {}
        self.capabilities = Capabilities(trace=False, memory_snapshot=False, tool_calls=False, retrieval=False)
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout_s)

    def _headers(self) -> dict[str, str]:
        key = os.environ.get(self.api_key_env, "")
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    async def probe(self) -> ProbeResult:
        try:
            resp = await self._client.post(
                self.chat_path,
                json={"model": self.model_name, "messages": [{"role": "user", "content": "ping"}]},
                headers=self._headers(),
            )
            return ProbeResult(reachable=resp.status_code < 500, capabilities=self.capabilities, detail={"status": resp.status_code})
        except httpx.TransportError as exc:
            return ProbeResult(reachable=False, capabilities=self.capabilities, error=str(exc))

    async def reset_state(self) -> None:
        return None  # black-box: нет стандартного способа сбросить состояние произвольного таргета

    async def new_session(self, user_id: str) -> str:
        return f"{user_id}-{uuid.uuid4().hex[:8]}"

    async def send(self, session_id: str, message: str) -> SendResult:
        body = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": message}],
            "session_id": session_id,
            **self.request_extra_fields,
        }
        resp = await self._client.post(self.chat_path, json=body, headers=self._headers())
        resp.raise_for_status()
        raw = resp.json()
        content = raw["choices"][0]["message"]["content"]
        return SendResult(content=content, events=[], raw=raw)

    async def close_session(self, session_id: str) -> None:
        return None

    async def aclose(self) -> None:
        await self._client.aclose()
