"""core/target.py — чёрный ящик: клиент к целевому агенту по OpenAI-совместимому контракту.

Target-agnostic: никакой стенд-специфики (auth_mode, схема memory-эндпоинтов) здесь
не хардкодится. Всё, что расширяет стандартный OpenAI chat/completions контракт
(genai-invest-agent-memory-stand добавляет auth_mode/session_id полями тела запроса),
приходит через TargetConfig.request_extra_fields из config.yaml профиля запуска.

Не менять сигнатуры без пометки BREAKING (правило CLAUDE.md — attacks_loader и паки
на них полагаются).
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

import httpx


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TargetConfig:
    base_url: str
    api_key_env: str = "TARGET_API_KEY"
    chat_path: str = "/v1/chat/completions"
    finalize_path_template: str | None = "/v1/sessions/{session_id}/finalize"
    finalize_via_chat_keyword: str | None = "finalize"
    request_extra_fields: dict[str, Any] = field(default_factory=dict)
    timeout_s: float = 60.0
    retries: int = 2
    model_name: str = "genai-invest-assistant"

    @property
    def api_key(self) -> str:
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise RuntimeError(
                f"Переменная окружения {self.api_key_env} не задана — нужен ключ sk-genai-… "
                "(или эквивалент таргета). Секреты в конфиг не кладём."
            )
        return key


@dataclass
class ChatTurn:
    role: Literal["user", "assistant", "system", "tool"]
    content: str

    def to_dict(self) -> dict:
        return {"role": self.role, "content": self.content}


@dataclass
class ChatResult:
    content: str
    session_id: str
    raw_request: dict
    raw_response: dict
    latency_ms: float
    ts: datetime
    label: str = "chat"


@dataclass
class FinalizeResult:
    raw_response: dict
    ts: datetime
    session_id: str


class TargetError(RuntimeError):
    """Ошибка похода в target — несёт тело ответа, не пересказ (trace-based feedback)."""

    def __init__(self, message: str, *, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class TargetClient:
    def __init__(self, config: TargetConfig):
        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            timeout=config.timeout_s,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> TargetClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

    async def _post_with_retry(self, path: str, body: dict) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self.config.retries + 1):
            try:
                resp = await self._client.post(path, json=body, headers=self._headers())
                if resp.status_code >= 500 and attempt < self.config.retries:
                    last_exc = TargetError(
                        f"5xx от таргета на {path}", status_code=resp.status_code, body=resp.text
                    )
                    continue
                return resp
            except httpx.TransportError as exc:
                last_exc = exc
                continue
        assert last_exc is not None
        raise last_exc

    async def chat(
        self,
        messages: list[ChatTurn],
        *,
        session_id: str | None = None,
        extra_fields: dict[str, Any] | None = None,
        label: str = "chat",
    ) -> ChatResult:
        session_id = session_id or str(uuid.uuid4())[:8]
        body: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": [m.to_dict() for m in messages],
            "session_id": session_id,
            **self.config.request_extra_fields,
            **(extra_fields or {}),
        }
        t0 = time.monotonic()
        resp = await self._post_with_retry(self.config.chat_path, body)
        latency_ms = (time.monotonic() - t0) * 1000
        if resp.status_code != 200:
            raise TargetError(
                f"POST {self.config.chat_path} -> {resp.status_code}",
                status_code=resp.status_code,
                body=resp.text,
            )
        raw = resp.json()
        try:
            content = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise TargetError(
                f"Ответ таргета не похож на OpenAI chat.completion: {raw}"
            ) from exc
        return ChatResult(
            content=content,
            session_id=session_id,
            raw_request=body,
            raw_response=raw,
            latency_ms=latency_ms,
            ts=_utc_now(),
            label=label,
        )

    async def deliver_user_message(
        self, session_id: str, text: str, *, extra_fields: dict[str, Any] | None = None, label: str = "deliver"
    ) -> ChatResult:
        return await self.chat(
            [ChatTurn(role="user", content=text)],
            session_id=session_id,
            extra_fields=extra_fields,
            label=label,
        )

    async def finalize(self, session_id: str) -> FinalizeResult:
        cfg = self.config
        if cfg.finalize_path_template:
            path = cfg.finalize_path_template.format(session_id=session_id)
            t0 = time.monotonic()
            resp = await self._client.post(path, headers=self._headers())
            if resp.status_code != 200:
                raise TargetError(
                    f"POST {path} -> {resp.status_code}", status_code=resp.status_code, body=resp.text
                )
            return FinalizeResult(raw_response=resp.json(), ts=_utc_now(), session_id=session_id)

        if cfg.finalize_via_chat_keyword:
            result = await self.deliver_user_message(
                session_id, cfg.finalize_via_chat_keyword, label="finalize_via_chat"
            )
            return FinalizeResult(raw_response=result.raw_response, ts=result.ts, session_id=session_id)

        raise TargetError(
            "Ни finalize_path_template, ни finalize_via_chat_keyword не заданы в TargetConfig — "
            "нет способа запустить финализацию сессии на этом таргете."
        )


class TargetPool:
    """Несколько идентичностей на одном таргете (напр. client1001 и client1002 —
    каждая со своим sk-genai-… ключом). Нужен ЛЮБОЙ cross-user атаке: у API-контракта
    этого стенда identity привязана к Bearer-ключу, не к полю тела запроса, значит
    один TargetClient физически не может говорить и за жертву, и за свидетеля.

    configs: user_id -> TargetConfig (у каждого свой api_key_env, base_url обычно общий).
    """

    def __init__(self, configs: dict[str, TargetConfig]):
        self._clients = {user_id: TargetClient(cfg) for user_id, cfg in configs.items()}

    def get(self, user_id: str) -> TargetClient:
        if user_id not in self._clients:
            raise KeyError(
                f"В TargetPool нет идентичности для user_id={user_id!r}. "
                f"Известные: {sorted(self._clients)}. Добавь ключ в config.yaml (targets.identities)."
            )
        return self._clients[user_id]

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
