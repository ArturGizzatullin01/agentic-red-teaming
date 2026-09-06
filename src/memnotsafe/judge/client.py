"""src/memnotsafe/judge/client.py — транспорт судьи по OpenAI-совместимому
REST (contracts/judge-io.schema.md, «Запрос»).

Написан по образцу adapters/openai.py: тот же httpx.AsyncClient, тот же приём
«ключ читается из ENV по ИМЕНИ переменной». SDK провайдера ради одного
POST-запроса не заводится: новая зависимость противоречила бы требованию
офлайн-пути без сети (Принцип VI).

Клиент НИЧЕГО не знает про рубрики, пороги и бюджет. Его дело — отправить два
готовых сообщения и классифицировать сбой: timeout / rate_limit / transport.
Разбор ответа — verdict.py, учёт бюджета — runtime.py.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

# Схема структурированного ответа. `strict: true` — провайдеры, которые её
# поддерживают, не дадут модели выйти за формат; те, что игнорируют
# response_format, отсекаются разбором в verdict.py.
JUDGE_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["outcome", "confidence", "rationale", "quote"],
    "properties": {
        "outcome": {"type": "string", "enum": ["confirmed", "refuted"]},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "rationale": {"type": "string", "maxLength": 600},
        "quote": {"type": "string", "maxLength": 400},
    },
}


@dataclass
class JudgeCallResult:
    """Исход ОДНОГО HTTP-запроса к модели-судье."""

    ok: bool
    content: str = ""
    status: int | None = None
    raw: dict[str, Any] | None = None
    error: str = ""  # timeout | rate_limit | transport — словарь причин JudgeVerdict.error
    latency_ms: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


class JudgeClient:
    def __init__(
        self,
        *,
        model: str,
        base_url: str = "https://openrouter.ai/api/v1",
        api_key_env: str = "OPENROUTER_API_KEY",
        timeout_s: float = 30.0,
        temperature: float = 0.0,
        chat_path: str = "/chat/completions",
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env
        self.timeout_s = timeout_s
        self.temperature = temperature
        self.chat_path = chat_path
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout_s)

    def _headers(self) -> dict[str, str]:
        """Ключ берётся из ENV в момент запроса и НИКУДА не сохраняется:
        ни в артефакт вызова, ни в лог, ни в сообщение об ошибке."""
        headers = {"Content-Type": "application/json"}
        key = os.environ.get(self.api_key_env, "")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def request_params(self) -> dict[str, Any]:
        """То, что уходит в артефакт вызова рядом с текстом сообщений."""
        return {"model": self.model, "temperature": self.temperature, "timeout_s": self.timeout_s}

    async def complete(self, system: str, user: str) -> JudgeCallResult:
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "judge_verdict", "strict": True, "schema": JUDGE_RESPONSE_SCHEMA},
            },
        }
        started = time.monotonic()
        try:
            resp = await self._client.post(self.chat_path, json=body, headers=self._headers())
        except httpx.TimeoutException:
            return JudgeCallResult(ok=False, error="timeout", latency_ms=_ms(started))
        except httpx.TransportError:
            return JudgeCallResult(ok=False, error="transport", latency_ms=_ms(started))

        latency = _ms(started)
        if resp.status_code == 429:
            return JudgeCallResult(ok=False, status=resp.status_code, error="rate_limit", latency_ms=latency)
        if resp.status_code >= 400:
            return JudgeCallResult(ok=False, status=resp.status_code, error="transport", latency_ms=latency)

        try:
            raw = resp.json()
            content = raw["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError):
            # Тело не JSON или без ожидаемого поля — по контракту это шаг 1:
            # повторяемый сбой, а не вердикт.
            return JudgeCallResult(ok=False, status=resp.status_code, error="transport", latency_ms=latency)

        return JudgeCallResult(ok=True, content=content, status=resp.status_code, raw=raw, latency_ms=latency)

    async def aclose(self) -> None:
        await self._client.aclose()


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
