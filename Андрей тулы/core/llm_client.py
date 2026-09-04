"""core/llm_client.py — тонкий клиент к OpenAI-совместимому эндпоинту для ролей
attacker/judge (НЕ для таргета — тот ходит через core/target.py). Два разных LLM
(attacker/judge ≠ target-агент) конфигурируются независимо через LLMClientConfig —
у каждой роли свой base_url/api_key_env/model, но код клиента общий, чтобы не плодить
три копии одной и той же httpx-обвязки.

Без langchain/openai SDK — обычный httpx.AsyncClient, чтобы не тащить тяжёлые
зависимости ради двух эндпоинтов (chat/completions, embeddings).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class LLMClientConfig:
    base_url: str
    api_key_env: str
    model: str
    temperature: float = 0.0
    max_tokens: int = 800
    timeout_s: float = 60.0
    extra_headers: dict[str, str] = field(default_factory=dict)
    # Схема авторизации в заголовке Authorization. OpenAI-совместимые эндпоинты (Ollama,
    # OpenRouter) ждут "Bearer <ключ>" — дефолт. Yandex Cloud LLM API ждёт "Api-Key <ключ>"
    # (2026-09-03: обнаружено по 401 при judge=Yandex Cloud с дефолтной схемой).
    auth_scheme: str = "Bearer"

    @property
    def api_key(self) -> str:
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise RuntimeError(f"Переменная окружения {self.api_key_env} не задана.")
        return key

    @property
    def auth_header_value(self) -> str:
        return f"{self.auth_scheme} {self.api_key}"


class LLMClient:
    """Роль-агностичный клиент: один экземпляр = одна роль (attacker ИЛИ judge),
    задаётся тем, какой LLMClientConfig в него передали."""

    def __init__(self, config: LLMClientConfig):
        self.config = config
        self._client = httpx.AsyncClient(base_url=config.base_url.rstrip("/"), timeout=config.timeout_s)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def complete(self, system: str, user: str, *, temperature: float | None = None,
                        max_tokens: int | None = None) -> str | None:
        body = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
        }
        headers = {"Authorization": self.config.auth_header_value, **self.config.extra_headers}
        resp = await self._client.post("/chat/completions", json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def complete_json(self, system: str, user: str, *, temperature: float | None = None) -> dict[str, Any]:
        """Просит модель ответить строго JSON, парсит с фолбэком на извлечение
        первого {...}-блока (модели иногда оборачивают в ```json ... ```)."""
        judge_system = (
            system + "\n\nОтвечай СТРОГО валидным JSON, без markdown-обёртки, без комментариев. "
            "Внутри строковых значений НЕ используй двойные кавычки для цитирования/акцента "
            "(qwen2.5:3b на живом прогоне 2026-09-03 ломала JSON, вставляя литеральные \" внутрь "
            "rationale) — вместо этого используй одинарные кавычки ' ' или пиши без кавычек."
        )
        raw = await self.complete(judge_system, user, temperature=temperature)
        if raw is None:
            # reasoning-модели (deepseek-v4-flash на Yandex Cloud) иногда тратят ВЕСЬ
            # max_tokens на скрытый reasoning_content и возвращают content: null
            # (finish_reason "length") — не ошибка авторизации/парсинга, встречено на
            # стрессовом прогоне 2026-09-03 (~7% вызовов). Один retry с удвоенным
            # бюджетом на этот конкретный вызов, прежде чем считать это отказом.
            raw = await self.complete(judge_system, user, temperature=temperature,
                                       max_tokens=self.config.max_tokens * 2)
        if raw is None:
            raise RuntimeError(
                "Судья/атакующая модель вернула content=None даже после retry с "
                f"удвоенным max_tokens ({self.config.max_tokens * 2}) — вероятно, "
                "reasoning-модель тратит весь бюджет на reasoning_content. Подними "
                "LLMClientConfig.max_tokens в конфиге ещё выше."
            )
        # Маленькие локальные модели (qwen2.5:3b) иногда экранируют одинарные кавычки
        # как `\'` внутри JSON-строк — невалидный escape по спецификации JSON, ловим
        # реальным прогоном 2026-09-03. Чиним заменой перед повторным парсом, вместо
        # того чтобы тащить отдельную JSON-repair зависимость ради одного паттерна.
        for candidate in (raw, raw.replace("\\'", "'")):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                match = re.search(r"\{.*\}", candidate, re.DOTALL)
                if match:
                    try:
                        return json.loads(match.group(0))
                    except json.JSONDecodeError:
                        continue
        raise ValueError(f"Судья/атакующая модель не вернула валидный JSON: {raw!r}")

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """По одному тексту за запрос, не батчем: Yandex Cloud LLM API /embeddings
        отвечает 400 "Array input must contain exactly one string" на batch-input
        (стресс-тест 2026-09-03) — OpenAI-совместимые провайдеры batch тоже
        принимают, так что по-одному безопасно для всех, просто N запросов вместо 1."""
        headers = {"Authorization": self.config.auth_header_value, **self.config.extra_headers}
        vectors: list[list[float]] = []
        for text in texts:
            body = {"model": self.config.model, "input": [text]}
            resp = await self._client.post("/embeddings", json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            vectors.append(data["data"][0]["embedding"])
        return vectors


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
