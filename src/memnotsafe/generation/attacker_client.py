"""src/memnotsafe/generation/attacker_client.py — транспорт атакующей LLM.

Паттерн скопирован с `adapters/openai.py` и `judge/client.py`: тот же
`httpx.AsyncClient`, тот же приём «ключ читается из ENV по ИМЕНИ переменной»
(FR-016). SDK провайдера ради одного POST не заводится — новой зависимости нет.

Но атакующий клиент — это ГЕНЕРАТОР ТЕКСТА, а не `TargetAdapter`: у него нет
сессий и снапшотов, поэтому он не наследует адаптер, только повторяет проверенный
HTTP-паттерн (research §8). Любой сетевой сбой → `AttackerError`; исчерпание
бюджета клиент не знает — это забота вызывающего (budget.py).

`StubAttackerClient` — офлайн-реализация: отдаёт скриптованные ответы по очереди,
ровно как `MockTarget` заменяет живой стенд (Принцип VI, research §9).
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

import httpx

from memnotsafe.generation.config import (
    PROVIDER_OPENAI,
    PROVIDER_STUB,
    AttackerConfig,
)
from memnotsafe.generation.errors import AttackerError


@runtime_checkable
class AttackerClient(Protocol):
    """Контракт атакующей LLM: получить system+user промпт, вернуть сырой текст
    ответа модели. Разбор ответа в запись атаки — забота corpus_gen/rewrite,
    не клиента."""

    async def complete(self, prompt: str, *, system: str = "") -> str: ...

    async def aclose(self) -> None: ...


class StubAttackerClient:
    """Офлайн-заглушка: отдаёт `scripted`-ответы по очереди. Выбирается
    `provider="stub"`, ровно как `adapter="mock"` выбирает `MockTarget`.
    Исчерпание скрипта (ответов меньше, чем вызовов) — это ошибка теста/скрипта,
    а не «модель недоступна», но по коду возврата оба идут как сбой генерации."""

    def __init__(self, scripted: list[str] | None = None):
        self._scripted = list(scripted or [])
        self._cursor = 0
        self.calls = 0

    async def complete(self, prompt: str, *, system: str = "") -> str:
        self.calls += 1
        if self._cursor >= len(self._scripted):
            raise AttackerError(
                "StubAttackerClient: скрипт ответов исчерпан "
                f"(запрошено {self.calls}, заготовлено {len(self._scripted)})"
            )
        response = self._scripted[self._cursor]
        self._cursor += 1
        return response

    async def aclose(self) -> None:
        return None


class HTTPAttackerClient:
    """Живая атакующая LLM по OpenAI-совместимому `/v1/chat/completions`.
    Ключ берётся из ENV в момент запроса и никуда не сохраняется (FR-016).
    Ретраи — на 429/5xx/transport; 4xx и неразбираемый ответ — сразу
    `AttackerError` (повтор не поможет)."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str | None,
        api_key_env: str = "ATTACKER_API_KEY",
        timeout_s: float = 60.0,
        max_retries: int = 2,
        temperature: float = 0.0,
        chat_path: str = "/v1/chat/completions",
    ):
        if not base_url:
            raise AttackerError("openai-провайдеру атакующей LLM нужен base_url (--attacker-base-url)")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env
        self.timeout_s = timeout_s
        self.max_retries = max(0, max_retries)
        self.temperature = temperature
        self.chat_path = chat_path
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout_s)

    def _headers(self) -> dict[str, str]:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            raise AttackerError(
                f"переменная окружения {self.api_key_env} не задана или пуста — "
                f"атакующая LLM не может обратиться к провайдеру"
            )
        return {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}

    async def complete(self, prompt: str, *, system: str = "") -> str:
        headers = self._headers()  # нет ключа → AttackerError сразу, без ретраев
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        last_error = "неизвестно"
        for _attempt in range(self.max_retries + 1):
            try:
                resp = await self._client.post(self.chat_path, json=body, headers=headers)
            except httpx.TimeoutException as exc:
                last_error = f"timeout: {exc}"
                continue
            except httpx.TransportError as exc:
                last_error = f"transport: {exc}"
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                last_error = f"status {resp.status_code}"
                continue
            if resp.status_code >= 400:
                raise AttackerError(f"атакующая LLM вернула HTTP {resp.status_code}")
            try:
                raw = resp.json()
                return raw["choices"][0]["message"]["content"] or ""
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise AttackerError(f"ответ атакующей LLM не разобран: {exc}") from exc

        raise AttackerError(
            f"атакующая LLM недоступна после {self.max_retries + 1} попыток: {last_error}"
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def build_attacker_client(config: AttackerConfig) -> AttackerClient:
    """Выбор реализации по `provider` — симметрично `build_adapter` в ядре."""
    if config.provider == PROVIDER_STUB:
        return StubAttackerClient(config.scripted)
    if config.provider == PROVIDER_OPENAI:
        return HTTPAttackerClient(
            model=config.model or "",
            base_url=config.base_url,
            api_key_env=config.api_key_env,
            timeout_s=config.timeout_s,
            max_retries=config.max_retries,
        )
    raise AttackerError(f"неизвестный provider атакующей LLM: {config.provider!r}")
