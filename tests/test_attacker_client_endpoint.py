"""tests/test_attacker_client_endpoint.py — регресс живого прогона LIVE-COVERAGE.

Баг, пойманный ПЕРВЫМ живым прогоном атакующего (HTTP 404): HTTPAttackerClient
по умолчанию слал POST на chat_path=`/v1/chat/completions`, а base_url пресета
(и мастера go, и все локи) уже несёт `/v1`
(`https://llm.api.cloud.yandex.net/v1`) → запрос уходил на `…/v1/v1/chat/...` → 404.
Судья (JudgeClient) с ТЕМ ЖЕ base_url бьёт в рабочую ручку через
chat_path=`/chat/completions`. Инвариант: при одинаковом base_url атакующий и
судья обязаны попадать в ОДНУ ручку OpenAI-совместимого провайдера. Офлайн
(httpx.MockTransport), без сети.
"""

from __future__ import annotations

import asyncio

import httpx


def _capture_client(base_url: str, bucket: dict, key: str) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        bucket[key] = str(request.url)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    return httpx.AsyncClient(base_url=base_url, transport=httpx.MockTransport(handler))


def test_attacker_and_judge_hit_same_yandex_endpoint(monkeypatch) -> None:
    from memnotsafe.generation.attacker_client import HTTPAttackerClient
    from memnotsafe.judge.client import JudgeClient

    monkeypatch.setenv("ATTACKER_API_KEY", "x")
    monkeypatch.setenv("PROVIDER_API_KEY", "x")
    base = "https://llm.api.cloud.yandex.net/v1"  # каким его дают пресеты и все локи
    seen: dict[str, str] = {}

    async def _go() -> None:
        att = HTTPAttackerClient(model="gpt://f/qwen3.6-35b-a3b/latest",
                                 base_url=base, api_key_env="ATTACKER_API_KEY")
        await att._client.aclose()
        att._client = _capture_client(base, seen, "attacker")

        jud = JudgeClient(model="gpt://f/deepseek-v4-flash/latest",
                          base_url=base, api_key_env="PROVIDER_API_KEY")
        await jud._client.aclose()
        jud._client = _capture_client(base, seen, "judge")

        await att.complete("payload", system="sys")
        await jud.complete("sys", "user")
        await att.aclose()
        await jud.aclose()

    asyncio.run(_go())

    # Паритет: одинаковый base_url → одна и та же ручка (иначе атакующий 404, судья 200).
    assert seen["attacker"] == seen["judge"], seen
    # И это именно рабочая ручка Yandex (без дубля /v1).
    assert seen["attacker"].endswith("/v1/chat/completions"), seen["attacker"]
    assert "/v1/v1" not in seen["attacker"], seen["attacker"]
