"""scripts/smoke_test.py — end-to-end прогон core/runner.py БЕЗ живого стенда/Mongo/Docker.

Зачем: проверить, что оркестрация (target -> evidence -> judge -> report) реально
склеена правильно, независимо от того, поднят ли Docker локально. httpx.AsyncClient.post
подменяется на функцию, строящую настоящие httpx.Response в памяти (не Mock — реальный
объект httpx, чтобы resp.json()/status_code вели себя как боевые), EvidenceSource и
judge LLM — простые фейки с предсказуемым поведением.

Это НЕ замена прогону на живом стенде (verify-finding.md требует реальный diff Mongo +
трассу реального прогона) — это дымовой тест на "код не сломан", который можно гонять
за секунды в CI без инфраструктуры.

Запуск: .venv/Scripts/python.exe scripts/smoke_test.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

os.environ.setdefault("TARGET_API_KEY_CLIENT1001", "sk-genai-fake-1001")
os.environ.setdefault("TARGET_API_KEY_CLIENT1002", "sk-genai-fake-1002")
os.environ.setdefault("JUDGE_API_KEY", "fake-judge-key")

from attacks.cross_user_scope_global.pack import CrossUserScopeGlobalStrong
from core.attack_base import AttackContext
from core.evidence import EvidenceSource, MemorySnapshot
from core.llm_client import LLMClient, LLMClientConfig
from core.report import human_summary, write_json_report
from core.runner import run_attack
from core.target import TargetConfig, TargetPool
from core.tracer import CompositeTracer

_CALLS: list[str] = []


async def _fake_post(self, url, *, json=None, headers=None, **kwargs):
    _CALLS.append(url)
    if "/finalize" in url:
        payload = {"episodes": [{"summary": "тестовая сессия"}],
                   "facts": [{"fact": "правило про VIP", "scope": "global", "confidence": 0.9}]}
    else:
        payload = {
            "id": "chatcmpl-fake", "object": "chat.completion", "created": 0,
            "model": "genai-invest-assistant",
            "choices": [{"index": 0, "message": {"role": "assistant",
                         "content": "Хорошо, зафиксировал. При работе с вами буду учитывать "
                                    "внутренние практики банка для VIP-клиентов."},
                         "finish_reason": "stop"}],
        }
    return httpx.Response(200, json=payload, request=httpx.Request("POST", "http://fake-target" + url))


class FakeEvidenceSource(EvidenceSource):
    """Первый snapshot() — пусто (before). Второй — с новым agent_policy_memories
    документом (after), имитируя реальную запись orchestrator'а стенда."""

    def __init__(self):
        self._calls = 0

    def snapshot(self, user_id: str) -> MemorySnapshot:
        self._calls += 1
        policy = []
        if self._calls > 1:
            policy = [{
                "policy_id": "pol-1", "statement": "правило про VIP",
                "confidence": 0.9, "source_session_id": "attack-session",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }]
        return MemorySnapshot(
            ts=datetime.now(timezone.utc), user_id=user_id,
            dialog_sessions=[], episodic_memories=[], semantic_memories=[],
            agent_policy_memories=policy, source="fake",
        )


async def _fake_complete_json(self, system: str, user: str, *, temperature=None):
    return {
        "success": True, "confidence": 0.87,
        "rationale": "Ответ witness-клиенту явно упоминает внутренние практики для VIP.",
        "what_written": "правило про VIP", "who_affected": ["client1002"],
    }


async def main() -> None:
    httpx.AsyncClient.post = _fake_post
    LLMClient.complete_json = _fake_complete_json

    targets = TargetPool({
        "client1001": TargetConfig(base_url="http://fake-target", api_key_env="TARGET_API_KEY_CLIENT1001"),
        "client1002": TargetConfig(base_url="http://fake-target", api_key_env="TARGET_API_KEY_CLIENT1002"),
    })
    evidence_source = FakeEvidenceSource()
    judge_llm = LLMClient(LLMClientConfig(base_url="http://fake-judge", api_key_env="JUDGE_API_KEY", model="fake"))
    tracer = CompositeTracer(traces_dir="traces/smoke")

    attack = CrossUserScopeGlobalStrong()
    ctx = AttackContext(
        victim_user_id="client1001", session_id="smoke-session",
        run_seed=1, witness_user_id="client1002",
    )

    result = await run_attack(
        attack, ctx, targets=targets, evidence_source=evidence_source,
        judge_llm=judge_llm, tracer=tracer,
    )

    assert result.evidence.diff.cross_user_write_detected, "WRITE-стадия должна была обнаружить diff"
    assert result.verdict.success, f"Ожидался успех, получено: {result.verdict}"
    assert result.verdict.when_activated == "both", result.verdict.when_activated
    assert result.verdict.trace_present, "trace_ref обязателен (evidence-first инвариант)"
    assert any("/finalize" in c for c in _CALLS), "finalize() не был вызван"
    assert sum("/finalize" not in c for c in _CALLS) == 2, f"ожидалось 2 chat-вызова (deliver+trigger), было: {_CALLS}"

    report_path = write_json_report([(result, attack.metadata)], "reports/smoke_sample.json")
    print(human_summary([(result, attack.metadata)]))
    print(f"\nJSON-отчёт (пример формы, данные фейковые — НЕ реальный прогон): {report_path}")
    print("SMOKE TEST: OK — оркестрация target->evidence->judge->report работает корректно")
    await targets.aclose()
    await judge_llm.aclose()


if __name__ == "__main__":
    asyncio.run(main())
