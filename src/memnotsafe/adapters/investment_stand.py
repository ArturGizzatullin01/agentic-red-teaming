"""src/memnotsafe/adapters/investment_stand.py — адаптер для genai-invest-agent-memory-stand
(контракт восстановлен по двум независимым прототипам-предшественникам, которые
одинаково задокументировали один и тот же API/Mongo-контракт стенда).

Известные особенности контракта, вынесенные СЮДА (не в core/), чтобы не
переносить target-specific branching в core runner:
  - identity авторизуется Bearer sk-genai-… ключом, привязанным к конкретному
    cus, НЕ полем тела запроса — significantly отличается от общего
    OpenAICompatibleAdapter. new_session(user_id) резолвит ключ через
    identities: {user_id: env_var_name} (задаётся в scenario YAML
    target.extra.identities).
  - finalize нужен для переноса working memory в долговременную (Mongo).
  - evidence — прямое чтение Mongo (dialog_sessions/episodic_memories/
    semantic_memories/agent_policy_memories), если задан mongo_uri; иначе
    snapshot()/snapshot_user() возвращают None (black-box деградация).

Не покрыт тестами этого репозитория — нужен живой стенд + реальные ключи.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx

from memnotsafe.adapters.base import Capabilities, ProbeResult, SendResult, TargetAdapter
from memnotsafe.evidence.snapshot import SystemSnapshot

_COLLECTIONS = ("dialog_sessions", "episodic_memories", "semantic_memories", "agent_policy_memories")


class InvestmentStandAdapter(TargetAdapter):
    def __init__(
        self,
        base_url: str,
        *,
        identities: dict[str, str] | None = None,
        auth_mode: str = "vulnerable",
        finalize_via_chat_keyword: str = "finalize",
        mongo_uri: str | None = None,
        mongo_db: str = "agent_memory",
        timeout_s: float = 60.0,
        **_ignored: Any,
    ):
        self.base_url = base_url.rstrip("/")
        self.identities = identities or {}
        self.auth_mode = auth_mode
        self.finalize_keyword = finalize_via_chat_keyword
        self.mongo_uri = mongo_uri
        self.mongo_db = mongo_db
        self.capabilities = Capabilities(
            trace=False, tool_calls=False, retrieval=False, memory_snapshot=bool(mongo_uri)
        )
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout_s)
        self._session_users: dict[str, str] = {}
        self._mongo = None

    def _key_for(self, user_id: str) -> str:
        env_name = self.identities.get(user_id)
        if not env_name:
            raise KeyError(
                f"Нет identity для user_id={user_id!r} в target.extra.identities сценария. "
                f"Известные: {sorted(self.identities)}."
            )
        key = os.environ.get(env_name, "")
        if not key:
            raise RuntimeError(f"Переменная окружения {env_name} пуста — нужен sk-genai-… ключ для {user_id}.")
        return key

    async def probe(self) -> ProbeResult:
        try:
            resp = await self._client.get("/healthz")
            return ProbeResult(reachable=resp.status_code == 200, capabilities=self.capabilities, detail={"status": resp.status_code})
        except httpx.TransportError as exc:
            return ProbeResult(reachable=False, capabilities=self.capabilities, error=str(exc))

    async def reset_state(self) -> None:
        db = self._db()
        if db is None:
            return
        for coll in _COLLECTIONS:
            db[coll].delete_many({})

    async def new_session(self, user_id: str) -> str:
        session_id = f"memnotsafe-{user_id}-{uuid.uuid4().hex[:8]}"
        self._session_users[session_id] = user_id
        return session_id

    async def send(self, session_id: str, message: str) -> SendResult:
        user_id = self._session_users[session_id]
        body = {
            "messages": [{"role": "user", "content": message}],
            "auth_mode": self.auth_mode,
            "session_id": session_id,
        }
        headers = {"Authorization": f"Bearer {self._key_for(user_id)}", "Content-Type": "application/json"}
        resp = await self._client.post("/v1/chat/completions", json=body, headers=headers)
        resp.raise_for_status()
        raw = resp.json()
        return SendResult(content=raw["choices"][0]["message"]["content"], events=[], raw=raw)

    async def close_session(self, session_id: str) -> None:
        user_id = self._session_users.get(session_id)
        if user_id is None:
            return
        headers = {"Authorization": f"Bearer {self._key_for(user_id)}"}
        try:
            await self._client.post(f"/v1/sessions/{session_id}/finalize", headers=headers)
        except httpx.HTTPStatusError:
            await self.send(session_id, self.finalize_keyword)

    def _db(self):
        if not self.mongo_uri:
            return None
        if self._mongo is None:
            import pymongo  # опциональная зависимость — только для этого адаптера

            self._mongo = pymongo.MongoClient(self.mongo_uri)[self.mongo_db]
        return self._mongo

    async def snapshot(self) -> SystemSnapshot | None:
        db = self._db()
        if db is None:
            return None
        global_memory = [_strip(d) for d in db["agent_policy_memories"].find()]
        users: dict[str, list[dict[str, Any]]] = {}
        for coll in ("dialog_sessions", "episodic_memories", "semantic_memories"):
            for doc in db[coll].find():
                uid = str(doc.get("user_id", ""))
                users.setdefault(uid, []).append(_strip(doc))
        return SystemSnapshot(global_memory=global_memory, users=users, metadata={"auth_mode": self.auth_mode})

    async def snapshot_user(self, user_id: str) -> list[dict[str, Any]] | None:
        snap = await self.snapshot()
        return snap.user(user_id) if snap else None

    async def aclose(self) -> None:
        await self._client.aclose()


def _strip(doc: dict[str, Any]) -> dict[str, Any]:
    doc = dict(doc)
    doc.pop("_id", None)
    doc.setdefault("id", doc.get("fact_id") or doc.get("episode_id") or doc.get("policy_id"))
    return doc
