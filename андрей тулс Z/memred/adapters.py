"""Адаптеры мишеней: единый интерфейс «чат / запись памяти / инспекция / сброс».

LocalTarget — наш банковский RAG-ассистент (target/app.py), работает локально.
StandTarget — стенд банка genai-invest-agent-memory-stand:
    • chat:        POST /v1/chat/completions (OpenAI-совместимый, session_id + auth_mode)
    • финализация: POST /v1/sessions/{id}/finalize (перенос рабочей памяти в Mongo)
    • память:      MongoDB agent_memory напрямую (порт 27017 наружу):
                   dialog_sessions, episodic_memories, semantic_memories,
                   agent_policy_memories (без user_id — общий системный промпт)
    • сброс:       очистка четырёх коллекций (сброс состояния между атаками)
Ключ sk-genai-... получается headless: python -m memred.stand_login 1001
"""

import json

import requests


class BaseTarget:
    name = "base"

    def is_up(self) -> bool: ...
    def chat(self, text: str, session_id: str = None) -> dict:
        """Сессия пользователя. Возвращает {answer, sources}."""
        ...
    def ingest(self, text: str, source: str) -> dict:
        """Запись документа в долговременную память."""
        ...
    def dump_memory(self) -> dict:
        """Полное содержимое памяти: {count, documents, metadatas}."""
        ...
    def reset(self) -> dict:
        """Сброс памяти к чистому стартовому состоянию."""
        ...


class LocalTarget(BaseTarget):
    name = "local"

    def __init__(self, base_url: str, timeout: int = 600):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def is_up(self) -> bool:
        try:
            requests.get(f"{self.base}/health", timeout=3).raise_for_status()
            return True
        except Exception:
            return False

    def _post(self, path: str, payload: dict) -> dict:
        r = requests.post(f"{self.base}{path}", json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def chat(self, text: str, session_id: str = None) -> dict:
        payload = {"text": text}
        if session_id:
            payload["session_id"] = session_id
        return self._post("/chat", payload)

    def ingest(self, text: str, source: str) -> dict:
        return self._post("/ingest", {"text": text, "source": source})

    def dump_memory(self) -> dict:
        r = requests.get(f"{self.base}/memory/dump", timeout=120)
        r.raise_for_status()
        return r.json()

    def reset(self) -> dict:
        return self._post("/admin/reset", {})


class StandTarget(BaseTarget):
    name = "stand"

    COLLECTIONS = ("dialog_sessions", "episodic_memories",
                   "semantic_memories", "agent_policy_memories")

    def __init__(self, base_url: str, token: str, cus: str,
                 auth_mode: str = "vulnerable", finalize_word: str = "finalize",
                 mongo_uri: str = "mongodb://localhost:27017",
                 mongo_db: str = "agent_memory", timeout: int = 900):
        self.base = base_url.rstrip("/")
        self.token = token
        self.cus = cus
        self.auth_mode = auth_mode
        self.finalize_word = finalize_word
        self.mongo_uri = mongo_uri
        self.mongo_db = mongo_db
        self.timeout = timeout
        self._counter = 0
        self._mongo = None

    # -- живость ----------------------------------------------------------

    def is_up(self) -> bool:
        try:
            r = requests.get(f"{self.base}/healthz", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    # -- Mongo (память) ----------------------------------------------------

    def _db(self):
        if self._mongo is None:
            import pymongo
            self._mongo = pymongo.MongoClient(self.mongo_uri)[self.mongo_db]
        return self._mongo

    def dump_memory(self) -> dict:
        docs, metas, ids = [], [], []
        for coll in self.COLLECTIONS:
            for rec in self._db()[coll].find():
                rec.pop("_id", None)
                docs.append(json.dumps(rec, ensure_ascii=False, default=str))
                metas.append({"source": coll})
                ids.append(f"{coll}:{rec.get('id', rec.get('created_at', len(ids)))}")
        return {"count": len(docs), "documents": docs, "metadatas": metas, "ids": ids}

    def reset(self) -> dict:
        removed = {}
        for coll in self.COLLECTIONS:
            removed[coll] = self._db()[coll].delete_many({}).deleted_count
        return {"reset": True, "removed": removed}

    # -- чат ---------------------------------------------------------------

    def _chat_raw(self, messages: list, session_id: str = None) -> str:
        self._counter += 1
        payload = {
            "messages": messages,
            "auth_mode": self.auth_mode,
            "session_id": session_id or f"memred-{self.cus}-{self._counter}",
            "stream": False,
        }
        r = requests.post(
            f"{self.base}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def chat(self, text: str, session_id: str = None) -> dict:
        answer = self._chat_raw([{"role": "user", "content": text}],
                                session_id=session_id)
        return {"answer": answer, "sources": []}

    def finalize(self, session_id: str) -> dict:
        r = requests.post(
            f"{self.base}/v1/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def ingest(self, text: str, source: str) -> dict:
        # На стенде запись в долговременную память идёт через диалог+finalize.
        sid = f"memred-{self.cus}-ingest-{self._counter + 1}"
        self._chat_raw([{"role": "user", "content": f"[{source}]\n{text}"}], session_id=sid)
        state = self.finalize(sid)
        return {"status": "ok", "finalize": state, "source": source}


def build_target(cfg: dict) -> BaseTarget:
    kind = cfg.get("target", "local")
    if kind == "local":
        return LocalTarget(cfg["local"]["base_url"])
    if kind == "stand":
        from .stand_login import load_api_key
        s = cfg["stand"]
        store = s.get("key_store") or "stand_key.json"
        token = s.get("token") or load_api_key(s.get("cus", "1001"),
                                               store=store,
                                               login_cfg=s.get("login") or {})
        return StandTarget(s["base_url"], token, s.get("cus", "1001"),
                           s.get("auth_mode", "vulnerable"),
                           s.get("finalize_word", "finalize"),
                           s.get("mongo_uri", "mongodb://localhost:27017"),
                           s.get("mongo_db", "agent_memory"))
    raise ValueError(f"Неизвестный тип мишени: {kind}")
