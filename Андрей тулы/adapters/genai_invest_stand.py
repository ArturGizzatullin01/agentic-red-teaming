"""adapters/genai_invest_stand.py — evidence-адаптер для genai-invest-agent-memory-stand.

Стенд-специфика живёт здесь, а не в core/evidence.py (правило CLAUDE.md). Читаем Mongo
НАПРЯМУЮ (pymongo), а не через `GET /memory`: та ручка отдаёт HTML и авторизуется
X-Forwarded-Access-Token от oauth2-proxy (Keycloak SSO-сессия) — не Bearer sk-genai-…
ключом, которым бьёт /v1/chat/completions (см. app/api_server.py:_current_identity).
Для headless-автоматизации это тупик без полного OIDC-флоу; порт Mongo `27017` при этом
проброшен наружу в docker-compose.yml — прямое чтение той же схемы, что видит
app/memory/mongo.py, надёжнее и не требует иной инфраструктуры.

Мы намеренно НЕ импортируем app.memory.models целевого стенда (не тащим его как
зависимость нашего инструмента — чёрный ящик должен собираться и работать, даже если
исходники таргета недоступны локально). Вместо этого читаем сырые документы по тем же
именам полей, которые эта версия стенда фактически пишет.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from pymongo import MongoClient

from core.evidence import EvidenceSource, MemorySnapshot


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _strip_ids(docs: list[dict]) -> list[dict]:
    out = []
    for d in docs:
        d = dict(d)
        d.pop("_id", None)
        out.append(d)
    return out


@dataclass
class MongoEvidenceSourceConfig:
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "agent_memory"
    agent_policy_limit: int = 500


class MongoEvidenceSource(EvidenceSource):
    def __init__(self, config: MongoEvidenceSourceConfig | None = None):
        self.config = config or MongoEvidenceSourceConfig()
        self._client = MongoClient(self.config.mongo_uri)
        self._db = self._client[self.config.mongo_db]

    def close(self) -> None:
        self._client.close()

    def snapshot(self, user_id: str) -> MemorySnapshot:
        dialog = _strip_ids(list(self._db["dialog_sessions"].find({"user_id": user_id})))
        episodic = _strip_ids(list(self._db["episodic_memories"].find({"user_id": user_id})))
        semantic = _strip_ids(list(self._db["semantic_memories"].find({"user_id": user_id})))
        # agent_policy_memories: НЕ фильтруем по user_id — уровень структурно без него,
        # это и есть суть уязвимости (виден всем клиентам, source_session_id — только аудит).
        policy = _strip_ids(
            list(
                self._db["agent_policy_memories"]
                .find({})
                .sort("created_at", -1)
                .limit(self.config.agent_policy_limit)
            )
        )
        return MemorySnapshot(
            ts=_utc_now(),
            user_id=user_id,
            dialog_sessions=dialog,
            episodic_memories=episodic,
            semantic_memories=semantic,
            agent_policy_memories=policy,
            source="mongo_direct",
        )
