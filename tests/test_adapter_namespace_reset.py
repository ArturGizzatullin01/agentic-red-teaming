"""tests/test_adapter_namespace_reset.py — CARD-P13-b (W7/G3.1): режим
scope="namespace" у reset_state адаптера investment_stand.

Глобальный reset (дефолт, без изменений) чистит все 4 коллекции
delete_many({}) — при двух параллельных воркерах reset одного стирает опыт
другого (G3.1 FAIL). Namespace-режим удаляет ТОЛЬКО документы, принадлежащие
сессиям ЭТОГО экземпляра адаптера (sessions создаются new_session =
memnotsafe-{user}-{uuid4.hex[:8]}).

Атрибуция — по коду записи стенда (не выдумана):
  - dialog_sessions: поле session_id (persist_dialog, mongo.py:65; сам адаптер
    читает его в _read_session_docs);
  - episodic_memories: поля session_id и source_session, оба = id сессии
    (finalize-узел, orchestrator/graph.py:111-116);
  - semantic_memories: session-поля НЕТ; привязка факта к сессии — только
    source_episode_id → episode_id эпизода финалайза этой сессии, поле
    nullable (graph.py:138-144: None, когда у сессии нет эпизодов);
  - agent_policy_memories: глобальная коллекция (G3.2), в namespace-режиме
    не трогается ВООБЩЕ.

Все тесты офлайн: поддельный клиент через seam _db() (паттерн
test_investment_stand_adapter.py), Mongo/сеть/стенд не поднимаются.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from memnotsafe.adapters.investment_stand import (
    _COLLECTIONS,
    InvestmentStandAdapter,
)

_IDENTITIES = {"2001": "SK_W1_A", "2002": "SK_W1_B", "3001": "SK_W2_A"}


# --------------------------------------------------------------------- фальшивый Mongo


class _FakeCollection:
    """Поддельная коллекция: ровно те операции, которые зовёт reset_state
    (find с {"$in"}-фильтром и delete_many), с журналом вызовов и фильтров."""

    def __init__(self, name: str, docs: list[dict], calls: list[tuple[str, dict]]):
        self.name = name
        self.docs = docs
        self.calls = calls

    @staticmethod
    def _matches(doc: dict, flt: dict) -> bool:
        for field, cond in flt.items():
            if isinstance(cond, dict):
                if doc.get(field) not in cond.get("$in", ()):
                    return False
            elif doc.get(field) != cond:
                return False
        return True

    def find(self, flt: dict | None = None) -> list[dict]:
        return [dict(d) for d in self.docs if self._matches(d, flt or {})]

    def delete_many(self, flt: dict) -> None:
        self.calls.append((self.name, flt))
        self.docs[:] = [d for d in self.docs if not self._matches(d, flt)]


class _FakeDb:
    def __init__(self, store: dict[str, list[dict]]):
        self.calls: list[tuple[str, dict]] = []
        self.collections = {
            name: _FakeCollection(name, docs, self.calls)
            for name, docs in store.items()
        }

    def __getitem__(self, name: str) -> _FakeCollection:
        return self.collections[name]


def _foreign_seed() -> dict[str, list[dict]]:
    """Стартовое состояние Mongo: только документы ЧУЖОГО воркера W2. W2 трогал
    ТОГО ЖЕ пользователя 2002, что и W1 — выживание его документов доказывает
    атрибуцию по session_id, а не по user_id (иначе W7 не закрыт). Свои
    документы добавляет _inject_own() с РЕАЛЬНЫМИ id сессий адаптера."""
    return {
        "dialog_sessions": [
            {"user_id": "3001", "session_id": "memnotsafe-3001-w2cccccc"},
            {"user_id": "2002", "session_id": "memnotsafe-2002-w2dddddd"},
        ],
        "episodic_memories": [
            {
                "episode_id": "ep-w2-victim",
                "user_id": "3001",
                "session_id": "memnotsafe-3001-w2cccccc",
                "source_session": "memnotsafe-3001-w2cccccc",
                "summary": "эпизод чужого воркера W2",
            },
        ],
        "semantic_memories": [
            {
                "fact_id": "fact-w2",
                "fact": "факт из эпизода W2",
                "scope": "user",
                "user_id": "3001",
                "source_episode_id": "ep-w2-victim",
            },
            {
                "fact_id": "fact-orphan",
                "fact": "факт без ссылки на эпизод",
                "scope": "user",
                "user_id": "2001",
                "source_episode_id": None,
            },
        ],
        "agent_policy_memories": [
            {
                "policy_id": "pol-w1",
                "statement": "политика, рождённая сессией W1",
                "source_session_id": "memnotsafe-2001-w1ownseed",
            },
            {
                "policy_id": "pol-w2",
                "statement": "политика чужого воркера",
                "source_session_id": "memnotsafe-3001-w2cccccc",
            },
        ],
    }


def _inject_own(store: dict[str, list[dict]], own: list[str]) -> None:
    """Документы СВОИХ сессий W1 — по схеме записи финалайза стенда, с
    настоящими id сессий адаптера (диалог + эпизод с session_id/source_session,
    факт с source_episode_id на этот эпизод)."""
    store["dialog_sessions"].append({"user_id": "2001", "session_id": own[0]})
    store["dialog_sessions"].append({"user_id": "2002", "session_id": own[1]})
    store["episodic_memories"].append({
        "episode_id": "ep-w1-attacker",
        "user_id": "2001",
        "session_id": own[0],
        "source_session": own[0],
        "summary": "эпизод доставки W1",
    })
    store["semantic_memories"].append({
        "fact_id": "fact-w1",
        "fact": "факт из эпизода W1",
        "scope": "user",
        "user_id": "2001",
        "source_episode_id": "ep-w1-attacker",
    })


class _SeededStand(InvestmentStandAdapter):
    """Адаптер на поддельном Mongo: без сети, без pymongo. Сессии воркера W1
    создаются настоящим new_session (реальный префикс memnotsafe-…)."""

    def __init__(self, store: dict[str, list[dict]], **kw):
        kw.setdefault("identities", _IDENTITIES)
        kw.setdefault("mongo_uri", "mongodb://fake")
        super().__init__(base_url="http://fake", **kw)
        self.db = _FakeDb(store)

    def _db(self) -> _FakeDb:
        return self.db


async def _open_sessions(adapter: _SeededStand, users: list[str]) -> list[str]:
    return [await adapter.new_session(u) for u in users]


# --------------------------------------------------------- namespace: чужое выживает


def test_namespace_reset_deletes_only_own_session_documents(tmp_path) -> None:
    store = _foreign_seed()
    adapter = _SeededStand(store, scope="namespace")
    own = asyncio.run(_open_sessions(adapter, ["2001", "2002"]))
    _inject_own(store, own)

    asyncio.run(adapter.reset_state())

    # Свои диалоги удалены, чужие живы — включая сессию ТОГО ЖЕ пользователя
    # 2002 у чужого воркера (атрибуция по session_id, не по владельцу-юзеру).
    dialogs = {d["session_id"] for d in store["dialog_sessions"]}
    assert own[0] not in dialogs and own[1] not in dialogs
    assert dialogs == {"memnotsafe-3001-w2cccccc", "memnotsafe-2002-w2dddddd"}

    # Свои эпизоды удалены, чужой жив.
    episodes = {e["episode_id"] for e in store["episodic_memories"]}
    assert episodes == {"ep-w2-victim"}

    # Факт, связанный со СВОИМ эпизодом (source_episode_id), удалён; факт
    # чужого эпизода жив; факт без ссылки на эпизод (None — session-поля у
    # фактов нет) не атрибутируем и честно выживает.
    facts = {f["fact_id"] for f in store["semantic_memories"]}
    assert facts == {"fact-w2", "fact-orphan"}


def test_namespace_reset_delete_filters_never_global() -> None:
    """Замок против деградации до delete_many({}): каждый фильтр обязан быть
    скоупленным, порядок вызовов детерминирован, пустых фильтров нет."""
    store = _foreign_seed()
    adapter = _SeededStand(store, scope="namespace")
    own = asyncio.run(_open_sessions(adapter, ["2001", "2002"]))
    _inject_own(store, own)

    asyncio.run(adapter.reset_state())

    names = [name for name, _flt in adapter.db.calls]
    assert names == ["dialog_sessions", "episodic_memories", "semantic_memories"]
    filters = [flt for _name, flt in adapter.db.calls]
    assert all(flt for flt in filters), f"пустой (глобальный) фильтр: {filters}"
    assert filters[0] == {"session_id": {"$in": own}}
    assert filters[1] == {"session_id": {"$in": own}}
    assert filters[2] == {"source_episode_id": {"$in": ["ep-w1-attacker"]}}


def test_namespace_reset_leaves_agent_policy_memories_untouched() -> None:
    """G3.2: глобальная коллекция в namespace-режиме недосягаема — состав
    документов побайтово тот же, ни одного вызова delete_many по ней."""
    store = _foreign_seed()
    before = json.dumps(store["agent_policy_memories"], sort_keys=True)
    adapter = _SeededStand(store, scope="namespace")
    own = asyncio.run(_open_sessions(adapter, ["2001", "2002"]))
    _inject_own(store, own)

    asyncio.run(adapter.reset_state())

    assert json.dumps(store["agent_policy_memories"], sort_keys=True) == before
    assert all(name != "agent_policy_memories" for name, _ in adapter.db.calls)
    assert adapter.run_metadata()["reset_available"] is True


def test_namespace_reset_without_own_sessions_is_noop() -> None:
    """Первая попытка воркера: своих сессий ещё нет — reset не должен дотро-
    гнуться НИ ДО ОДНОЙ коллекции (в т.ч. чужих документов)."""
    store = _foreign_seed()
    adapter = _SeededStand(store, scope="namespace")

    asyncio.run(adapter.reset_state())

    assert adapter.db.calls == []
    assert adapter.run_metadata()["reset_available"] is True
    assert {d["session_id"] for d in store["dialog_sessions"]} == {
        "memnotsafe-3001-w2cccccc",
        "memnotsafe-2002-w2dddddd",
    }


# ------------------------------------------------------------------ дефолт: глобальный


def test_default_scope_wipes_all_four_collections() -> None:
    """Дефолт (scope не передан) — прежнее поведение побайтово: delete_many({})
    по всем 4 коллекциям в порядке _COLLECTIONS."""
    store = _foreign_seed()
    adapter = _SeededStand(store)

    asyncio.run(adapter.reset_state())

    assert [(name, flt) for name, flt in adapter.db.calls] == [
        (coll, {}) for coll in _COLLECTIONS
    ]
    for docs in store.values():
        assert docs == []
    assert adapter.run_metadata()["reset_available"] is True


def test_explicit_global_scope_wipes_all_four_collections() -> None:
    """Явный scope="global" идентичен дефолту."""
    store = _foreign_seed()
    adapter = _SeededStand(store, scope="global")

    asyncio.run(adapter.reset_state())

    assert [(name, flt) for name, flt in adapter.db.calls] == [
        (coll, {}) for coll in _COLLECTIONS
    ]
    for docs in store.values():
        assert docs == []


def test_unknown_scope_rejected_loudly() -> None:
    """Опечатка в scope не имеет права молчно включить глобальный reset
    (W7): неизвестное значение — громкий отказ конфигурации при создании."""
    with pytest.raises(ValueError, match="scope"):
        _SeededStand(_foreign_seed(), scope="namespac")


# ------------------------------------------------------------------- metadata прогона


def test_snapshot_metadata_carries_reset_scope() -> None:
    """Режим виден в артефактах существующим механизмом адаптера — metadata
    снимка (рядом с auth_mode) и run_metadata(); без новых полей в схеме
    attempts.jsonl. Дефолт ключ НЕ добавляет — побайтово прежний (карточка),
    namespace помечает себя явно."""
    namespaced = _SeededStand(_foreign_seed(), scope="namespace")
    glob = _SeededStand(_foreign_seed())
    assert namespaced._build_snapshot({}).metadata["reset_scope"] == "namespace"
    assert namespaced.run_metadata()["reset_scope"] == "namespace"
    assert "reset_scope" not in glob._build_snapshot({}).metadata
    assert "reset_scope" not in glob.run_metadata()


# ------------------------------------------------------------------- деградация прав


class _NoWriteDb:
    """Чтение есть, записи нет: find отвечает, delete_many падает."""

    def __init__(self):
        self.deleted: list[str] = []

    def __getitem__(self, name: str):
        db = self

        class _Coll:
            def find(self, _flt):
                return []

            def delete_many(self, _flt):
                db.deleted.append(name)
                raise PermissionError("read-only")

        return _Coll()


class _NoWriteStand(InvestmentStandAdapter):
    def __init__(self, **kw):
        kw.setdefault("identities", _IDENTITIES)
        kw.setdefault("mongo_uri", "mongodb://fake")
        super().__init__(base_url="http://fake", **kw)
        self.no_write_db = _NoWriteDb()

    def _db(self):
        return self.no_write_db


def test_namespace_reset_without_write_rights_degrades() -> None:
    """Нет прав на запись → reset_available=false, без падения (оба режима)."""
    namespaced = _NoWriteStand(scope="namespace")
    asyncio.run(_open_sessions(namespaced, ["2001"]))
    asyncio.run(namespaced.reset_state())
    assert namespaced.run_metadata()["reset_available"] is False

    glob = _NoWriteStand(scope="global")
    asyncio.run(glob.reset_state())
    assert glob.run_metadata()["reset_available"] is False


def test_namespace_reset_without_mongo_marks_unavailable() -> None:
    adapter = InvestmentStandAdapter(
        base_url="http://fake", identities=_IDENTITIES, mongo_uri=None, scope="namespace"
    )
    asyncio.run(adapter.reset_state())
    assert adapter._reset_available is False
    assert adapter.run_metadata()["reset_available"] is False
