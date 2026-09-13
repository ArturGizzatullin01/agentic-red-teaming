"""P09-lite (glm/write-marker-snapshots): захват тела HTTP-finalize.

Приёмка (гэп 1 пакета Astra-6): адаптер больше не выбрасывает resp.json()
finalize — предложенные писателем episodes/facts попадают в metadata снимков
(фазовая привязка бесплатна: M0 несёт baseline-finalize, M1 — delivery, M3 —
trigger). Не-JSON — усечённый raw_text; ошибка чтения тела не роняет close;
reset_state очищает лог; чат-фолбэк тела не даёт (честный gap).
"""

from __future__ import annotations

import asyncio

import httpx

from memnotsafe.adapters.investment_stand import InvestmentStandAdapter


class FinalizeStubStand(InvestmentStandAdapter):
    """Seam-подмена HTTP-финалайза телом ответа; Mongo-чтение заглушено."""

    def __init__(self, *, payload, status: int = 200):
        super().__init__(base_url="http://fake", identities={"1001": "SK_A"}, mongo_uri="mongodb://fake")
        self.payload = payload
        self.status = status
        self.chat_calls: list[str] = []

    def _read_all_docs(self):
        return {}

    def _db(self):
        return None  # reset_state честно пометит reset_available=false, без Mongo

    async def _post_finalize(self, session_id: str) -> httpx.Response:
        if isinstance(self.payload, Exception):
            raise self.payload
        return httpx.Response(
            self.status, request=httpx.Request("POST", "http://fake/v1/sessions/x/finalize"),
            json=self.payload,
        )

    async def send(self, session_id: str, message: str):  # type: ignore[override]
        self.chat_calls.append(message)
        from memnotsafe.adapters.base import SendResult
        return SendResult(content="ok")


def _session(adapter) -> str:
    return asyncio.run(adapter.new_session("1001"))


def test_finalize_body_captured_into_snapshot_metadata():
    body = {"episodes": ["эпизод-1"], "facts": [{"fact": "факт-1", "scope": "user"}]}
    adapter = FinalizeStubStand(payload=body)
    sid = _session(adapter)
    asyncio.run(adapter.close_session(sid))
    snap = asyncio.run(adapter.snapshot())
    log = snap.metadata["finalize_bodies"]
    assert len(log) == 1
    assert log[0]["session_id"] == sid
    assert log[0]["user_id"] == "1001"
    assert log[0]["body"] == body
    # каждый последующий снимок несёт накопленный лог (фазовая привязка)
    snap2 = asyncio.run(adapter.snapshot())
    assert snap2.metadata["finalize_bodies"] == log


def test_finalize_non_json_body_stored_as_raw_text():
    adapter = FinalizeStubStand(payload=None)
    adapter.payload = None
    # подменяем ответ на не-JSON: Response(None) нельзя, имитируем через Exception-путь ниже
    class RawStand(FinalizeStubStand):
        async def _post_finalize(self, session_id: str) -> httpx.Response:
            return httpx.Response(200, request=httpx.Request("POST", "http://fake/finalize"), text="<html>not json</html>")

    raw = RawStand(payload=None)
    sid = _session(raw)
    asyncio.run(raw.close_session(sid))
    snap = asyncio.run(raw.snapshot())
    entry = snap.metadata["finalize_bodies"][0]
    assert entry["body"]["raw_text"] == "<html>not json</html>"


def test_finalize_body_capture_does_not_break_close_on_weird_response():
    class BrokenResponse(httpx.Response):
        def json(self):
            raise RuntimeError("boom")

        @property
        def text(self):
            raise RuntimeError("boom")

    class BrokenBodyStand(FinalizeStubStand):
        async def _post_finalize(self, session_id: str) -> httpx.Response:
            return BrokenResponse(200, request=httpx.Request("POST", "http://fake/finalize"))

    adapter = BrokenBodyStand(payload={"ok": True})
    sid = _session(adapter)
    asyncio.run(adapter.close_session(sid))  # не падает
    snap = asyncio.run(adapter.snapshot())
    assert snap.metadata["finalize_bodies"] == []  # диагностика молчит, close выполнен


def test_reset_state_clears_finalize_log():
    adapter = FinalizeStubStand(payload={"facts": []})
    sid = _session(adapter)
    asyncio.run(adapter.close_session(sid))
    assert len(asyncio.run(adapter.snapshot()).metadata["finalize_bodies"]) == 1
    asyncio.run(adapter.reset_state())
    assert asyncio.run(adapter.snapshot()).metadata["finalize_bodies"] == []


def test_chat_fallback_yields_no_body():
    adapter = FinalizeStubStand(payload=httpx.HTTPStatusError(
        "404", request=httpx.Request("POST", "http://fake"), response=httpx.Response(404, request=httpx.Request("POST", "http://fake")),
    ))
    sid = _session(adapter)
    asyncio.run(adapter.close_session(sid))
    assert adapter.chat_calls == ["finalize"]  # фолбэк сработал
    assert asyncio.run(adapter.snapshot()).metadata["finalize_bodies"] == []  # тела нет — честный gap
