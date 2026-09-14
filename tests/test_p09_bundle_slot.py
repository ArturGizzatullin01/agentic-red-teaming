"""tests/test_p09_bundle_slot.py — слот context_tool_evidence в EvidenceBundle
(P09-full, фича 010): опциональность при чтении, семантика статусов,
fail-fast записи, структурная валидация при replay. Всё офлайн."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.evidence.bundle import (  # noqa: E402
    BUNDLE_SLOTS,
    BundleError,
    read_bundle,
    write_bundle,
)
from memnotsafe.evidence.telemetry import (  # noqa: E402
    PHASE_M3_TRIGGER_FINALIZE,
    SOURCE_EXTERNAL_TELEMETRY,
    TELEMETRY_SCHEMA_VERSION,
    parse_context_tool_evidence,
)


def _valid_record() -> dict:
    """Минимальная валидная запись телеметрии (копия эталона из
    test_p09_full_offline; файлы сознательно самодостаточны)."""
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "effective_context": [
            {
                "phase": PHASE_M3_TRIGGER_FINALIZE,
                "session_id": "sess-victim-1",
                "actor_user_id": "1003",
                "source": SOURCE_EXTERNAL_TELEMETRY,
                "records": [
                    {"record_id": "mem-1", "fragment": "правило", "truncated": False,
                     "scope": "global", "source_user": "1001"},
                ],
            }
        ],
        "actual_tool_calls": [
            {"call_id": "call-a1", "session_id": "sess-victim-1", "actor_user_id": "1003",
             "phase": PHASE_M3_TRIGGER_FINALIZE, "tool": "portfolio", "args": {"cus": "1003"},
             "case_marker": None},
        ],
        "adapter_tool_calls": [
            {"call_id": "call-a1", "session_id": "sess-victim-1", "actor_user_id": "1003",
             "phase": PHASE_M3_TRIGGER_FINALIZE, "tool": "portfolio", "args": {"cus": "1003"},
             "case_marker": None},
        ],
        "tool_log_complete": True,
        "channel": {"heartbeat_alive": True, "heartbeat_counter": 7},
        "stand_version": "mock-1",
        "chat_prompt_revision": None,
    }


def _bundle_kwargs(tmp_path: Path) -> dict:
    return dict(
        run_id="RUN-p09",
        case_id="CASE-p09-1",
        attempt_no=1,
        experiment_id=None,
        candidate_id="CASE-p09-1",
        goal_digest=None,
    )


def test_bundle_slot_write_read_roundtrip(tmp_path: Path) -> None:
    payload = parse_context_tool_evidence(_valid_record())
    bundle = write_bundle(
        tmp_path / "b1", **_bundle_kwargs(tmp_path), payloads={"context_tool_evidence": payload}
    )
    assert bundle.present("context_tool_evidence")
    reread = read_bundle(tmp_path / "b1")
    assert reread.present("context_tool_evidence")
    artifact = json.loads((tmp_path / "b1" / "artifacts" / "context_tool_evidence.json").read_text(encoding="utf-8"))
    assert artifact["actual_tool_calls"][0]["call_id"] == "call-a1"


def test_bundle_slot_unavailable_and_absent_semantics(tmp_path: Path) -> None:
    # слот упомянут, но телеметрии нет → unavailable (не absent, не present)
    write_bundle(tmp_path / "b2", **_bundle_kwargs(tmp_path), payloads={"context_tool_evidence": None})
    b2 = read_bundle(tmp_path / "b2")
    assert b2.slots["context_tool_evidence"].status == "unavailable"
    # слот вовсе не упомянут → absent (историческое поведение остальных слотов)
    write_bundle(tmp_path / "b3", **_bundle_kwargs(tmp_path))
    b3 = read_bundle(tmp_path / "b3")
    assert b3.slots["context_tool_evidence"].status == "absent"


def test_historical_bundle_without_new_slot_reads_as_absent(tmp_path: Path) -> None:
    write_bundle(tmp_path / "b4", **_bundle_kwargs(tmp_path))
    manifest_path = tmp_path / "b4" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # эмулируем ИСТОРИЧЕСКИЙ манифест: нового слота в нём нет вовсе
    manifest["slots"].pop("context_tool_evidence", None)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    bundle = read_bundle(tmp_path / "b4")
    assert bundle.slots["context_tool_evidence"].status == "absent"
    assert bundle.slots["m0"].status == "absent"


def test_bundle_rejects_structurally_invalid_slot_content_even_with_fresh_checksum(tmp_path: Path) -> None:
    # подмена контента с ПЕРЕСЧИТАННЫМ манифестом: checksum честный, но
    # содержимое нарушает контракт телеметрии (call_id пуст) — replay обязан
    # это поймать структурной валидацией, а не только checksum.
    payload = parse_context_tool_evidence(_valid_record())
    write_bundle(tmp_path / "b5", **_bundle_kwargs(tmp_path), payloads={"context_tool_evidence": payload})
    artifact = tmp_path / "b5" / "artifacts" / "context_tool_evidence.json"
    broken = json.loads(artifact.read_text(encoding="utf-8"))
    broken["actual_tool_calls"][0]["call_id"] = ""
    artifact.write_text(
        json.dumps(broken, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )
    manifest_path = tmp_path / "b5" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    data = artifact.read_bytes()
    slot = manifest["slots"]["context_tool_evidence"]
    slot["sha256"] = hashlib.sha256(data).hexdigest()
    slot["bytes"] = len(data)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    with pytest.raises(BundleError):
        read_bundle(tmp_path / "b5")


def test_bundle_write_rejects_invalid_payload_fail_fast(tmp_path: Path) -> None:
    with pytest.raises(BundleError):
        write_bundle(
            tmp_path / "b6",
            **_bundle_kwargs(tmp_path),
            payloads={"context_tool_evidence": {"случайный": "мусор"}},
        )


def test_bundle_core_slots_unchanged() -> None:
    # ядро обязательных слотов не сужалось
    for slot in ("m0", "m1", "m2", "m3", "transcript", "settle", "candidate", "memory_diff", "tool_events", "trace"):
        assert slot in BUNDLE_SLOTS
