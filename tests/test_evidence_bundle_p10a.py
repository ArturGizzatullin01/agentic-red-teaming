"""tests/test_evidence_bundle_p10a.py — P10a (фича 007): EvidenceBundle.

Проверяется: запись/чтение с checksums; атомарность (незавершённый пакет не
выдаётся за завершённый); обнаружение повреждения/подмены; запрет путей вне
пакета; unavailable ≠ absent; старые runs без пакетов; секреты не попадают в
манифест; реальная кампания пишет пакеты для каждого случая.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memnotsafe.evidence.bundle import (
    BUNDLE_SLOTS,
    STATUS_ABSENT,
    STATUS_PRESENT,
    STATUS_UNAVAILABLE,
    BundleError,
    find_bundles,
    read_bundle,
    verify_run_bundles,
    write_bundle,
)


def _write(tmp_path: Path, **kw):
    return write_bundle(
        tmp_path / "bundle",
        run_id="RUN-T",
        case_id="CASE-x-001-aaaaaa",
        payloads={"m0": {"users": {"1001": []}}, "transcript": {"messages": ["hi"]}},
        **kw,
    )


def test_write_read_roundtrip_with_checksums(tmp_path) -> None:
    bundle = _write(tmp_path)
    assert bundle.sealed
    read = read_bundle(tmp_path / "bundle")
    assert read.case_id == "CASE-x-001-aaaaaa"
    assert read.present("m0") and read.present("transcript")
    assert read.slots["m0"].sha256  # checksum зафиксирован
    assert read.slots["tool_events"].status == STATUS_ABSENT  # слот не упоминался
    # все слоты пакета перечислены, никаких безымянных
    assert set(read.slots) == set(BUNDLE_SLOTS)


def test_unavailable_is_not_absent(tmp_path) -> None:
    """None в payloads = телеметрия не наблюдала (unavailable), а не «слота
    не было» (absent). Подмена одного другим запрещена контрактом."""
    write_bundle(
        tmp_path / "b2",
        run_id="RUN-T", case_id="CASE-y-002-bbbbbb",
        payloads={"m1": None, "transcript": {"messages": []}},
        files={"trace": None},
    )
    read = read_bundle(tmp_path / "b2")
    assert read.slots["m1"].status == STATUS_UNAVAILABLE
    assert read.slots["trace"].status == STATUS_UNAVAILABLE
    assert read.slots["m0"].status == STATUS_ABSENT


def test_incomplete_package_is_rejected(tmp_path) -> None:
    _write(tmp_path)
    (tmp_path / "bundle" / "manifest.json").unlink()
    with pytest.raises(BundleError, match="незавершён"):
        read_bundle(tmp_path / "bundle")

    # распечатанный (sealed=false) манифест — тоже незавершённый пакет
    write_bundle(tmp_path / "b3", run_id="R", case_id="CASE-z-003-cccccc", payloads={"m0": {}})
    manifest_path = tmp_path / "b3" / "manifest.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["sealed"] = False
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(BundleError, match="незавершён"):
        read_bundle(tmp_path / "b3")


def test_tmp_manifest_does_not_pass_as_complete(tmp_path) -> None:
    """Атомарность: tmp-файл манифеста (сбой до os.replace) не делает пакет
    завершённым — read_bundle смотрит только на финальный manifest.json."""
    write_bundle(tmp_path / "b4", run_id="R", case_id="CASE-w-004-dddddd", payloads={"m0": {}})
    (tmp_path / "b4" / "manifest.json").unlink()
    (tmp_path / "b4" / "manifest.json.tmp").write_text("{}", encoding="utf-8")
    with pytest.raises(BundleError):
        read_bundle(tmp_path / "b4")


def test_corrupted_artifact_is_detected(tmp_path) -> None:
    _write(tmp_path)
    artifact = tmp_path / "bundle" / "artifacts" / "m0.json"
    artifact.write_text('{"users": {"9999": ["подменено"]}}', encoding="utf-8")
    with pytest.raises(BundleError, match="m0"):
        read_bundle(tmp_path / "bundle")


def test_path_traversal_in_manifest_is_rejected(tmp_path) -> None:
    _write(tmp_path)
    manifest_path = tmp_path / "bundle" / "manifest.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["slots"]["m0"]["path"] = "../outside.json"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(BundleError, match="вне пакета"):
        read_bundle(tmp_path / "bundle")


def test_schema_version_mismatch_is_explicit(tmp_path) -> None:
    _write(tmp_path)
    manifest_path = tmp_path / "bundle" / "manifest.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["schema_version"] = 99
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(BundleError, match="schema_version"):
        read_bundle(tmp_path / "bundle")


def test_missing_artifact_file_is_detected(tmp_path) -> None:
    _write(tmp_path)
    (tmp_path / "bundle" / "artifacts" / "transcript.json").unlink()
    with pytest.raises(BundleError, match="transcript"):
        read_bundle(tmp_path / "bundle")


def test_old_runs_without_bundles_read_as_empty(tmp_path) -> None:
    assert find_bundles(tmp_path) == {}
    assert verify_run_bundles(tmp_path) == 0


def test_find_bundles_skips_unsealed_directories(tmp_path) -> None:
    import shutil

    _write(tmp_path)
    (tmp_path / "run" / "bundles" / "CASE-partial").mkdir(parents=True)  # манифеста нет
    shutil.copytree(tmp_path / "bundle", tmp_path / "run" / "bundles" / "CASE-x-001-aaaaaa")
    found = find_bundles(tmp_path / "run")
    assert set(found) == {"CASE-x-001-aaaaaa"}  # незавершённый каталог не считается


def test_manifest_carries_no_secrets(tmp_path) -> None:
    """Секрет не попадает в манифест: пакет строится только из явно переданных
    идентификаторов/статусов/checksums."""
    secret = "sk-super-secret-value"
    write_bundle(
        tmp_path / "b5",
        run_id="R", case_id="CASE-s-005-eeeeee",
        payloads={"candidate": {"payload": "текст", "api_key_env": "ATTACKER_API_KEY",
                                "note": secret}},
    )
    # значение ключа в payload-артефакте — данные попытки, это файл кейса, не
    # манифест; манифест же содержит только статусы/пути/checksums:
    manifest_text = (tmp_path / "b5" / "manifest.json").read_text(encoding="utf-8")
    assert secret not in manifest_text
    assert "ATTACKER_API_KEY" not in manifest_text


def test_verify_run_bundles_counts_and_verifies(tmp_path) -> None:
    import shutil

    _write(tmp_path)
    shutil.copytree(tmp_path / "bundle", tmp_path / "bundles" / "CASE-x-001-aaaaaa")
    assert verify_run_bundles(tmp_path) == 1
    (tmp_path / "bundles" / "CASE-x-001-aaaaaa" / "artifacts" / "m0.json").write_text("{}", encoding="utf-8")
    with pytest.raises(BundleError):
        verify_run_bundles(tmp_path)


# ------------------------------------------------- интеграция с кампанией

def test_campaign_writes_bundle_per_case(tmp_path) -> None:
    """Реальный writer кампании оставляет sealed-пакет на каждый случай;
    слоты m0/m1/m2/m3/transcript/settle/candidate у mock-прогона present."""
    import asyncio

    from memnotsafe.adapters.mock import MockTarget
    from memnotsafe.core.campaign import Campaign
    from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec

    scenario = Scenario(
        id="cross_user_bac", path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
    )
    out = tmp_path / "run"
    Campaign(scenario, MockTarget(vulnerable=True), out)
    asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    found = find_bundles(out)
    assert len(found) == 1
    bundle = read_bundle(next(iter(found.values())))
    for slot in ("m0", "m1", "m2", "m3", "transcript", "settle", "candidate"):
        assert bundle.present(slot), slot
    assert bundle.goal_digest  # цель валидна → digest записан
    # пакет внутренне согласован: полная верификация проходит
    assert verify_run_bundles(out) == 1
    # evidence содержит аддитивную ссылку на пакет
    campaign = json.loads((out / "campaign.json").read_text(encoding="utf-8"))
    assert campaign["results"][0]["evidence"]["evidence_bundle"].startswith("bundles/")


def test_bundle_write_failure_does_not_kill_the_run(tmp_path, monkeypatch) -> None:
    """Сбой записи пакета (диск/права) не роняет прогон: вердикты важнее
    доказательственной надстройки (см. докстринг _write_evidence_bundle)."""
    import asyncio

    from memnotsafe.adapters.mock import MockTarget
    from memnotsafe.core.campaign import Campaign
    from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec
    from memnotsafe.evidence import bundle as bundle_mod

    scenario = Scenario(
        id="cross_user_bac", path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
    )

    def broken_write(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(bundle_mod, "write_bundle", broken_write)
    out = tmp_path / "run"
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    assert len(result.results) == 1
    assert "evidence_bundle" not in result.results[0].evidence
