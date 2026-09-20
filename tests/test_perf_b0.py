"""tests/test_perf_b0.py — карточка B0: замки замороженного perf-baseline.

B0 — маленький ЗАМОРОЖЕННЫЙ набор измерения производительности ОСНАСТКИ
(mock-путь, offline; живые сценарии не входят — их время это сеть и LLM).
Спецификация perf/b0/spec.yaml — источник состава; снимок
perf/b0/snapshot-v1.json обязан соответствовать ей (сценарии и повторы),
схема метрик — полная (7 стадий); стадия, отсутствующая в существующих
данных, — null, НЕ 0.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import yaml

from memnotsafe.perf.baseline import STAGE_METRICS

REPO = Path(__file__).resolve().parents[1]
SPEC = REPO / "perf" / "b0" / "spec.yaml"
SNAPSHOT = REPO / "perf" / "b0" / "snapshot-v1.json"


def _spec() -> dict:
    return yaml.safe_load(SPEC.read_text(encoding="utf-8"))


def _snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def _scenario_repetitions(spec: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for name in spec["scenario_selection"]["scenarios"]:
        cfg = yaml.safe_load((REPO / "scenarios" / f"{name}.yaml").read_text(encoding="utf-8"))
        out[name] = int((cfg.get("metrics") or {}).get("repetitions", 1))
    return out


def _spec_null_stages(spec: dict) -> set[str]:
    return {k for k, v in spec["metrics"]["stage_sources"].items() if v is None}


def test_spec_parses_and_is_complete() -> None:
    """PASS_IF: spec парсится и полон — версия, прогоны, состав, метрики,
    правила ошибок, источники стадий (недоступные — явный null)."""
    spec = _spec()
    assert spec["version"] == "B0-v1"
    assert spec["runs"] == 3
    names = spec["scenario_selection"]["scenarios"]
    assert len(names) == len(set(names)) == 28
    for name in names:
        assert (REPO / "scenarios" / f"{name}.yaml").exists(), name
    assert tuple(spec["metrics"]["per_attempt"]) == STAGE_METRICS
    rules = spec["error_rules"]
    assert rules["failed_attempt"] == "keep_time_mark_failed"
    assert rules["max_failed_ratio"] == 0.10
    assert "новая версия" in spec["change_policy"].lower()
    assert _spec_null_stages(spec) == {"t_reset", "t_finalize", "t_scoring"}


def test_snapshot_matches_spec() -> None:
    """PASS_IF: снимок соответствует spec — сценарии и повторы совпадают,
    ровно runs прогонов; все попытки из состава spec."""
    snap = _snapshot()
    spec = _spec()
    names = spec["scenario_selection"]["scenarios"]
    assert snap["spec_version"] == spec["version"]
    assert sorted(snap["scenarios"]) == sorted(names)
    expected = Counter(_scenario_repetitions(spec))
    assert len(snap["runs"]) == spec["runs"]
    for run in snap["runs"]:
        assert run["attempts"] == sum(expected.values())
        assert Counter(row["scenario"] for row in run["per_attempt"]) == expected


def test_snapshot_metric_schema_null_not_zero() -> None:
    """PASS_IF: схема метрик полная — 7 стадий у каждой попытки; у успешной
    попытки null-стадии — ровно задекларированные в spec (null, не 0);
    доступные стадии — float >= 0; итоги содержат median/p95/wall."""
    snap = _snapshot()
    spec_nulls = _spec_null_stages(_spec())
    assert snap["totals"]["null_stages"] == sorted(spec_nulls)
    for run in snap["runs"]:
        for row in run["per_attempt"]:
            assert set(row["metrics"]) == set(STAGE_METRICS)
            assert isinstance(row["failed"], bool)
            if row["failed"]:
                continue  # у попытки до отказа части стадий может не быть — это факт
            nulls = {k for k, v in row["metrics"].items() if v is None}
            assert nulls == spec_nulls, row["scenario"]
            for k, v in row["metrics"].items():
                if v is not None:
                    assert isinstance(v, float) and v >= 0, (row["scenario"], k, v)
        assert isinstance(run["wall_time_s"], float) and run["wall_time_s"] > 0
    for key in ("median", "p95"):
        assert set(snap["totals"][key]) == set(STAGE_METRICS)
    assert len(snap["totals"]["wall_time_s"]) == 3


def test_snapshot_manifest_versions() -> None:
    """PASS_IF: в снимке sha кода (40 hex), версия Python, машина/CPU,
    версия телеметрии и версия spec."""
    m = _snapshot()["manifest"]
    assert len(m["git_sha"]) == 40 and all(c in "0123456789abcdef" for c in m["git_sha"])
    assert m["python"]
    assert m["machine"] and m["cpu_count"] >= 1
    assert m["telemetry_schema_version"]
    assert m["spec_version"] == "B0-v1"
