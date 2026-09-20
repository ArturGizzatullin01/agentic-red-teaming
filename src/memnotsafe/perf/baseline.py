"""src/memnotsafe/perf/baseline.py — измеритель замороженного perf-baseline B0.

Карточка B0: маленький ЗАМОРОЖЕННЫЙ набор для измерения производительности
ОСНАСТКИ (mock-путь, offline; живые сценарии не входят — их время это сеть
и LLM, не наш код). Состав набора и правила агрегации — источник истины
perf/b0/spec.yaml (изменение spec = новая версия B0, не правка задним числом).

Принципы (негативные ограничения карточки):
  - runner.py НЕ расширяется ради таймингов: стадии собираются ТОЛЬКО из
    существующих точек данных — transcript.observed_at (фазы delivery/trigger),
    campaign.json persistence.evidence[].settle.elapsed_s; стена попытки —
    perf_counter измерителя вокруг попытки.
  - t_reset / t_finalize / t_scoring существующими артефактами не
    таймштампятся — честный null в снимке + UNKNOWN в хендофе, НЕ ноль.
  - Ничего не оптимизируется: B0 только измеряет.

Запуск (A0 может воспроизвести структуру снимка на своей машине; числовые
тайминги между машинами различаются — это ожидаемо):
    PYTHONPATH=src python -m memnotsafe.perf.baseline \
        --spec perf/b0/spec.yaml --output perf/b0/snapshot-v1.json

Измеритель отказывается работать в грязном рабочем дереве: git_sha манифеста
обязан быть sha того дерева, которым снят снимок.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import platform
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import build_adapter, load_scenario
from memnotsafe.tracing.recorder import read_events_jsonl

STAGE_METRICS: tuple[str, ...] = (
    "t_total",
    "t_reset",
    "t_delivery",
    "t_settle",
    "t_trigger",
    "t_finalize",
    "t_scoring",
)
SNAPSHOT_SCHEMA = "b0-snapshot/1"

_COMPLETED_OUTCOMES = frozenset({"completed_success", "completed_failure"})


# -- агрегаты ----------------------------------------------------------------


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


def _p95(values: list[float]) -> float | None:
    """nearest-rank перцентиль — детерминирован, без внешних зависимостей."""
    if not values:
        return None
    s = sorted(values)
    idx = max(0, min(len(s) - 1, math.ceil(0.95 * len(s)) - 1))
    return s[idx]


def _run_per_metric(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for metric in STAGE_METRICS:
        values = [r["metrics"][metric] for r in rows if r["metrics"][metric] is not None]
        out[metric] = {
            "median": _median(values),
            "p95": _p95(values),
            "n": len(values),
            "nulls": sum(1 for r in rows if r["metrics"][metric] is None),
        }
    return out


# -- извлечение стадий из СУЩЕСТВУЮЩИХ артефактов ----------------------------


def _phase_span_seconds(
    transcript: dict[str, Any] | None, events: list[dict[str, Any]], phase: str
) -> float | None:
    """Span фазы по timestamps СОБЫТИЙ ТРЕЙСА (существующая точка данных).

    observed_at в транскрипте на mock-пути не заполняется (None) — поэтому
    фазовые границы берутся джойном: транскрипт даёт фаза -> session_id,
    events.jsonl — реальные времена событий этой сессии. Delivery-сессия
    включает её finalize (memory_write): на mock-артефактах они неразделимы,
    отдельный t_finalize не записывается (null).
    """
    if not transcript or not events:
        return None
    sessions = {
        m.get("session_id")
        for m in transcript.get("messages") or []
        if m.get("phase") == phase and m.get("session_id")
    }
    if not sessions:
        return None
    stamps = []
    for event in events:
        if event.get("session_id") in sessions and event.get("timestamp"):
            try:
                stamps.append(datetime.fromisoformat(event["timestamp"]))
            except ValueError:
                continue
    if not stamps:
        return None
    return round((max(stamps) - min(stamps)).total_seconds(), 6)


def _settle_seconds(campaign_json: dict[str, Any] | None) -> float | None:
    """settle.elapsed_s из стадии persistence (существующая точка данных)."""
    if not campaign_json:
        return None
    for result in campaign_json.get("results") or []:
        for stage in result.get("stages") or []:
            if stage.get("stage") != "persistence":
                continue
            for evidence in stage.get("evidence") or []:
                settle = evidence.get("settle") if isinstance(evidence, dict) else None
                if isinstance(settle, dict) and isinstance(settle.get("elapsed_s"), (int, float)):
                    return round(float(settle["elapsed_s"]), 6)
    return None


def _attempt_outcome(out_dir: Path) -> str | None:
    path = out_dir / "attempts.jsonl"
    if not path.exists():
        return None
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows[-1].get("outcome") if rows else None


def _telemetry_schema_version(out_dir: Path) -> Any:
    path = out_dir / "attempts.jsonl"
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            return json.loads(line).get("schema_version")
    return None


# -- одна попытка --------------------------------------------------------------


def run_attempt(scenario_path: Path) -> dict[str, Any]:
    """Один прогон Campaign(repetitions=1) + разбор артефактов.

    t_total — стена измерителя; остальные стадии — из артефактов прогона.
    Ошибка прогона НЕ выбрасывается наружу: попытка помечается failed,
    её время (время до отказа) остаётся фактом замера.
    """
    out_dir = Path(tempfile.mkdtemp(prefix="b0-attempt-"))
    error: str | None = None
    started = time.perf_counter()
    try:
        scenario = load_scenario(scenario_path)
        target = build_adapter(scenario, None)
        campaign = Campaign(scenario, target, out_dir)
        asyncio.run(campaign.run(repetitions=1))
    except Exception as exc:  # попытка не выбрасывает: failed-попытка — факт
        error = f"{type(exc).__name__}: {exc}"
    wall = round(time.perf_counter() - started, 6)

    campaign_json = None
    transcript = None
    events: list[dict[str, Any]] = []
    try:
        cj = out_dir / "campaign.json"
        if cj.exists():
            campaign_json = json.loads(cj.read_text(encoding="utf-8"))
        transcripts = sorted((out_dir / "evidence").glob("*-transcript.json"))
        if transcripts:
            transcript = json.loads(transcripts[0].read_text(encoding="utf-8"))
        events = read_events_jsonl(out_dir / "events.jsonl")
    except Exception as exc:
        error = error or f"artifact-parse: {type(exc).__name__}: {exc}"
    # до rmtree: попытка/телеметрия читаются из артефактов, которые ещё живы
    outcome = _attempt_outcome(out_dir)
    telemetry_schema = _telemetry_schema_version(out_dir)
    shutil.rmtree(out_dir, ignore_errors=True)

    failed = error is not None or outcome not in _COMPLETED_OUTCOMES
    metrics: dict[str, Any] = {
        "t_total": wall,
        "t_reset": None,
        "t_delivery": _phase_span_seconds(transcript, events, "delivery"),
        "t_settle": _settle_seconds(campaign_json),
        "t_trigger": _phase_span_seconds(transcript, events, "trigger"),
        "t_finalize": None,
        "t_scoring": None,
    }
    return {
        "scenario": scenario_path.stem,
        "failed": failed,
        "outcome": outcome if outcome is not None else (error or "unknown"),
        "telemetry_schema_version": telemetry_schema,
        "metrics": metrics,
    }


# -- git-манифест --------------------------------------------------------------


def _git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args], capture_output=True, text=True, encoding="utf-8"
    )
    if proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _require_clean_tree(repo_root: Path) -> None:
    dirty = _git(repo_root, "status", "--porcelain")
    if dirty:
        raise SystemExit(
            "рабочее дерево грязное — снимок обязан сниматься на чистом HEAD "
            "(git_sha манифеста = sha дерева измерения):\n" + dirty
        )


# -- главный прогон -------------------------------------------------------------


def measure(spec: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    names: list[str] = spec["scenario_selection"]["scenarios"]
    runs: int = int(spec["runs"])
    max_failed_ratio = float(spec["error_rules"]["max_failed_ratio"])
    repetitions = {}
    for name in names:
        repetitions[name] = int(load_scenario(repo_root / "scenarios" / f"{name}.yaml").repetitions)

    git_sha = _git(repo_root, "rev-parse", "HEAD")
    telemetry_schema = None
    runs_payload: list[dict[str, Any]] = []

    for run_no in range(1, runs + 1):
        rows: list[dict[str, Any]] = []
        run_started = time.perf_counter()
        for name in names:
            scenario_path = repo_root / "scenarios" / f"{name}.yaml"
            for _ in range(repetitions[name]):
                row = run_attempt(scenario_path)
                row["attempt"] = len(rows) + 1
                rows.append(row)
                if telemetry_schema is None:
                    telemetry_schema = row.get("telemetry_schema_version")
            print(f"[B0] run {run_no}/{runs}: {name} — попыток {repetitions[name]}", flush=True)
        run_wall = round(time.perf_counter() - run_started, 6)

        failed = [r for r in rows if r["failed"]]
        if len(failed) / len(rows) > max_failed_ratio:
            report = "\n".join(f"  {r['scenario']}: {r['outcome']}" for r in failed)
            raise SystemExit(
                f"прогон {run_no}: failed-попыток {len(failed)}/{len(rows)} — выше лимита "
                f"{max_failed_ratio:.0%}; снимок НЕ пишется (правило spec.error_rules).\n{report}"
            )
        runs_payload.append(
            {
                "run_no": run_no,
                "wall_time_s": run_wall,
                "attempts": len(rows),
                "failed": len(failed),
                "per_attempt": rows,
                "per_metric": _run_per_metric(rows),
            }
        )

    totals_median = {
        metric: _median([run["per_metric"][metric]["median"] for run in runs_payload])
        for metric in STAGE_METRICS
    }
    pooled_p95 = {
        metric: _p95(
            [
                row["metrics"][metric]
                for run in runs_payload
                for row in run["per_attempt"]
                if row["metrics"][metric] is not None
            ]
        )
        for metric in STAGE_METRICS
    }
    spec_nulls = sorted(
        k for k, v in (spec["metrics"]["stage_sources"] or {}).items() if v is None
    )
    return {
        "schema_version": SNAPSHOT_SCHEMA,
        "spec_version": spec["version"],
        "scenarios": list(names),
        "repetitions": dict(sorted(repetitions.items())),
        "manifest": {
            "git_sha": git_sha,
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "platform": platform.platform(terse=True),
            "cpu_count": os.cpu_count(),
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "telemetry_schema_version": telemetry_schema,
            "spec_version": spec["version"],
        },
        "runs": runs_payload,
        "totals": {
            "median": totals_median,
            "p95": pooled_p95,
            "null_stages": spec_nulls,
            "wall_time_s": [run["wall_time_s"] for run in runs_payload],
            "wall_time_median_s": _median([run["wall_time_s"] for run in runs_payload]),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="memnotsafe.perf.baseline", description=__doc__)
    parser.add_argument("--spec", required=True, help="путь к замороженной spec (perf/b0/spec.yaml)")
    parser.add_argument("--output", required=True, help="куда писать снимок JSON")
    args = parser.parse_args(argv)

    spec_path = Path(args.spec).resolve()
    repo_root = spec_path.parents[2]
    _require_clean_tree(repo_root)
    spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))

    snapshot = measure(spec, repo_root)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    totals = snapshot["totals"]
    print(
        f"[B0] снимок: {output} | sha={snapshot['manifest']['git_sha'][:12]} "
        f"| попыток/прогон={snapshot['runs'][0]['attempts']} "
        f"| wall median={totals['wall_time_median_s']}s "
        f"| t_total median={totals['median']['t_total']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
