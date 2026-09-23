"""tests/test_timing_regress.py — CARD-P14 (timing_regress, G3.5).

Синтетика по дизайну §5/§6: run-каталоги генерируются тестом напрямую
(раннер не задействуется). Замки:

  1. точные малые случаи: 3 vs 3 ⇒ p_min = 1/C(6,3) = 0,05; 5 vs 5 ⇒
     1/252 < α·w_min (FAIL Холма достижим); связи — перестановками точно;
  2. засеянный регресс end-to-end: k=1 ⇒ PASS; k=3 ⇒ FAIL; k≈M ⇒
     UNKNOWN(CI_STRADDLES) — проверка мощности метода;
  3. каждый из 12 UNKNOWN-кодов ловится ИМЕННО своим гвардом
     (включая CLOCK_SUSPECT на нулях и BASELINE_INVALID на базисе-B0-v2);
  4. маржа — только из базиса (k не меняет M); побайтовый повтор отчёта
     при том же seed; exit-коды 0/1/2; инструментальная метка mock;
  5. негативные: отсутствие сигнала (campaign.json/events) — UNKNOWN с
     именем сигнала, НЕ молчаливый PASS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.reporting.timing_regress import (  # noqa: E402
    _PermTest,
    _canonical_prereg_sha256,
)

PY = sys.executable
REPO = Path(__file__).resolve().parents[1]

BASE_T = {"t_reset": 0.30, "t_delivery": 5.10, "t_finalize": 0.40,
          "t_settle": 1.80, "t_trigger": 2.20, "t_scoring": 0.05}
JIT = (0.980, 1.020, 0.990, 1.010, 1.030, 0.970, 1.005, 0.995, 1.012, 0.988,
       1.006, 0.994, 1.018, 0.982, 1.003, 1.008, 0.992, 1.015, 0.985, 1.001)
FAMILIES = ("fam_a", "fam_b")


def _value(phase: str, i: int, factor: float = 1.0) -> float:
    return round(BASE_T[phase] * JIT[i % len(JIT)] * factor, 6)


def _timing(i: int, factor: float, *, skip_phase: str | None = None,
            zero_phase: str | None = None, negative_phase: str | None = None,
            flat: bool = False, factor_phases: dict | None = None,
            jitter_k: float = 1.0, jitter_stride: int = 1) -> dict:
    out = {}
    for phase in BASE_T:
        if phase == skip_phase:
            out[phase] = None
            continue
        if phase == zero_phase:
            out[phase] = 0.0
            continue
        if flat:
            out[phase] = round(BASE_T[phase] * (factor_phases or {}).get(phase, factor), 6)
            continue
        # шум: базовый узор ±3%, jitter_k масштабирует (5 ≈ живые ±15%);
        # jitter_stride декоррелирует узоры блоков (A и B видят разные фазы)
        noise = 1.0 + (JIT[(i * jitter_stride) % len(JIT)] - 1.0) * jitter_k
        v = BASE_T[phase] * noise * (factor_phases or {}).get(phase, factor)
        if phase == negative_phase:
            v = -abs(v)
        out[phase] = round(v, 6)
    return out


def _attempt_line(case_id: str, *, timing: dict | None, outcome: str = "completed_failure",
                  attempt_no: int = 1) -> dict:
    return {
        "schema_version": 1, "experiment_id": "exp-test", "run_id": "run-test",
        "case_id": case_id, "candidate_id": case_id, "parent_candidate_id": None,
        "attempt_no": attempt_no, "transport_retry": 0, "case_marker": None,
        "goal_digest": None, "seed": 1, "session_ids": {}, "outcome": outcome,
        "error": None, **({"timing": timing} if timing is not None else {}),
    }


def _write_run(run_dir: Path, *, fam_counts: dict[str, int], factor: float = 1.0,
               id_base: int = 0, adapter: str = "stand-x",
               start_iso: str = "2026-06-01T00:00:00+00:00",
               wall_seconds: float | None = None, campaign: bool = True,
               settle_timeouts: int = 0, no_timing: bool = False,
               timing_kwargs: dict | None = None,
               broken_records: list[dict] | None = None,
               bookkeeping: int = 0) -> None:
    """Один run-каталог блока: attempts.jsonl + campaign.json + events.jsonl.
    wall_seconds управляет стеной блока (последнее событие); по умолчанию
    стена = Σ фаз / 2 (conc = 2 — как живой N=2)."""
    run_dir.mkdir(parents=True, exist_ok=True)
    timing_kwargs = timing_kwargs or {}
    lines: list[dict] = []
    cases: list[str] = []
    total = 0.0
    idx = 0
    for fam, count in fam_counts.items():
        for i in range(count):
            n = id_base + idx
            case_id = f"CASE-{fam}-{i + 1:03d}-{n % 0xFFFFFF:06x}"
            cases.append(case_id)
            timing = None if no_timing else _timing(n, factor, **timing_kwargs)
            lines.append(_attempt_line(case_id, timing=timing))
            if timing:
                total += sum(v for v in timing.values() if isinstance(v, (int, float)))
            idx += 1
    for b in range(bookkeeping):
        lines.insert(0, _attempt_line(f"CASE-book-{b:03d}-{b:06x}",
                                      timing=None, outcome="registered", attempt_no=0))
    for extra in broken_records or []:
        lines.append(extra)
    (run_dir / "attempts.jsonl").write_text(
        "\n".join(json.dumps(l, ensure_ascii=False) for l in lines) + "\n", encoding="utf-8")
    if campaign:
        results = []
        for k, case_id in enumerate(cases):
            timed_out = k < settle_timeouts
            results.append({
                "case_id": case_id, "attack_id": fam, "family": fam,
                "success": False,
                "stages": [{
                    "stage": "persistence",
                    "success": False,
                    "reason": ("settle (wait_until_persistent): критерий записи не появился "
                               "в памяти за 10.0s (память читалась 20 раз) — определённый негатив"
                               if timed_out else "запись с case-marker присутствует в памяти"),
                }],
            })
        (run_dir / "campaign.json").write_text(json.dumps({
            "run_id": "run-test", "scenario_id": "scenario",
            "attempts": len(cases),
            "metadata": {"adapter": adapter, "target": "http://stand"},
            "results": results,
        }, ensure_ascii=False), encoding="utf-8")
    if wall_seconds is None:
        wall_seconds = total / 2.0 if total else 1.0
    from datetime import datetime, timedelta, timezone
    t0 = datetime.fromisoformat(start_iso)
    events = []
    for k, case_id in enumerate(cases):
        ts = t0 + timedelta(seconds=(k + 1) * (wall_seconds / max(len(cases), 1)))
        events.append({"case_id": case_id, "timestamp": ts.isoformat(),
                       "event": "probe", "run_id": "run-test"})
    (run_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")


def _prereg(tmp: Path, **overrides) -> Path:
    data = {
        "prereg_id": "P14-G35-2026-09-23-1",
        "alpha": 0.05,
        "holm_weights": {"t_settle": 0.5, "t_reset": 0.1, "t_delivery": 0.1,
                         "t_finalize": 0.1, "t_trigger": 0.1, "t_scoring": 0.1},
        "estimator": "stratified_hl_log",
        "strata": "scenario_id",
        "scenarios": list(FAMILIES),
        "perm": {"exact_max": 100000, "mc_B": 200, "seed": 42},
        "kappa": {"model": "ceiling", "cap": 2.0},
        "tau": {p: 0.25 for p in BASE_T},
        "abs_floor_s": {p: 0.05 for p in BASE_T},
        "poll_quantum_s": 0.5,
        "design": {"blocks": ["A", "B", "A2"],
                   "repeats_per_scenario": {"A": 10, "B": 10, "A2": 10},
                   "warmup_per_worker": 1},
        "n_min_per_stage": 5,
        "unknown": {"f_null_max": 0.10, "f_censor_max": 0.10, "drift_tol": 0.15,
                    "conc_min": 1.5, "strata_lost_max": 0.34},
        "stopping": "fixed_n_no_extension",
        "stamp": "2026-01-01T00:00:00Z",
        "upstream_green": True,
    }
    data.update(overrides)
    data["sha256_self"] = _canonical_prereg_sha256(data)
    path = tmp / "prereg.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _run_cli(prereg: Path, a: Path, b: Path, a2: Path, *extra: str,
             output: Path | None = None) -> tuple[int, str]:
    argv = [PY, "-m", "memnotsafe.reporting.timing_regress",
            "--prereg", str(prereg)]
    if output is not None:
        argv += ["--output", str(output)]
    argv += [str(a), str(b), str(a2), *extra]
    proc = subprocess.run(argv, cwd=str(REPO), capture_output=True, text=True,
                          encoding="utf-8", env={**os.environ, "PYTHONPATH": str(SRC)})
    return proc.returncode, proc.stdout + proc.stderr


def _std_blocks(tmp: Path, *, factor_b: float = 1.0, factor_a2: float = 1.0,
                counts: dict | None = None, **kw) -> tuple[Path, Path, Path]:
    counts = counts or {fam: 10 for fam in FAMILIES}
    root = tmp / "runs"
    a, b, a2 = root / "A", root / "B", root / "A2"
    _write_run(a, fam_counts=counts, factor=1.0, id_base=0, **kw)
    _write_run(b, fam_counts=counts, factor=factor_b, id_base=100, **kw)
    _write_run(a2, fam_counts=counts, factor=factor_a2, id_base=200,
               start_iso="2026-06-01T01:00:00+00:00", **kw)
    return a, b, a2


# ---------------------------------------------------------------- точная механика

def test_exact_small_cases_and_ties() -> None:
    """3 vs 3 ⇒ p_min = 1/20 = 0,05; 5 vs 5 ⇒ 1/252 ≈ 0,00397 < α·w_min;
    связи (квантованный поллинг) учитываются перестановками точно."""
    x = {"s": [1.0, 2.0, 3.0]}
    y = {"s": [4.0, 5.0, 6.0]}
    perm = _PermTest(x, y, exact_max=100000, mc_b=10, seed=1)
    assert perm.exact
    t, p_plus, p_minus = perm.evaluate(0.0)
    assert t == 9.0  # все девять пар положительны
    assert p_plus == 1 / 20 and p_minus == 1.0

    x5 = {"s": [1.0, 2.0, 3.0, 4.0, 5.0]}
    y5 = {"s": [11.0, 12.0, 13.0, 14.0, 15.0]}
    perm5 = _PermTest(x5, y5, exact_max=100000, mc_b=10, seed=1)
    assert perm5.exact and perm5.total_combos == 252
    p_min = perm5.evaluate(0.0)[1]
    assert p_min == 1 / 252 and p_min < 0.005  # α·w_min — FAIL Холма достижим

    # связи: все значения одинаковы ⇒ все sgn = 0 ⇒ T = 0 при любом δ=0
    xt = {"s": [1.0, 1.0, 1.0]}
    yt = {"s": [1.0, 1.0, 1.0]}
    permt = _PermTest(xt, yt, exact_max=100000, mc_b=10, seed=1)
    t_ties, p_ties, _ = permt.evaluate(0.0)
    assert t_ties == 0.0
    assert p_ties == 1.0  # вырожденный нуль: перестановки ничего не меняют


def test_mc_mode_and_determinism_of_perm() -> None:
    """Переключение точный/MC по exact_max; MC детерминирован seed'ом."""
    x = {"s": [float(i) for i in range(1, 9)]}
    y = {"s": [float(i) + 3.0 for i in range(1, 9)]}
    exact = _PermTest(x, y, exact_max=10 ** 9, mc_b=10, seed=7)
    mc1 = _PermTest(x, y, exact_max=10, mc_b=50, seed=7)
    mc2 = _PermTest(x, y, exact_max=10, mc_b=50, seed=7)
    assert exact.exact and not mc1.exact
    assert [mc1.evaluate(d)[1] for d in (0.0, 0.5, 1.0)] == \
           [mc2.evaluate(d)[1] for d in (0.0, 0.5, 1.0)]


# ---------------------------------------------------------------- конвейер

def test_k1_pass_exit0(tmp_path: Path) -> None:
    """Засеянный «нет сдвига»: k=1 ⇒ PASS, exit 0 (мощность не FAIL)."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, factor_b=1.0)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "verdict=PASS" in out, out
    assert rc == 0


def test_k3_fail_exit1(tmp_path: Path) -> None:
    """Засеянный регресс k=3 ⇒ FAIL (Холм отвергает), exit 1."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, factor_b=3.0)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "verdict=FAIL" in out, out
    assert rc == 1


def test_k_near_margin_unknown(tmp_path: Path) -> None:
    """k ≈ M каждой фазы (стендовые 2.5, settle 2.78 = κ(1+τ)+Δ_poll/m,
    t_scoring без сдвига — κ=1, локальный CPU) при живом шуме ⇒ U ≥ M ⇒
    CI_STRADDLES ⇒ UNKNOWN — «нет сигнала ≠ нет регресса» (мощность
    метода: сдвиг НА марже неразличим со сдвигом ПОД маржу)."""
    prereg = _prereg(tmp_path)
    fp = {p: 2.5 for p in BASE_T if p != "t_scoring" and p != "t_settle"}
    fp["t_settle"] = 2.7778   # 2·1.25 + 0.5/1.8 — маржа фазы из базиса
    fp["t_scoring"] = 1.0
    root = tmp_path / "runs"
    counts = {fam: 10 for fam in FAMILIES}
    _write_run(root / "A", fam_counts=counts)
    _write_run(root / "B", fam_counts=counts, id_base=100, factor=1.0,
               timing_kwargs={"factor_phases": fp, "jitter_k": 5.0, "jitter_stride": 7})
    _write_run(root / "A2", fam_counts=counts, id_base=200,
               start_iso="2026-06-01T01:00:00+00:00")
    rc, out = _run_cli(prereg, root / "A", root / "B", root / "A2")
    assert "verdict=UNKNOWN" in out, out
    assert "CI_STRADDLES" in out, out
    assert "verdict=FAIL" not in out.splitlines()[0], out
    assert rc == 2


def test_report_byte_determinism(tmp_path: Path) -> None:
    """Побайтовый повтор отчёта при том же seed (stdout и JSON)."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, factor_b=1.7)
    out1, out2 = tmp_path / "r1.txt", tmp_path / "r2.txt"
    json1, json2 = tmp_path / "r1.json", tmp_path / "r2.json"
    rc1, text1 = _run_cli(prereg, a, b, a2, output=json1)
    rc2, text2 = _run_cli(prereg, a, b, a2, output=json2)
    out1.write_text(text1, encoding="utf-8")
    out2.write_text(text2, encoding="utf-8")
    assert rc1 == rc2 and text1 == text2
    assert json1.read_bytes() == json2.read_bytes()


def test_margin_computed_from_baseline_only(tmp_path: Path) -> None:
    """Маржа никогда не выводится из данных B: k=1 и k=3 ⇒ одинаковые M."""
    j1, j3 = tmp_path / "m1.json", tmp_path / "m3.json"
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, factor_b=1.0)
    _run_cli(prereg, a, b, a2, output=j1)
    a, b, a2 = _std_blocks(tmp_path / "runs3", factor_b=3.0)
    _run_cli(prereg, a, b, a2, output=j3)
    m1 = {p["phase"]: p.get("margin_m") for p in json.loads(j1.read_text("utf-8"))["phases"]}
    m3 = {p["phase"]: p.get("margin_m") for p in json.loads(j3.read_text("utf-8"))["phases"]}
    assert m1 == m3 and all(v and v > 1.0 for v in m1.values())


def test_mock_instrumental_label(tmp_path: Path) -> None:
    """Мок-вход ⇒ метка «инструментальная проверка, не вердикт G3.5»;
    mock==mock не является BASELINE_INVALID."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, factor_b=1.0, adapter="mock")
    rc, out = _run_cli(prereg, a, b, a2)
    assert "инструментальная проверка, не вердикт G3.5" in out, out
    assert "BASELINE_INVALID" not in out


# ---------------------------------------------------------------- гварды (12)

def test_guard_prereg_missing(tmp_path: Path) -> None:
    a, b, a2 = _std_blocks(tmp_path)
    rc, out = _run_cli(tmp_path / "нет-файла.json", a, b, a2)
    assert "PREREG_MISSING" in out and rc == 2, out


def test_guard_prereg_deviation_sha(tmp_path: Path) -> None:
    """Правка JSON после заморозки (tau без пересчёта sha256_self)."""
    path = _prereg(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["tau"]["t_settle"] = 0.9
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    a, b, a2 = _std_blocks(tmp_path)
    rc, out = _run_cli(path, a, b, a2)
    assert "PREREG_DEVIATION" in out and "sha256_self" in out and rc == 2, out


def test_guard_prereg_deviation_stamp(tmp_path: Path) -> None:
    """Штамп позже первой попытки A (A стартует 2026-06-01)."""
    path = _prereg(tmp_path, stamp="2026-09-01T00:00:00Z")
    a, b, a2 = _std_blocks(tmp_path)
    rc, out = _run_cli(path, a, b, a2)
    assert "PREREG_DEVIATION" in out and "штамп" in out and rc == 2, out
    assert "UPSTREAM_NOT_GREEN" not in out  # ровно свой код


def test_guard_baseline_invalid_b0_snapshot(tmp_path: Path) -> None:
    """Базис = B0-снимок (v3.34(б): не допускается даже справочно)."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path)
    (a / "snapshot-v2.json").write_text("{}", encoding="utf-8")
    rc, out = _run_cli(prereg, a, b, a2)
    assert "BASELINE_INVALID" in out and "B0" in out and rc == 2, out


def test_guard_baseline_invalid_not_n1_and_worker_loading(tmp_path: Path) -> None:
    """Базис из ДВУХ воркер-каталогов ⇒ BASELINE_INVALID; блок B из двух
    воркер-каталогов (оркестратор P13-a) грузится и НЕ даёт этот код."""
    prereg = _prereg(tmp_path)
    root = tmp_path / "runs"
    _write_run(root / "A", fam_counts={fam: 10 for fam in FAMILIES})
    _write_run(root / "A2", fam_counts={fam: 10 for fam in FAMILIES},
               start_iso="2026-06-01T01:00:00+00:00")
    b = root / "B"  # каталог оркестратора: сам без attempts.jsonl
    _write_run(root / "B-w1", fam_counts={fam: 5 for fam in FAMILIES}, id_base=100)
    _write_run(root / "B-w2", fam_counts={fam: 5 for fam in FAMILIES}, id_base=150)
    rc, out = _run_cli(prereg, root / "A", b, root / "A2")
    assert "BASELINE_INVALID" not in out, out  # B из воркеров — норма
    # теперь ломаем базис: A как каталог оркестратора с двумя воркерами
    root2 = tmp_path / "runs2"
    (root2 / "A" / "locks").mkdir(parents=True)  # сам блок существует (замки)
    _write_run(root2 / "A-w1", fam_counts={fam: 5 for fam in FAMILIES})
    _write_run(root2 / "A-w2", fam_counts={fam: 5 for fam in FAMILIES}, id_base=50)
    _write_run(root2 / "A2", fam_counts={fam: 10 for fam in FAMILIES},
               start_iso="2026-06-01T01:00:00+00:00")
    _write_run(root2 / "B", fam_counts={fam: 10 for fam in FAMILIES}, id_base=100)
    rc2, out2 = _run_cli(prereg, root2 / "A", root2 / "B", root2 / "A2")
    assert "BASELINE_INVALID" in out2 and "не N=1" in out2 and rc2 == 2, out2


def test_guard_baseline_invalid_adapter_mismatch(tmp_path: Path) -> None:
    prereg = _prereg(tmp_path)
    root = tmp_path / "runs"
    _write_run(root / "A", fam_counts={fam: 10 for fam in FAMILIES})
    _write_run(root / "B", fam_counts={fam: 10 for fam in FAMILIES},
               id_base=100, adapter="stand-другой")
    _write_run(root / "A2", fam_counts={fam: 10 for fam in FAMILIES},
               id_base=200, start_iso="2026-06-01T01:00:00+00:00")
    rc, out = _run_cli(prereg, root / "A", root / "B", root / "A2")
    assert "BASELINE_INVALID" in out and "различаются" in out and rc == 2, out


def test_guard_upstream_not_green(tmp_path: Path) -> None:
    """Без явного подтверждения — UNKNOWN с этим кодом; флаг снимает."""
    prereg = _prereg(tmp_path)
    data = json.loads(prereg.read_text(encoding="utf-8"))
    data.pop("upstream_green")
    data["sha256_self"] = _canonical_prereg_sha256(data)
    prereg.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    a, b, a2 = _std_blocks(tmp_path)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "UPSTREAM_NOT_GREEN" in out and rc == 2, out
    rc2, out2 = _run_cli(prereg, a, b, a2, "--upstream-green")
    assert "UPSTREAM_NOT_GREEN" not in out2 and "verdict=PASS" in out2, out2


def test_guard_no_concurrency_serial_wall(tmp_path: Path) -> None:
    """Стена B ≈ Σ длительностей (сериализация) ⇒ conc ≈ 1 < 1,5."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, wall_seconds=None)
    # пересобираем B с явной стеной = total (serial)
    import shutil
    shutil.rmtree(b)
    _write_run(b, fam_counts={fam: 10 for fam in FAMILIES}, id_base=100,
               wall_seconds=10_000.0)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "NO_CONCURRENCY" in out and rc == 2, out


def test_guard_no_concurrency_no_events(tmp_path: Path) -> None:
    """Нет меток времени в B ⇒ по сумме фаз (безопасное занижение) ⇒ гвард."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path)
    (b / "events.jsonl").unlink()
    rc, out = _run_cli(prereg, a, b, a2)
    assert "NO_CONCURRENCY" in out and "по сумме фаз" in out and rc == 2, out


def test_guard_clock_suspect_variants(tmp_path: Path) -> None:
    """Ноль в I/O-фазе, отрицательное, все значения равны — каждый даёт
    CLOCK_SUSPECT (нули замороженных часов иначе дали бы R̂=1 и PASS)."""
    for kw, needle in (
        ({"zero_phase": "t_settle"}, "=0.0 в I/O-фазе"),
        ({"negative_phase": "t_delivery"}, "отрицательное значение"),
        ({"flat": True}, "равны"),
    ):
        prereg = _prereg(tmp_path / "_".join(sorted(kw)))  # type: ignore[arg-type]
        a, b, a2 = _std_blocks(tmp_path / "_".join(sorted(kw)), factor_b=3.0,  # type: ignore[arg-type]
                               timing_kwargs=kw)
        rc, out = _run_cli(prereg, a, b, a2)
        assert "CLOCK_SUSPECT" in out and needle in out and rc == 2, (kw, out)
        assert "verdict=FAIL" not in out  # данным не доверяем — UNKNOWN, не FAIL


def test_guard_n_low(tmp_path: Path) -> None:
    """2 повтора на семейство: ступень B = 4 наблюдения < n_min 5 ⇒ N_LOW
    (при 4 vs 4 p_min = 1/70 — FAIL вторичной фазы недостижим, дизайн §4.5)."""
    counts = {fam: 2 for fam in FAMILIES}
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, counts=counts, factor_b=3.0)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "N_LOW" in out and rc == 2 and "verdict=UNKNOWN" in out, out


def test_guard_strata_lost(tmp_path: Path) -> None:
    """Предрегистрировано 4 сценария, в данных 2 ⇒ доля потерь 2/4 = 0,5 >
    strata_lost_max 0,34 ⇒ STRATA_LOST на каждой фазе."""
    counts = {fam: 10 for fam in FAMILIES}
    prereg4 = _prereg(tmp_path, scenarios=["fam_a", "fam_b", "fam_c", "fam_d"])
    a, b, a2 = _std_blocks(tmp_path, counts=counts, factor_b=1.0)
    rc, out = _run_cli(prereg4, a, b, a2)
    assert "STRATA_LOST" in out and rc == 2, out


def test_guard_attrition(tmp_path: Path) -> None:
    """3 из 20 попыток B без таймингов (15% > 10%) ⇒ ATTRITION (не PASS)."""
    prereg = _prereg(tmp_path)
    root = tmp_path / "runs"
    _write_run(root / "A", fam_counts={fam: 10 for fam in FAMILIES})
    _write_run(root / "A2", fam_counts={fam: 10 for fam in FAMILIES},
               start_iso="2026-06-01T01:00:00+00:00", id_base=200)
    _write_run(root / "B", fam_counts={fam: 10 for fam in FAMILIES}, id_base=100,
               broken_records=[
                   _attempt_line("CASE-fam_a-099-10000f", timing=None, outcome="unknown"),
                   _attempt_line("CASE-fam_a-098-10000e", timing=None, outcome="unknown"),
                   _attempt_line("CASE-fam_b-097-10000d", timing=None, outcome="transport_error"),
               ])
    rc, out = _run_cli(prereg, root / "A", root / "B", root / "A2")
    assert "ATTRITION" in out and rc == 2, out


def test_guard_censored_high(tmp_path: Path) -> None:
    """3 из 20 таймаутов settle в B (15% > 10%) ⇒ CENSORED_HIGH, ТОЛЬКО
    t_settle; прочие фазы не получают этот код."""
    prereg = _prereg(tmp_path)
    root = tmp_path / "runs"
    _write_run(root / "A", fam_counts={fam: 10 for fam in FAMILIES})
    _write_run(root / "A2", fam_counts={fam: 10 for fam in FAMILIES},
               start_iso="2026-06-01T01:00:00+00:00", id_base=200)
    _write_run(root / "B", fam_counts={fam: 10 for fam in FAMILIES}, id_base=100,
               settle_timeouts=3)
    rc, out = _run_cli(prereg, root / "A", root / "B", root / "A2")
    assert "CENSORED_HIGH(t_settle)" in out and rc == 2, out
    for phase in ("t_reset", "t_delivery", "t_scoring"):
        assert f"CENSORED_HIGH({phase})" not in out


def test_guard_stand_drift(tmp_path: Path) -> None:
    """A′ вдвое медленнее A ⇒ STAND_DRIFT (дрейф стенда, не регресс B)."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, factor_b=1.0, factor_a2=2.0)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "STAND_DRIFT" in out and rc == 2, out


def test_guard_telemetry_lost(tmp_path: Path) -> None:
    """Старая схема: ни одного timing ни в одной попытке ⇒ TELEMETRY_LOST."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, no_timing=True)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "TELEMETRY_LOST" in out and rc == 2, out


def test_negative_missing_marker_is_unknown_not_pass(tmp_path: Path) -> None:
    """Негативный: нет campaign.json нигде ⇒ цензура settle неверифицируема —
    UNKNOWN с именем сигнала, а НЕ PASS по умолчанию."""
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, campaign=False)
    rc, out = _run_cli(prereg, a, b, a2)
    assert "CENSORED_HIGH" in out and "неверифицируема" in out, out
    assert "verdict=UNKNOWN" in out and rc == 2, out


# ---------------------------------------------------------------- вход/выход

def test_input_error_no_dir_no_traceback(tmp_path: Path) -> None:
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path)
    rc, out = _run_cli(prereg, a, tmp_path / "нет-каталога", a2)
    assert rc == 2 and "ОШИБКА" in out and "не существует" in out, out
    assert "Traceback" not in out


def test_prereg_field_validation(tmp_path: Path) -> None:
    a, b, a2 = _std_blocks(tmp_path)
    bad = _prereg(tmp_path / "s", stopping="optional_stopping")
    rc, out = _run_cli(bad, a, b, a2)
    assert "PREREG_DEVIATION" in out and "stopping" in out and rc == 2, out
    bad2 = _prereg(tmp_path / "n", n_min_per_stage=4)
    rc2, out2 = _run_cli(bad2, a, b, a2)
    assert "PREREG_DEVIATION" in out2 and "n_min_per_stage" in out2 and rc2 == 2, out2
