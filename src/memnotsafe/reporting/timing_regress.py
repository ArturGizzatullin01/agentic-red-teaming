"""src/memnotsafe/reporting/timing_regress.py — CARD-P14: компаратор
тайминг-регресса G3.5 (ступень 1→2).

Read-only CLI по паттерну ledger_recon/B4 (собственный main, cli.py не
тронут): run-каталоги блоков A / B / A′ + замороженная предрегистрация →
вердикт PASS / FAIL / UNKNOWN с кодом причины. Live-прогоны и оркестрация
A→B→A′ — НЕ эта карточка (P13-f): компаратор только читает готовые
каталоги.

Норматив: карточка CARD-P14-timing-regress-2026-09-23 (§2 — решения
владельца; при расхождении карточка важнее) + дизайн
OPUS-P14-THRESHOLD-DESIGN-2026-09-23 (§1–§5).

Метод (дизайн §1): фазы t_reset/t_delivery/t_finalize/t_settle/t_trigger/
t_scoring; наблюдение — попытка; ℓ = ln max(t, 1e-6) (разрешение round 6);
сценарий — страта (поля scenario_id в схеме нет — страта выводится из
префикса case_id); стратифицированный Ходжес–Леманн Δ̂ = med{Y−X} по
всем парам всех страт (вес страты ∝ m·n — автоматически числом пар);
R̂ = e^Δ̂; отношение медиан печатается рядом. Критерий
T(δ) = Σ sgn(Y − δ − X); нуль-распределение — перестановки меток ступени
внутри страт: полный перебор при Π C(m+n, n) ≤ exact_max, иначе
Монте-Карло B с seed из предрегистрации (сплиты переиспользуются при всех
δ — общие случайные числа, побайтово детерминировано); MC: p=(1+#{})/(B+1),
точно: #{}/K; границы U/L бисекцией по попарным разностям (T монотонна по
δ); связи (квантованный поллинг settle) учитываются перестановками точно.

Вердикт (α = 0.05): PASS_p ⇔ U_p < ln M_p; FAIL_p — взвешенный Холм по
p_p = p₊(ln M_p), веса t_settle 0.5 / остальные 0.1; иначе UNKNOWN_p
(CI_STRADDLES). PASS гейта = PASS всех шести (intersection–union, без
поправки); «нет FAIL» НИКОГДА не читается как PASS. Гварды целого прогона
(PREREG_*, BASELINE_INVALID, UPSTREAM_NOT_GREEN, NO_CONCURRENCY,
CLOCK_SUSPECT) капят ЛЮБОЙ фазовый вердикт в UNKNOWN — данные недоверены.

Маржа (формула заморожена; числа — только из базиса, никогда из B):
M_p = max(κ_p·(1+τ_p) + q_p/m_p; 1 + a_p/m_p); τ = 0.25, a = 0.05 с,
q = Δ_poll только для t_settle; κ — модель экспозиции при resource_map в
предрегистрации (ρ_r = доля медиан фаз ресурса в сумме медиан базиса,
u = 1 без профилирования), иначе потолок: 2 для фаз стенда / 1 для
t_scoring (локальный CPU); потолок κ ≤ 2 в любом случае.

Схема данных (прочитано в коде, не выдумано; полное описание — §4 хендофа):
- attempts.jsonl (AttemptRecord, schema 1): timing: {фаза: float|null}|null
  аддитивно (P12); worker_id НЕТ; scenario_id НЕТ (страта = префикс
  case_id CASE-<attack>-<NNN>-<uuid6>); меток начала/конца попытки НЕТ;
  флага таймаута settle НЕТ.
- campaign.json: results[].stages[] с reason — маркер таймаута settle
  (persistence: «критерий записи не появился…»); metadata.adapter —
  метка стенда (mock/live-прокси).
- events.jsonl: строки с timestamp/ts/created_at (TraceEvent несёт ISO
  UTC; сырые события мока полей времени НЕ несут) — единственный источник
  стены блока и сверки штампа предрегистрации.
- Оркестратор P13-a: воркеры — соседние `<dir>-w<i>`, сводка
  `<dir>-orchestrator.json`; блок B может быть каталогом оркестратора.

Следствия честности (отсутствие сигнала = UNKNOWN с именем, не PASS):
- worker_id нет → прогрев воркера не исключается (счёт попыток это печатает);
- меток попытки нет → подвёрстка CLOCK_SUSPECT «сумма фаз > длительности
  попытки» НЕ проверяется (остальные три признака работают);
- без events-меток NO_CONCURRENCY считается по сумме фаз (занижает —
  ошибка в безопасную сторону), а штамп предрегистрации неверифицируем
  (PREREG_DEVIATION);
- без campaign.json цензура settle неверифицируема (CENSORED_HIGH).
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import itertools
import json
import math
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from memnotsafe.core.attempt import AttemptHistoryError, read_history

SCHEMA_VERSION = "timing-regress/1"

PHASES = ("t_reset", "t_delivery", "t_finalize", "t_settle", "t_trigger", "t_scoring")
IO_PHASES = frozenset(p for p in PHASES if p != "t_scoring")
STAND_PHASES = frozenset(IO_PHASES)  # κ-потолок 2; t_scoring — синхронный локальный CPU

EXIT_PASS, EXIT_FAIL, EXIT_UNKNOWN = 0, 1, 2

DEFAULT_UNKNOWN = {
    "f_null_max": 0.10,
    "f_censor_max": 0.10,
    "drift_tol": 0.15,
    "conc_min": 1.5,
    "strata_lost_max": 0.34,
}

_PREREG_REQUIRED = (
    "prereg_id", "alpha", "holm_weights", "perm", "kappa", "tau",
    "abs_floor_s", "poll_quantum_s", "design", "n_min_per_stage",
    "unknown", "stopping", "scenarios", "stamp",
)

# Маркеры таймаута settle в reason стадии persistence (oracles/persistence.py,
# adapters/investment_stand.py: «не появился … за Ns», мок: «не выполнен»).
_SETTLE_TIMEOUT_MARKERS = ("не появился", "не выполнен")

# Seed дрейф-теста A/A′: в предрегистрации его нет (дизайн молчит); фиксиром
# держим побайтовую воспроизводимость отчёта.
_DRIFT_SEED = 0xC0FFEE


class TimingRegressError(ValueError):
    """Ошибка входа компаратора (нет каталога, битая история)."""


class PreregError(ValueError):
    """Неверифицируемая предрегистрация: kind = missing | deviation."""

    def __init__(self, message: str, *, kind: str = "deviation"):
        super().__init__(message)
        self.kind = kind


# ---------------------------------------------------------------- предрегистрация

def _canonical_prereg_sha256(data: dict) -> str:
    """Самоподпись JSON: sha256 канонической сериализации БЕЗ поля
    sha256_self (sort_keys, без пробелов). Ловит правку после заморозки."""
    payload = {k: v for k, v in data.items() if k != "sha256_self"}
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def parse_stamp(value) -> float:
    """Штамп: ISO-8601 (допускается Z) или unix-секунды → epoch UTC."""
    if isinstance(value, bool):
        raise PreregError(f"штамп предрегистрации не читается: {value!r}")
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError as exc:
        raise PreregError(f"штамп предрегистрации не читается: {value!r}") from exc


def load_prereg(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        raise PreregError(f"файл предрегистрации не существует: {p}", kind="missing")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PreregError(f"предрегистрация не читается как JSON: {exc}", kind="missing")
    if not isinstance(data, dict):
        raise PreregError("предрегистрация обязана быть JSON-объектом", kind="missing")
    missing = [k for k in _PREREG_REQUIRED if k not in data]
    if missing:
        raise PreregError(f"предрегистрация отклоняется от поля: нет {missing}")
    if data["stopping"] != "fixed_n_no_extension":
        raise PreregError(
            f"stopping={data['stopping']!r} не поддерживается "
            "(допускается только fixed_n_no_extension — досбор запрещён)"
        )
    try:
        n_min = int(data["n_min_per_stage"])
    except (TypeError, ValueError) as exc:
        raise PreregError(f"n_min_per_stage не читается: {exc}") from exc
    if n_min < 5:
        raise PreregError("n_min_per_stage < 5: при 4 vs 4 p_min = 1/70 — FAIL вторичной фазы недостижим")
    parse_stamp(data["stamp"])
    self_hash = data.get("sha256_self")
    if self_hash is not None and self_hash != _canonical_prereg_sha256(data):
        raise PreregError(
            "sha256_self не сходится — JSON правился после заморозки"
        )
    return data


# ---------------------------------------------------------------- блоки прогона

@dataclass
class AttemptObs:
    """Попытка на target (attempt_no≥1): тайминги и исход."""

    case_id: str
    stratum: str
    outcome: str
    timing: dict | None
    settle_timeout: bool | None = None  # campaign.json; None = маркера нет


@dataclass
class Block:
    name: str
    run_dirs: list[Path]
    attempts: list[AttemptObs] = field(default_factory=list)
    bookkeeping: int = 0                       # attempt_no=0: registered/rewrite/budget
    excluded: dict[str, int] = field(default_factory=dict)
    wall_start: float | None = None            # events.jsonl → epoch; None = меток нет
    wall_end: float | None = None
    adapter: str | None = None
    b0_snapshot: bool = False


def _stratum_of(case_id: str) -> str:
    """Семейство атаки из case_id = CASE-<attack_id>-<NNN>-<uuid6>.
    Поля scenario_id в схеме нет — единственный кодируемый прокси."""
    if case_id.startswith("CASE-"):
        parts = case_id.split("-")
        if len(parts) >= 4:
            return "-".join(parts[1:-2])
    return case_id


def _parse_event_ts(row: dict) -> float | None:
    for key in ("timestamp", "ts", "created_at"):
        raw = row.get(key)
        if raw is None:
            continue
        try:
            return parse_stamp(raw)
        except PreregError:
            continue
    return None


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _settle_timeout_flags(campaign: dict) -> dict[str, bool]:
    """Таймаут settle по case_id: стадия persistence с маркером таймаута в
    reason. Кейс без стадии (не дошёл до оценки) → ключа нет = сигнала нет."""
    flags: dict[str, bool] = {}
    for result in campaign.get("results") or []:
        case_id = result.get("case_id")
        if not case_id:
            continue
        for stage in result.get("stages") or []:
            if stage.get("stage") != "persistence":
                continue
            reason = str(stage.get("reason") or "")
            flags[case_id] = any(m in reason for m in _SETTLE_TIMEOUT_MARKERS)
    return flags


def _discover_run_dirs(block_dir: Path) -> list[Path]:
    """Блок = один run-каталог (N=1) ИЛИ каталог оркестратора P13-a (воркеры
    `<dir>-w<i>`, сводка `<dir>-orchestrator.json`, замки `<dir>/locks`)."""
    if (block_dir / "attempts.jsonl").exists():
        return [block_dir]
    found: list[Path] = []
    summary = _read_json(block_dir.with_name(block_dir.name + "-orchestrator.json"))
    if summary:
        for worker in summary.get("workers") or []:
            run_dir = Path(worker.get("run_dir") or "")
            if run_dir and (run_dir / "attempts.jsonl").exists():
                found.append(run_dir)
    if not found:
        found = sorted(d for d in block_dir.parent.glob(block_dir.name + "-w*")
                       if d.is_dir() and (d / "attempts.jsonl").exists())
    if not found:
        found = sorted(d for d in block_dir.iterdir()
                       if d.is_dir() and (d / "attempts.jsonl").exists())
    if not found:
        raise TimingRegressError(
            f"блок {block_dir}: нет attempts.jsonl ни в самом каталоге, "
            "ни в воркер-подкаталогах — сравнивать нечего"
        )
    return found


def load_block(name: str, block_dir: str | Path) -> Block:
    directory = Path(block_dir)
    if not directory.exists():
        raise TimingRegressError(f"блок {name}: каталог не существует: {directory}")
    block = Block(name=name, run_dirs=_discover_run_dirs(directory))
    settle_flags: dict[str, bool] = {}
    ts_min = ts_max = None
    for run_dir in block.run_dirs:
        if list(run_dir.glob("snapshot-v*.json")) or list(run_dir.glob("b0-snapshot*.json")):
            block.b0_snapshot = True
        campaign = _read_json(run_dir / "campaign.json")
        if campaign is not None:
            meta = campaign.get("metadata") or {}
            block.adapter = block.adapter or meta.get("adapter")
            settle_flags.update(_settle_timeout_flags(campaign))
        events_path = run_dir / "events.jsonl"
        if events_path.exists():
            for line in events_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    ts = _parse_event_ts(row)
                    if ts is not None:
                        ts_min = ts if ts_min is None else min(ts_min, ts)
                        ts_max = ts if ts_max is None else max(ts_max, ts)
    block.wall_start, block.wall_end = ts_min, ts_max

    records = []
    for run_dir in block.run_dirs:
        records.extend(read_history(run_dir / "attempts.jsonl"))
    for rec in records:
        if rec.attempt_no < 1:
            block.bookkeeping += 1
            continue
        if rec.timing is None and rec.outcome in ("transport_error", "aborted"):
            # попытка НАЧАЛАСЬ (умерла на target) — остаётся в знаменателе
            # attrition (дизайн §4.7), но в счёте попыток показывается как
            # исключённая из тайминг-анализа
            block.excluded[rec.outcome] = block.excluded.get(rec.outcome, 0) + 1
        block.attempts.append(AttemptObs(
            case_id=rec.case_id,
            stratum=_stratum_of(rec.case_id),
            outcome=rec.outcome,
            timing=rec.timing,
            settle_timeout=settle_flags.get(rec.case_id),
        ))
    return block


# ---------------------------------------------------------------- статистика

def _phase_pairs(attempts: list[AttemptObs], phase: str) -> list[tuple[str, float]]:
    """Валидные наблюдения фазы: (страта, ℓ=ln max(t,1e-6)). Не-числа, null и
    нули не входят (нули I/O-фаз ловит CLOCK_SUSPECT раньше — гвардом всего
    прогона, до фазового анализа)."""
    out = []
    for obs in attempts:
        if obs.timing is None:
            continue
        raw = obs.timing.get(phase)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw > 0:
            out.append((obs.stratum, math.log(max(float(raw), 1e-6))))
    return out


def _group_by_stratum(pairs: list[tuple[str, float]]) -> dict[str, list[float]]:
    grouped: dict[str, list[float]] = {}
    for stratum, value in pairs:
        grouped.setdefault(stratum, []).append(value)
    return grouped


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _hl_delta(x_groups: dict[str, list[float]], y_groups: dict[str, list[float]]) -> float:
    """Стратифицированный Ходжес–Леманн (медиана всех разностей Y−X)."""
    diffs = [
        y - x
        for stratum, ys in y_groups.items()
        for x in x_groups.get(stratum, [])
        for y in ys
    ]
    if not diffs:
        return float("nan")
    diffs.sort()
    return _median(diffs)


class _PermTest:
    """Перестановочный тест сдвига внутри страт (при одной страте — точный
    интервал Мозеса). Нуль H0: Δ=δ строится СДВИГОМ пула: значения ступени
    Y уменьшаются на δ ДО перемешивания меток, перестановки берутся из
    сдвинутого пула. (Равномерное применение δ к обеим сторонам на
    НЕсдвинутом пуле вырождается на крайних δ: T и T* сатурируются
    одинаково и p→1 — ловушка, найденная тестом k=1.) Сплиты фиксированы
    на время жизни объекта и переиспользуются при всех δ бисекции (общие
    случайные числа) — побайтовая воспроизводимость при том же seed."""

    def __init__(self, x_groups: dict[str, list[float]], y_groups: dict[str, list[float]],
                 *, exact_max: int, mc_b: int, seed: int):
        self._strata: list[dict] = []
        total_combos = 1
        for stratum in sorted(set(x_groups) | set(y_groups)):
            xs, ys = x_groups.get(stratum, []), y_groups.get(stratum, [])
            pooled = sorted(xs + ys)
            x_idx = _take_indices(pooled, xs)
            self._strata.append({
                "pooled": pooled,
                "x_idx": x_idx,
                "y_idx": set(range(len(pooled))) - x_idx,
                "n_y": len(ys),
            })
            total_combos *= math.comb(len(pooled), len(ys))
        self.exact = total_combos <= exact_max
        self.total_combos = total_combos
        self.mc_b = mc_b
        if not self.exact:
            rng = random.Random(seed)
            self._splits = [
                [set(rng.sample(range(len(st["pooled"])), st["n_y"])) for st in self._strata]
                for _ in range(mc_b)
            ]

    @staticmethod
    def _t_split(shifted: list[float], y_idx: set[int]) -> float:
        """T = Σ_{u∈Y} Σ_{v∈X} sgn(shifted[u] − shifted[v]); связи дают 0 —
        квантованный поллинг settle учитывается перестановками точно."""
        xs = sorted(shifted[i] for i in range(len(shifted)) if i not in y_idx)
        m = len(xs)
        total = 0
        for i in y_idx:
            a = shifted[i]
            cnt_lt = bisect.bisect_left(xs, a)
            cnt_le = bisect.bisect_right(xs, a)
            total += 2 * cnt_lt + (cnt_le - cnt_lt) - m
        return total

    def _shifted_pools(self, delta: float) -> list[list[float]]:
        return [[p - delta if i in st["y_idx"] else p
                 for i, p in enumerate(st["pooled"])] for st in self._strata]

    def evaluate(self, delta: float) -> tuple[float, float, float]:
        """(T(δ), p₊(δ)=P(T*≥T), p₋(δ)=P(T*≤T)); MC: p=(1+#{})/(B+1),
        точно: #{}/K (наблюдаемое разбиение всегда среди перестановок)."""
        shifted = self._shifted_pools(delta)
        t_obs = sum(self._t_split(s, st["y_idx"])
                    for s, st in zip(shifted, self._strata))
        if self.exact:
            combo_lists = [list(itertools.combinations(range(len(s)), st["n_y"]))
                           for s, st in zip(shifted, self._strata)]
            ge = le = count = 0
            for combo in itertools.product(*combo_lists):
                t = sum(self._t_split(s, set(y_idx))
                        for s, y_idx in zip(shifted, combo))
                count += 1
                if t >= t_obs:
                    ge += 1
                if t <= t_obs:
                    le += 1
            return t_obs, ge / count, le / count
        ge = le = 0
        for splits in self._splits:
            t = sum(self._t_split(s, y_idx) for s, y_idx in zip(shifted, splits))
            if t >= t_obs:
                ge += 1
            if t <= t_obs:
                le += 1
        return t_obs, (1 + ge) / (self.mc_b + 1), (1 + le) / (self.mc_b + 1)

    def ci_bounds(self, alpha: float, *, tol: float = 1e-4) -> tuple[float, float]:
        """(L, U): U = sup{δ: p₋(δ) > α}, L = inf{δ: p₊(δ) > α} — бисекция;
        скобки поиска гарантируются сатурацией T на крайних δ (T(→−∞)=+mn
        с p₋→1 слева, T(→+∞)=−mn с p₊→1 справа)."""
        diffs = []
        for st in self._strata:
            x_vals = [st["pooled"][i] for i in sorted(st["x_idx"])]
            y_vals = [st["pooled"][i] for i in sorted(st["y_idx"])]
            diffs.extend(y - x for y in y_vals for x in x_vals)
        if not diffs:
            return float("nan"), float("nan")
        lo, hi = min(diffs) - 1.0, max(diffs) + 1.0
        a, b = lo, hi
        if self.evaluate(a)[2] <= alpha:
            return float("nan"), a
        for _ in range(60):
            if b - a <= tol:
                break
            mid = (a + b) / 2.0
            if self.evaluate(mid)[2] > alpha:
                a = mid
            else:
                b = mid
        u = a
        a, b = lo, hi
        if self.evaluate(b)[1] <= alpha:
            return b, u
        for _ in range(60):
            if b - a <= tol:
                break
            mid = (a + b) / 2.0
            if self.evaluate(mid)[1] > alpha:
                b = mid
            else:
                a = mid
        return b, u


def _take_indices(pooled: list[float], values: list[float]) -> set[int]:
    """Индексы значений X в отсортированном пуле с корректным расходом
    дублей (равные значения распределяются 1:1 по вхождениям)."""
    positions: dict[float, list[int]] = {}
    for i, p in enumerate(pooled):
        positions.setdefault(p, []).append(i)
    counters: dict[float, int] = {}
    idxs: set[int] = set()
    for v in values:
        lst = positions[v]
        idxs.add(lst[counters.get(v, 0)])
        counters[v] = counters.get(v, 0) + 1
    return idxs


def _fisher_exact_one_sided(a: int, b: int, c: int, d: int) -> float:
    """Точный односторонний Фишер 2×2 (без scipy): p = P[X ≥ a],
    X ~ Hyp(N=a+b+c+d, K=a+c, draws=a+b)."""
    n, k, draws = a + b + c + d, a + c, a + b
    lo, hi = max(0, draws - (n - k)), min(draws, k)

    def dens(x: int) -> float:
        return math.comb(k, x) * math.comb(n - k, draws - x)

    total = sum(dens(x) for x in range(lo, hi + 1))
    return sum(dens(x) for x in range(a, hi + 1)) / total


# ---------------------------------------------------------------- κ и маржа

def _kappa_map(prereg: dict, base_seconds_medians: dict[str, float]) -> dict[str, float]:
    """κ по фазам. exposure: κ_p = 1 + Σ_{r: p∈map[r]} ρ_r, где ρ_r — доля
    суммы медиан фаз ресурса r в сумме всех медиан базиса (в секундах);
    u=1 без профилирования. ceiling: 2 для фаз стенда / 1 для t_scoring.
    Потолок cap ≤ 2 в любом случае."""
    cfg = prereg.get("kappa") or {}
    cap = min(float(cfg.get("cap", 2.0)), 2.0)
    out: dict[str, float] = {}
    resource_map = cfg.get("resource_map") if cfg.get("model") == "exposure" else None
    if resource_map:
        total = sum(v for v in base_seconds_medians.values() if v > 0)
        for phase in PHASES:
            kappa = 1.0
            if total > 0:
                for _resource, phases in resource_map.items():
                    if phase in phases:
                        kappa += sum(base_seconds_medians.get(q, 0.0)
                                     for q in phases if base_seconds_medians.get(q, 0.0) > 0) / total
            out[phase] = min(kappa, cap)
    else:
        for phase in PHASES:
            out[phase] = min(2.0 if phase in STAND_PHASES else 1.0, cap)
    return out


def _margin(prereg: dict, phase: str, med_base_seconds: float,
            kappa: float) -> float:
    """M_p = max(κ·(1+τ) + q/m; 1 + a/m) — m в СЕКУНДАХ, из базиса."""
    tau = float((prereg.get("tau") or {}).get(phase, 0.25))
    abs_floor = float((prereg.get("abs_floor_s") or {}).get(phase, 0.05))
    q = float(prereg.get("poll_quantum_s") or 0.0) if phase == "t_settle" else 0.0
    return max(kappa * (1.0 + tau) + q / med_base_seconds,
               1.0 + abs_floor / med_base_seconds)


def _holm_weighted(p_values: dict[str, float], weights: dict[str, float],
                   alpha: float) -> set[str]:
    """Взвешенный Холм: порядок по p/w; шаг k отвергает при
    p_(k) ≤ α·w_(k)/Σ_оставшихся w; остановка на первом неотвержении."""
    items = [(name, p_values[name], float(weights.get(name, 0.0)))
             for name in p_values if p_values[name] == p_values[name]]
    items.sort(key=lambda t: t[1] / t[2] if t[2] > 0 else float("inf"))
    remaining = sum(w for _, _, w in items)
    rejected: set[str] = set()
    for name, p, w in items:
        if w <= 0:
            break
        if p <= alpha * w / remaining:
            rejected.add(name)
            remaining -= w
        else:
            break
    return rejected


# ---------------------------------------------------------------- гварды

def _clock_guard(blocks: list[Block], codes: list[str], signals: list[str]) -> None:
    """CLOCK_SUSPECT (весь прогон): отрицательные значения; ровно 0.0 в
    I/O-фазе; все значения фазы в блоке равны (scripted/frozen clock).
    Подвёрстка «сумма фаз > длительности попытки» НЕ проверяется: меток
    начала/конца попытки в схеме нет (докстринг, §4 хендофа)."""
    for block in blocks:
        for obs in block.attempts:
            if obs.timing is None:
                continue
            for phase, raw in obs.timing.items():
                if not isinstance(raw, (int, float)) or isinstance(raw, bool):
                    continue
                if raw < 0:
                    codes.append("CLOCK_SUSPECT")
                    signals.append(f"отрицательное значение {phase}={raw} (case {obs.case_id})")
                    return
                if raw == 0 and phase in IO_PHASES:
                    codes.append("CLOCK_SUSPECT")
                    signals.append(f"{phase}=0.0 в I/O-фазе (case {obs.case_id}) — замороженные часы?")
                    return
        for phase in PHASES:
            vals = [o.timing[phase] for o in block.attempts
                    if o.timing is not None
                    and isinstance(o.timing.get(phase), (int, float))
                    and not isinstance(o.timing.get(phase), bool)]
            if len(vals) > 1 and len(set(vals)) == 1:
                codes.append("CLOCK_SUSPECT")
                signals.append(f"все значения {phase} в блоке {block.name} равны ({vals[0]}) — scripted clock")
                return


def _concurrency(b_block: Block) -> tuple[float, str]:
    """conc = Σ длительностей попыток B / стена B (events.jsonl). Без меток
    времени — по сумме фаз (даёт 1.0 < conc_min: занижает, безопасно)."""
    total = 0.0
    for obs in b_block.attempts:
        if obs.timing:
            total += sum(v for v in obs.timing.values()
                         if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0)
    if b_block.wall_start is None or b_block.wall_end is None:
        return 1.0, "нет меток времени — по сумме фаз (занижает)"
    wall = b_block.wall_end - b_block.wall_start
    if wall <= 0:
        return 1.0, "нулевая/отрицательная стена — по сумме фаз (занижает)"
    return total / wall, "по events.jsonl"


def _settle_timeouts(attempts: list[AttemptObs]) -> int:
    return sum(1 for o in attempts if o.settle_timeout is True)


def _censor_state(base: list[AttemptObs], stage_b: list[AttemptObs],
                  cfg: dict) -> tuple[bool, str | None]:
    """CENSORED_HIGH (t_settle): доля таймаутов > f_censor_max в любой
    ступени; без единого маркера (нет campaign.json) — неверифицируемо."""
    for name, group in (("базис", base), ("B", stage_b)):
        flagged = [o for o in group if o.settle_timeout is not None]
        if not flagged:
            continue
        share = _settle_timeouts(group) / len(flagged)
        if share > cfg["f_censor_max"]:
            return True, (f"таймауты settle: {name} {_settle_timeouts(group)}/{len(flagged)} "
                          f"> f_censor_max {cfg['f_censor_max']}")
    if all(o.settle_timeout is None for o in base + stage_b):
        return True, "нет маркеров таймаута settle (campaign.json отсутствует) — цензура неверифицируема"
    return False, None


def _attrition_state(started_base: int, timed_base: int, started_b: int, timed_b: int,
                     cfg: dict, alpha: float) -> tuple[bool, str | None]:
    """ATTRITION: доля попыток без t_p > f_null_max в любой ступени, ИЛИ
    в B выше базиса значимо (точный односторонний Фишер, α)."""
    nulls_base, nulls_b = started_base - timed_base, started_b - timed_b
    for name, nulls, started in (("базис", nulls_base, started_base), ("B", nulls_b, started_b)):
        if started and nulls / started > cfg["f_null_max"]:
            return True, (f"доля попыток без тайминга: {name} {nulls}/{started} "
                          f"> f_null_max {cfg['f_null_max']}")
    if started_base and started_b and nulls_b > nulls_base:
        p = _fisher_exact_one_sided(nulls_b, started_b - nulls_b,
                                    nulls_base, started_base - nulls_base)
        if p < alpha:
            return True, (f"потери B выше базиса: {nulls_b}/{started_b} против "
                          f"{nulls_base}/{started_base}, Фишер p={p:.4f}")
    return False, None


def _stand_drift(kept_a: list[AttemptObs], kept_a2: list[AttemptObs], phase: str,
                 alpha: float, cfg: dict, n_min: int) -> str | None:
    """STAND_DRIFT (фаза): сдвиг A′ против A значим на α (два односторонних
    по α/2 — эквивалент 90% CI без нуля) И |ln R̂| > ln(1+drift_tol). При
    недостатке данных в одном из блоков тест не выполняется (None) —
    покрывается фазовым N_LOW на объединённом базисе; честная граница,
    раскрыта в хендофе. Seed фиксирован — побайтовая воспроизводимость."""
    x = _phase_pairs(kept_a, phase)
    y = _phase_pairs(kept_a2, phase)
    if min(len(x), len(y)) < max(2, n_min // 2):
        return None
    delta_hat = _hl_delta(_group_by_stratum(x), _group_by_stratum(y))
    perm = _PermTest(_group_by_stratum(x), _group_by_stratum(y),
                     exact_max=100000, mc_b=2000, seed=_DRIFT_SEED)
    p_plus, p_minus = perm.evaluate(0.0)[1:3]
    significant = p_plus < alpha / 2.0 or p_minus < alpha / 2.0
    if significant and abs(delta_hat) > math.log(1.0 + cfg["drift_tol"]):
        return "STAND_DRIFT"
    return None


# ---------------------------------------------------------------- компаратор

def compare(prereg: dict, a_block: Block, b_block: Block, a2_block: Block,
            *, upstream_green: bool) -> dict:
    """Полный проход: гварды целого прогона → фазовые гварды → маржа →
    CI → Холм → вердикт. Детерминирован при том же seed предрегистрации."""
    codes_whole: list[str] = []
    signals: list[str] = []

    def whole(code: str, signal: str) -> None:
        codes_whole.append(code)
        signals.append(signal)

    # --- UPSTREAM_NOT_GREEN: без явного подтверждения вердикт не выше UNKNOWN
    if not upstream_green and not prereg.get("upstream_green"):
        whole("UPSTREAM_NOT_GREEN",
              "подтверждение «G3.1–G3.4 зелёные» не предъявлено "
              "(поле upstream_green / флаг --upstream-green); их FAIL ⇒ FAIL G3.5 — "
              "решается вручную, автоматикой не читается")

    # --- BASELINE_INVALID: B0-снимок, не-N=1 базис, метки стенда
    if a_block.b0_snapshot or a2_block.b0_snapshot:
        whole("BASELINE_INVALID",
              "базис содержит B0-снимок (v3.34(б): не допускается даже справочно)")
    if len(a_block.run_dirs) > 1 or len(a2_block.run_dirs) > 1:
        whole("BASELINE_INVALID",
              f"базис не N=1: воркер-каталогов A={len(a_block.run_dirs)}, "
              f"A′={len(a2_block.run_dirs)}")
    all_blocks = (a_block, b_block, a2_block)
    if any(b.adapter is None for b in all_blocks):
        whole("BASELINE_INVALID",
              "метка стенда (campaign.json metadata.adapter) отсутствует хотя бы в "
              "одном блоке — совпадение базиса и ступени неверифицируемо")
    elif len({b.adapter for b in all_blocks}) > 1:
        whole("BASELINE_INVALID",
              f"стенды/адаптеры различаются между блоками: "
              f"{sorted(str(b.adapter) for b in all_blocks)}")

    # --- PREREG_DEVIATION: штамп предрегистрации против первой попытки A
    if a_block.wall_start is None:
        whole("PREREG_DEVIATION",
              "в блоке A нет временных меток (events.jsonl) — штамп не сверить "
              "с первой попыткой")
    elif parse_stamp(prereg["stamp"]) >= a_block.wall_start:
        whole("PREREG_DEVIATION",
              "штамп предрегистрации не раньше первой попытки блока A")

    # --- CLOCK_SUSPECT (до фазового анализа — данным не доверяем)
    _clock_guard(list(all_blocks), codes_whole, signals)

    # --- NO_CONCURRENCY
    unknown_cfg = dict(DEFAULT_UNKNOWN)
    unknown_cfg.update(prereg.get("unknown") or {})
    conc, conc_note = _concurrency(b_block)
    if conc < float(unknown_cfg["conc_min"]):
        whole("NO_CONCURRENCY",
              f"фактическая контенция B = {conc:.2f} < {unknown_cfg['conc_min']} "
              f"({conc_note})")

    # --- наблюдения
    scenarios = list(prereg["scenarios"])
    kept = {}
    for block in all_blocks:
        kept[block.name] = [o for o in block.attempts if o.stratum in scenarios]
    kept_base = kept["A"] + kept["A2"]
    dropped = sum(len(b.attempts) - len(kept[b.name]) for b in all_blocks)
    present_base = {o.stratum for o in kept_base}
    present_b = {o.stratum for o in kept["B"]}
    lost_share = max(sum(1 for s in scenarios if s not in present_base),
                     sum(1 for s in scenarios if s not in present_b)) / max(len(scenarios), 1)

    alpha = float(prereg["alpha"])
    n_min = int(prereg["n_min_per_stage"])

    # медианы базиса в СЕКУНДАХ — для κ (exposure) и маржи; никогда из B
    base_seconds_medians: dict[str, float] = {}
    for phase in PHASES:
        med = _median([math.exp(v) for _, v in _phase_pairs(kept_base, phase)])
        if med is not None:
            base_seconds_medians[phase] = med
    kappas = _kappa_map(prereg, base_seconds_medians)

    phases_out: list[dict] = []
    stats: dict[str, dict] = {}
    for phase in PHASES:
        x_pairs = _phase_pairs(kept_base, phase)
        y_pairs = _phase_pairs(kept["B"], phase)
        x_groups, y_groups = _group_by_stratum(x_pairs), _group_by_stratum(y_pairs)
        med_x = _median([v for _, v in x_pairs])
        med_y = _median([v for _, v in y_pairs])
        entry = {"phase": phase, "n_base": len(x_pairs), "n_b": len(y_pairs),
                 "med_base_s": round(math.exp(med_x), 4) if med_x is not None else None,
                 "med_b_s": round(math.exp(med_y), 4) if med_y is not None else None}
        started_base, started_b = len(kept_base), len(kept["B"])
        code: str | None = None
        detail: str | None = None
        if not x_pairs and not y_pairs:
            code, detail = "TELEMETRY_LOST", ("нет ни одного наблюдения с timing "
                                              "(старая схема или null-фаза)")
        elif lost_share > float(unknown_cfg["strata_lost_max"]):
            code, detail = "STRATA_LOST", (f"доля сценариев без попыток в ступени = "
                                           f"{lost_share:.2f} > {unknown_cfg['strata_lost_max']}")
        elif min(len(x_pairs), len(y_pairs)) < n_min:
            code, detail = "N_LOW", (f"валидных наблюдений {min(len(x_pairs), len(y_pairs))} "
                                     f"< {n_min}")
        else:
            attr, attr_detail = _attrition_state(started_base, len(x_pairs),
                                                 started_b, len(y_pairs),
                                                 unknown_cfg, alpha)
            if attr:
                code, detail = "ATTRITION", attr_detail
            elif phase == "t_settle":
                cen, cen_detail = _censor_state(kept_base, kept["B"], unknown_cfg)
                if cen:
                    code, detail = "CENSORED_HIGH", cen_detail
        if code is None:
            drift = _stand_drift(kept["A"], kept["A2"], phase, alpha, unknown_cfg, n_min)
            if drift:
                code, detail = drift, ("A′ против A: значимый сдвиг сверх drift_tol — "
                                       "дрейф/деградация стенда")
        if code is None and not codes_whole:
            # тяжёлая статистика не считается, если вердикт уже capped
            # UNKNOWN-гвардом целого прогона — данным не доверяем, маржа
            # описательно не нужна (честно: в отчёте «—»)
            perm = _PermTest(x_groups, y_groups,
                             exact_max=int(prereg["perm"]["exact_max"]),
                             mc_b=int(prereg["perm"]["mc_B"]),
                             seed=int(prereg["perm"]["seed"]))
            l_, u_ = perm.ci_bounds(alpha)
            med_seconds = math.exp(med_x) if med_x is not None else 0.0
            margin = _margin(prereg, phase, med_seconds, kappas[phase])
            ln_m = math.log(margin)
            p_plus = perm.evaluate(ln_m)[1]
            delta_hat = _hl_delta(x_groups, y_groups)
            entry.update({
                "ci90": [round(math.exp(l_), 3) if l_ == l_ else None,
                         round(math.exp(u_), 3) if u_ == u_ else None],
                "margin_m": round(margin, 3),
                "kappa": round(kappas[phase], 3),
                "r_hat": round(math.exp(delta_hat), 3) if delta_hat == delta_hat else None,
                "med_ratio": round(math.exp(med_y - med_x), 3)
                if (med_x is not None and med_y is not None) else None,
                "perm_mode": "exact" if perm.exact else "mc",
            })
            stats[phase] = {"perm": perm, "l": l_, "u": u_, "p_plus": p_plus}
        entry["code"], entry["detail"] = code, detail
        phases_out.append(entry)

    # --- Холм по фазам, дошедшим до статистики
    rejected = _holm_weighted({p: stats[p]["p_plus"] for p in stats},
                              prereg["holm_weights"], alpha)
    for entry in phases_out:
        phase = entry["phase"]
        if entry["code"] is not None or phase not in stats:
            # фазовый гвард ИЛИ тяжёлая статистика пропущена из-за гварда
            # целого прогона — вердикт не выше UNKNOWN
            entry["verdict"] = "UNKNOWN"
            continue
        st = stats[phase]
        if phase in rejected:
            entry["verdict"] = "FAIL"
            entry["detail"] = (f"p₊(ln M)={st['p_plus']:.4f} ≤ порога Холма — "
                               f"регресс сверх маржи ×{entry['margin_m']}")
        elif st["u"] < math.log(entry["margin_m"]):
            entry["verdict"] = "PASS"
        else:
            entry["verdict"] = "UNKNOWN"
            entry["code"] = "CI_STRADDLES"
            entry["detail"] = (f"U={math.exp(st['u']):.2f} ≥ M={entry['margin_m']} — "
                               "регресс не исключён; недостающий сигнал: точность (n)")

    # --- гейт: гварды целого прогона капят ЛЮБОЙ фазовый вердикт в UNKNOWN
    if codes_whole:
        verdict = "UNKNOWN"
        for entry in phases_out:
            entry["verdict"] = "UNKNOWN"
            if entry["code"] is None:
                entry["code"] = codes_whole[0]
                entry["detail"] = signals[0]
    elif any(e["verdict"] == "FAIL" for e in phases_out):
        verdict = "FAIL"
    elif all(e["verdict"] == "PASS" for e in phases_out):
        verdict = "PASS"
    else:
        verdict = "UNKNOWN"

    report = {
        "schema_version": SCHEMA_VERSION,
        "verdict": verdict,
        "prereg": {
            "prereg_id": prereg.get("prereg_id"),
            "sha256": _canonical_prereg_sha256(prereg)[:12],
            "stamp": prereg.get("stamp"),
        },
        "instrumental": any(b.adapter and "mock" in str(b.adapter).lower()
                            for b in all_blocks),
        "concurrency": {"ratio": round(conc, 3), "source": conc_note},
        "codes_whole": codes_whole,
        "signals": signals,
        "phases": phases_out,
        "counts": _counts(a_block, b_block, a2_block, kept, dropped),
        "blind_zone": _blind_zone(phases_out),
        "strata_lost_share": round(lost_share, 3),
    }
    return report


def _counts(a: Block, b: Block, a2: Block, kept: dict[str, list[AttemptObs]],
            dropped: int) -> dict:
    excluded: dict[str, int] = {}
    for block in (a, b, a2):
        for k, v in block.excluded.items():
            excluded[k] = excluded.get(k, 0) + v
    return {
        "block_a": len(a.attempts), "block_b": len(b.attempts),
        "block_a2": len(a2.attempts),
        "baseline_used": len(kept["A"]) + len(kept["A2"]),
        "b_used": len(kept["B"]),
        "bookkeeping": a.bookkeeping + b.bookkeeping + a2.bookkeeping,
        "excluded": excluded,
        "dropped_out_of_prereg": dropped,
        "warmup_excluded": 0,
        "warmup_note": ("worker_id в схеме attempts.jsonl нет — прогрев воркера "
                        "не исключается"),
    }


def _blind_zone(phases_out: list[dict]) -> list[str]:
    lines = []
    for e in phases_out:
        if e.get("margin_m") and e.get("kappa"):
            lines.append(f"{e['phase']}: ×{(e['margin_m'] / e['kappa']):.2f} "
                         "сверх κ не различим")
    n_max = max([e.get("n_b") or 0 for e in phases_out] + [0])
    if n_max < 59:
        lines.append("p90/p95 — нет оценки (n<59)")
    return lines


# ---------------------------------------------------------------- рендер и CLI

def render_text(report: dict) -> str:
    verdict = report["verdict"]
    exit_code = {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL, "UNKNOWN": EXIT_UNKNOWN}[verdict]
    lines = [
        f"G3.5/timing verdict={verdict} exit={exit_code} "
        f"prereg={report['prereg']['prereg_id']} sha256={report['prereg']['sha256']}",
    ]
    if report.get("instrumental"):
        lines.append("инструментальная проверка, не вердикт G3.5 (mock)")
    lines.append("фаза        nAA′  nB  medAA′  medB  R̂     CI90          M     вердикт  код")
    for e in report["phases"]:
        med_x = f"{e['med_base_s']:.2f}" if e.get("med_base_s") is not None else "—"
        med_y = f"{e['med_b_s']:.2f}" if e.get("med_b_s") is not None else "—"
        r_hat = f"{e['r_hat']:.2f}" if e.get("r_hat") is not None else "—"
        ci = (f"[{e['ci90'][0]:.2f}; {e['ci90'][1]:.2f}]"
              if e.get("ci90") and all(v is not None for v in e["ci90"]) else "—")
        margin = f"{e['margin_m']:.2f}" if e.get("margin_m") else "—"
        lines.append(
            f"{e['phase']:<11} {e['n_base']:<5} {e['n_b']:<3} {med_x:<6}  "
            f"{med_y:<5} {r_hat:<5} {ci:<13} {margin:<5} {e['verdict']:<8} "
            f"{e['code'] or '—'}"
        )
        if e["verdict"] == "UNKNOWN" and e.get("detail"):
            lines.append(f"            └ {e['detail']}")
    for code, signal in zip(report["codes_whole"], report["signals"]):
        lines.append(f"UNKNOWN: {code} — {signal}")
    emitted = set()
    for e in report["phases"]:
        if e["code"] and e["code"] not in report["codes_whole"] and e["code"] not in emitted:
            emitted.add(e["code"])
            lines.append(f"UNKNOWN: {e['code']}({e['phase']}) — {e.get('detail') or ''}")
    for note in report.get("blind_zone", []):
        lines.append(f"Слепая зона: {note}")
    c = report["counts"]
    excluded = ", ".join(f"{k}×{v}" for k, v in sorted(c["excluded"].items())) or "0"
    lines.append(
        f"Счёт попыток: базис {c['baseline_used']} + B {c['b_used']} + книжковых "
        f"{c['bookkeeping']}; прогрев {c['warmup_excluded']} ({c['warmup_note']}); "
        f"исключены: {excluded}; вне предрегистрации: {c['dropped_out_of_prereg']}"
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    # CARD-P14-fix-stdout: рендер и справка содержат non-ASCII (′ U+2032, R̂,
    # русские строки); на cp1251/cp866-консоли Windows запись в stdout падала
    # UnicodeEncodeError, и счёт suite зависел от локали запускающего. Поток
    # переводится в utf-8 с заменой некодируемого — вывод не зависит от кодовой
    # страницы. Гвард — для потоков без reconfigure (подменённый sys.stdout =
    # io.StringIO, sys.stdout=None под pythonw); потоки pytest capsys/capfd —
    # TextIOWrapper, для них вызов проходит и безвреден.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="python -m memnotsafe.reporting.timing_regress",
        description="CARD-P14: компаратор тайминг-регресса G3.5 (read-only)",
    )
    parser.add_argument("--prereg", required=True,
                        help="JSON предрегистрации (заморожен до прогона)")
    parser.add_argument("--upstream-green", action="store_true",
                        help="явное подтверждение «G3.1–G3.4 зелёные»")
    parser.add_argument("--output", default=None,
                        help="путь для машинного JSON-отчёта")
    parser.add_argument("a_dir", help="run-каталог(и) блока A (N=1)")
    parser.add_argument("b_dir", help="run-каталог(и) блока B (N=2; допускается каталог оркестратора)")
    parser.add_argument("a2_dir", help="run-каталог(и) блока A′ (N=1)")
    args = parser.parse_args(argv)

    try:
        prereg = load_prereg(args.prereg)
        blocks = [load_block(name, d) for name, d in
                  (("A", args.a_dir), ("B", args.b_dir), ("A2", args.a2_dir))]
    except PreregError as exc:
        code = "PREREG_MISSING" if exc.kind == "missing" else "PREREG_DEVIATION"
        print(f"G3.5/timing verdict=UNKNOWN exit=2 prereg=<нет> sha256=—")
        print(f"UNKNOWN: {code} — {exc}")
        return EXIT_UNKNOWN
    except (TimingRegressError, AttemptHistoryError, OSError) as exc:
        print(f"ОШИБКА: {exc}")
        return EXIT_UNKNOWN

    report = compare(prereg, *blocks, upstream_green=args.upstream_green)
    sys.stdout.write(render_text(report))
    if args.output:
        Path(args.output).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL, "UNKNOWN": EXIT_UNKNOWN}[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
