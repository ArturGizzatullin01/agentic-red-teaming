"""src/memnotsafe/core/plan.py — CARD-MULTI-1 (Этап 1, офлайн): планировщик
пакетов проверок поверх существующих команд.

Отвечает за ЧТО и В КАКОМ ПОРЯДКЕ гонять пакет заданий по стендам; КАК запускать
дочерний прогон (подпроцесс CLI) — инжектируемый `runner` (дефолтный —
`core/worker.orchestrate_plan`). Слои:

* модель плана (`Plan`/`Stand`/`Job`) + `load_plan`/`validate_plan` — валидация
  ДО первого запуска, стоп с конкретной причиной (`PlanError`);
* планировщик `run_plan` — очередь, 1 активное задание на стенд, изоляция по
  `isolation_group` (общая группа блокирует параллелизм), потолок параллельных
  стендов и общий потолок вызовов; каждый job_id выдаётся ровно один раз
  (повторы — только через `iterations`); re-check чистоты стенда перед выдачей;
* таксономия исходов — транспорт/401/429/неполный finalize/неизвестно/бюджет —
  различимы, никаких скрытых повторов;
* сводка `build_summary`/`write_batch` — batch_id, дочерние experiment_id,
  статусы, ASR как N of M, расходы, ссылки на артефакты; UNKNOWN ≠ False;
  секретов нет; `rebuild_summary` пересобирает сводку из артефактов, НЕ
  перезапуская задания.

Границы: тексты сценариев не открываются (сценарий проверяется на
СУЩЕСТВОВАНИЕ, принципалы берутся из target_profile плана, не из YAML); движок
стадий и старый `orchestrate --scenario` не затрагиваются.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml

from memnotsafe.core.ledger import (
    OP_TARGET_CALL,
    PHASE_EXECUTED,
    LedgerError,
    read_ledger,
)

BATCH_SUMMARY_SCHEMA_VERSION = 1

# Имя файла бюджетного леджера в run-каталоге дочернего прогона
# (core/ledger.py, campaign.py) — источник ФАКТА вызовов цели (FIX-PACK-2 D1).
LEDGER_FILE = "budget-ledger.jsonl"

# ---- Таксономия исходов задания (различимы, скрытых повторов нет) -----------
OUTCOME_COMPLETED = "completed"                 # дочерний прогон завершился, есть campaign.json
OUTCOME_TRANSPORT = "transport_error"           # сеть/таймаут/сброс соединения
OUTCOME_AUTH_401 = "auth_error_401"             # отказ авторизации стенда
OUTCOME_RATE_LIMITED_429 = "rate_limited_429"   # троттлинг стенда
OUTCOME_INCOMPLETE_FINALIZE = "incomplete_finalize"  # прогон не дописал финал
OUTCOME_UNKNOWN = "unknown"                     # исход не распознан (≠ провал)
OUTCOME_BUDGET_EXHAUSTED = "budget_exhausted"   # не выдан: превысил бы потолок вызовов
OUTCOME_STAND_DIRTY = "stand_dirty"             # clean_check провалился — не выдан
OUTCOME_STAND_CLEAN_UNKNOWN = "stand_clean_unknown"  # нет hook clean_check — не выдан
OUTCOME_BLOCKED = "blocked"                     # не выдан: неудовлетворимые зависимости / нет чистого стенда

# Исходы, при которых задание НЕ выполнялось на стенде (для сводки/статистики).
NOT_DISPATCHED = frozenset({
    OUTCOME_BUDGET_EXHAUSTED, OUTCOME_STAND_DIRTY, OUTCOME_STAND_CLEAN_UNKNOWN, OUTCOME_BLOCKED,
})


class PlanError(ValueError):
    """Контрактная ошибка плана — стоп ДО первого запуска, с конкретной причиной."""


# ------------------------------------------------------------------ модель
@dataclass(frozen=True)
class Stand:
    id: str
    target: str                       # target_profile.target — как дочерний run видит стенд (mock|URL)
    principals: tuple[str, ...]        # target_profile.principals — область принципалов (для изоляции)
    isolation_group: str
    slots: int
    clean_check: tuple[str, ...] | None  # target_profile.clean_check — hook (argv) или None


@dataclass(frozen=True)
class Job:
    id: str
    scenario: str
    control: str | None                # control|none: путь контрольного сценария или None
    iterations: int
    requires: tuple[str, ...]


@dataclass(frozen=True)
class Plan:
    version: int
    max_parallel_stands: int
    max_total_target_calls: int
    stands: tuple[Stand, ...]
    jobs: tuple[Job, ...]


@dataclass
class JobRun:
    """Результат/исход одного задания. Для НЕ выданных заданий stand_id=None и
    исход из NOT_DISPATCHED; для выданных — исход прогона + метрики из артефактов."""
    job_id: str
    stand_id: str | None
    outcome: str
    experiment_id: str | None = None
    asr_n: int | None = None           # успешных попыток (числитель ASR)
    asr_m: int | None = None           # всего попыток (знаменатель)
    asr_value: float | None = None     # end_to_end_asr; None = UNKNOWN (≠ 0)
    target_calls_committed: int = 0
    target_calls_actual: int | None = None    # ФАКТ из леджера (D1); None = UNKNOWN
    target_calls_estimate: bool = False        # True = actual — грубая оценка, леджера не было (D1)
    run_dir: str | None = None
    control_scenario: str | None = None
    control_outcome: str | None = None
    control_run_dir: str | None = None
    stand_principals: tuple[str, ...] | None = None  # принципалы стенда прогона (D6, атрибуция)
    detail: str | None = None


@dataclass(frozen=True)
class CleanResult:
    status: str          # "clean" | "dirty" | "unknown"
    detail: str = ""


CleanChecker = Callable[[Stand], CleanResult]
JobRunner = Callable[[Job, Stand, Path], Awaitable[JobRun]]


# ------------------------------------------------------------------ загрузка
def load_plan(path: str | Path) -> Plan:
    """Читает YAML-план в модель. Форму НЕ валидирует (это делает validate_plan);
    бросает PlanError только на грубо нечитаемую структуру."""
    p = Path(path)
    if not p.exists():
        raise PlanError(f"план не найден: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PlanError(f"план {p} должен быть отображением (mapping), получено {type(raw).__name__}")

    stands: list[Stand] = []
    for s in (raw.get("stands") or []):
        s = s if isinstance(s, dict) else {}
        prof = s.get("target_profile") if isinstance(s.get("target_profile"), dict) else {}
        cc = prof.get("clean_check")
        clean_check = tuple(str(x) for x in cc) if isinstance(cc, (list, tuple)) and cc else None
        principals = prof.get("principals")
        principals = tuple(str(x) for x in principals) if isinstance(principals, (list, tuple)) else ()
        stands.append(Stand(
            id=str(s.get("id") or ""),
            target=str(prof.get("target") or ""),
            principals=principals,
            isolation_group=str(s.get("isolation_group") or ""),
            slots=int(s["slots"]) if str(s.get("slots", "")).strip() not in ("", "None") else 1,
            clean_check=clean_check,
        ))

    jobs: list[Job] = []
    for j in (raw.get("jobs") or []):
        j = j if isinstance(j, dict) else {}
        control = j.get("control")
        control = None if control in (None, "none", "None", "") else str(control)
        req = j.get("requires") or []
        requires = tuple(str(x) for x in req) if isinstance(req, (list, tuple)) else ()
        jobs.append(Job(
            id=str(j.get("id") or ""),
            scenario=str(j.get("scenario") or ""),
            control=control,
            iterations=int(j["iterations"]) if str(j.get("iterations", "")).strip() not in ("", "None") else 0,
            requires=requires,
        ))

    return Plan(
        version=int(raw["version"]) if str(raw.get("version", "")).strip() not in ("", "None") else 0,
        max_parallel_stands=int(raw["max_parallel_stands"]) if str(raw.get("max_parallel_stands", "")).strip() not in ("", "None") else 0,
        max_total_target_calls=int(raw["max_total_target_calls"]) if str(raw.get("max_total_target_calls", "")).strip() not in ("", "None") else 0,
        stands=tuple(stands),
        jobs=tuple(jobs),
    )


# ------------------------------------------------------------------ валидация
def validate_plan(plan: Plan, *, scenario_exists: Callable[[str], bool] | None = None) -> None:
    """Стоп ДО первого запуска с конкретной причиной (PlanError). Проверяет:
    пустые обязательные поля; неизвестный сценарий/контроль/зависимость;
    целостность id; циклы зависимостей.

    FIX-PACK-2 D5: изоляция по принципалам БОЛЬШЕ НЕ валидируется как ошибка.
    `isolation_group` — маркер ОБЩЕГО РЕСУРСА (одна Mongo → одна группа →
    сериализация планировщиком), а не утверждение о независимости стендов.
    Две независимые копии стенда с ОДНИМИ принципалами легальны и идут
    параллельно; общая группа при непересекающихся принципалах тоже легальна.
    Пересечение принципалов у стендов из РАЗНЫХ групп теперь неблокирующее
    предупреждение сводки (`plan_warnings`), не PlanError. Гейт параллелизма
    (общая группа ≤1 активного) не изменён."""
    exists = scenario_exists if scenario_exists is not None else (lambda s: Path(s).exists())

    # --- пустые обязательные поля / базовая форма
    if plan.version <= 0:
        raise PlanError("пустое обязательное поле: version (положительное целое)")
    if plan.max_parallel_stands < 1:
        raise PlanError("max_parallel_stands должен быть >= 1")
    if plan.max_total_target_calls < 1:
        raise PlanError("max_total_target_calls должен быть >= 1")
    if not plan.stands:
        raise PlanError("пустое обязательное поле: stands (нужен хотя бы один стенд)")
    if not plan.jobs:
        raise PlanError("пустое обязательное поле: jobs (нужно хотя бы одно задание)")

    seen_stand: set[str] = set()
    for s in plan.stands:
        if not s.id:
            raise PlanError("пустое обязательное поле: stands[].id")
        if s.id in seen_stand:
            raise PlanError(f"дублирующийся стенд id={s.id!r}")
        seen_stand.add(s.id)
        if not s.target:
            raise PlanError(f"стенд {s.id!r}: пустой target_profile.target (неизвестный стенд)")
        if not s.principals:
            raise PlanError(f"стенд {s.id!r}: пустой target_profile.principals — область принципалов обязательна для изоляции")
        if not s.isolation_group:
            raise PlanError(f"стенд {s.id!r}: пустое обязательное поле isolation_group")
        if s.slots < 1:
            raise PlanError(f"стенд {s.id!r}: slots должен быть >= 1")

    seen_job: set[str] = set()
    for j in plan.jobs:
        if not j.id:
            raise PlanError("пустое обязательное поле: jobs[].id")
        if j.id in seen_job:
            raise PlanError(f"дублирующийся job id={j.id!r}")
        seen_job.add(j.id)
        if not j.scenario:
            raise PlanError(f"задание {j.id!r}: пустое обязательное поле scenario")
        if j.iterations < 1:
            raise PlanError(f"задание {j.id!r}: iterations должен быть >= 1")
        if not exists(j.scenario):
            raise PlanError(f"задание {j.id!r}: неизвестный сценарий {j.scenario!r} (файл не найден)")
        if j.control is not None and not exists(j.control):
            raise PlanError(f"задание {j.id!r}: неизвестный контрольный сценарий {j.control!r} (файл не найден)")

    # --- зависимости: известны и без циклов
    for j in plan.jobs:
        for dep in j.requires:
            if dep not in seen_job:
                raise PlanError(f"задание {j.id!r}: requires ссылается на неизвестное задание {dep!r}")
            if dep == j.id:
                raise PlanError(f"задание {j.id!r}: requires ссылается само на себя")
    _assert_no_requires_cycle(plan)
    # FIX-PACK-2 D5: изоляция по принципалам больше не блокирует план — см.
    # docstring и plan_warnings (пересечение принципалов у РАЗНЫХ групп —
    # предупреждение сводки, не ошибка).


def _assert_no_requires_cycle(plan: Plan) -> None:
    graph = {j.id: set(j.requires) for j in plan.jobs}
    color: dict[str, int] = {}  # 0=white,1=gray,2=black

    def visit(node: str, trail: list[str]) -> None:
        color[node] = 1
        for dep in graph.get(node, ()):
            if color.get(dep, 0) == 1:
                cyc = " → ".join(trail + [node, dep])
                raise PlanError(f"цикл зависимостей requires: {cyc}")
            if color.get(dep, 0) == 0:
                visit(dep, trail + [node])
        color[node] = 2

    for j in plan.jobs:
        if color.get(j.id, 0) == 0:
            visit(j.id, [])


# ------------------------------------------------------ чтение артефактов
def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def read_experiment_id(run_dir: str | Path) -> str | None:
    return (_read_json(Path(run_dir) / "experiment.json") or {}).get("experiment_id") or None


def read_campaign(run_dir: str | Path) -> dict | None:
    """campaign.json дочернего прогона (или None, если каталог не готов)."""
    return _read_json(Path(run_dir) / "campaign.json")


def asr_from_campaign(campaign: dict | None) -> tuple[int | None, int | None, float | None]:
    """N of M и значение ASR из campaign.json. UNKNOWN → value=None (≠ 0)."""
    if not campaign:
        return None, None, None
    m = campaign.get("aggregate_metrics") or {}
    n = m.get("successful")
    total = m.get("attempts", campaign.get("attempts"))
    value = m.get("end_to_end_asr")  # уже None, если знаменатель 0 (UNKNOWN ≠ 0)
    return (int(n) if isinstance(n, int) else None,
            int(total) if isinstance(total, int) else None,
            float(value) if isinstance(value, (int, float)) else None)


def count_executed_target_calls(run_dir: str | Path | None) -> int | None:
    """ФАКТ вызовов цели из `<run_dir>/budget-ledger.jsonl` (FIX-PACK-2 D1):
    число записей operation=target_call, phase=executed. Одна попытка кампании
    посылает цели несколько вызовов (baseline/delivery/trigger/контроль), поэтому
    знаменатель ASR (число КЕЙСОВ) занижает расход — его нельзя выдавать за факт.

    Возвращает None, когда факт недоступен: леджера нет (исторический прогон),
    файл не читается или строка повреждена. Вызывающий откатывается на грубую
    оценку и помечает её (`estimate=True`) — выдуманного факта не появляется.
    Читается каноническим `ledger.read_ledger`; его LedgerError (битая строка/
    несовместимая schema_version) НЕ роняет сводку пакета — тоже откат к оценке."""
    if not run_dir:
        return None
    path = Path(run_dir) / LEDGER_FILE
    if not path.exists():
        return None
    try:
        entries = read_ledger(path)
    except (LedgerError, OSError):
        return None
    return sum(1 for e in entries
               if e.operation == OP_TARGET_CALL and e.phase == PHASE_EXECUTED)


def resolve_target_calls_actual(
    run_dir: str | Path | None, estimate_calls: int | None
) -> tuple[int | None, bool]:
    """(actual, is_estimate). Факт из леджера, если он есть (D1); иначе грубая
    оценка `estimate_calls` (текущая — знаменатель ASR) с пометкой is_estimate.
    Нет ни факта, ни оценки → (None, False): честный UNKNOWN, не выдумка."""
    counted = count_executed_target_calls(run_dir)
    if counted is not None:
        return counted, False
    return estimate_calls, (estimate_calls is not None)


def classify_outcome(returncode: int | None, campaign: dict | None, stderr: str | None) -> str:
    """Различимая таксономия исхода дочернего прогона. Скрытых повторов нет —
    здесь только МЕТКА, планировщик по ней ничего не перезапускает.

    Живые сигналы (401/429/транспорт) распознаются по тексту ошибки дочернего
    прогона; офлайн (mock) даёт returncode 0 + campaign.json → COMPLETED."""
    text = (stderr or "").lower()
    if returncode == 0 and campaign is not None:
        # прогон дошёл до конца, но финал недописан (нет агрегатов) — честный отдельный исход
        if not campaign.get("aggregate_metrics") and "attempts" not in campaign:
            return OUTCOME_INCOMPLETE_FINALIZE
        return OUTCOME_COMPLETED
    if "401" in text or "unauthorized" in text or "unauthorised" in text:
        return OUTCOME_AUTH_401
    if "429" in text or "rate limit" in text or "too many requests" in text:
        return OUTCOME_RATE_LIMITED_429
    if any(k in text for k in ("timeout", "timed out", "connection", "transport", "network", "reset by peer")):
        return OUTCOME_TRANSPORT
    if returncode == 0 and campaign is None:
        return OUTCOME_INCOMPLETE_FINALIZE
    return OUTCOME_UNKNOWN


def job_cost(job: Job) -> int:
    """Планируемый расход вызовов задания (потолок для проверки бюджета ДО
    выдачи): iterations атаки + iterations контроля, если он есть. Этап 1
    считает «вызов» = одна запланированная попытка (attempt); фактический расход
    сверяется из campaign.json после прогона."""
    return job.iterations + (job.iterations if job.control else 0)


# ------------------------------------------------------------------ планировщик
def _deps_status(job: Job, done: dict[str, JobRun]) -> tuple[bool, str | None]:
    """Готовность зависимостей задания к выдаче (FIX-PACK-2 D2).

    Возвращает (dispatchable, block_detail):
    * dispatchable=True  — КАЖДАЯ requires-зависимость разрешилась с исходом
      COMPLETED; задание можно выдавать;
    * (False, detail)    — хотя бы одна зависимость разрешилась НЕ в completed
      (transport_error/unknown/blocked/…): задание блокируется НАВСЕГДА, detail
      называет первую такую зависимость и её исход;
    * (False, None)      — зависимость ещё не разрешилась (в очереди/выполняется):
      не блокируем, ждём.

    Прежний код разблокировал зависимое ЛЮБЫМ присутствием зависимости в `done`
    (`dep in done`) — цепочка «разведка → атака» запускала атаку даже после
    провала разведки. Теперь разблокирует только успешное завершение."""
    block_detail: str | None = None
    all_present = True
    for dep in job.requires:
        r = done.get(dep)
        if r is None:
            all_present = False
            continue
        if r.outcome != OUTCOME_COMPLETED and block_detail is None:
            block_detail = f"зависимость {dep} {r.outcome}"
    if block_detail is not None:
        return False, block_detail
    return all_present, None


async def run_plan(
    plan: Plan,
    output: str | Path,
    *,
    runner: JobRunner,
    clean_checker: CleanChecker,
    results: dict[str, JobRun] | None = None,
) -> dict[str, JobRun]:
    """Прогоняет пакет: очередь заданий по совместимым свободным стендам.
    Инварианты: 1 активное задание на стенд; общая isolation_group блокирует
    параллелизм (≤1 активное на группу); ≤ max_parallel_stands активных стендов;
    committed вызовов ≤ max_total_target_calls (потолок не превышается); каждый
    job_id выдаётся ровно один раз; re-check чистоты стенда перед КАЖДОЙ выдачей
    (грязный/UNKNOWN — не выдаём). Возвращает job_id → JobRun (терминальные
    исходы для не выданных заданий тоже присутствуют).

    FIX-PACK-2 D2: зависимость разблокирует зависимое только исходом COMPLETED
    (см. `_deps_status`), иначе зависимое получает BLOCKED. FIX-PACK-2 D3: если
    передан `results`, планировщик наполняет ИМЕННО его (тот же объект и
    возвращается) — вызывающий видит частичный прогресс даже при исключении
    воркера и дописывает сводку в finally."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    pending: list[Job] = list(plan.jobs)
    done: dict[str, JobRun] = results if results is not None else {}
    committed = 0
    active: dict[asyncio.Task, tuple[Job, Stand]] = {}
    per_stand: dict[str, int] = {}
    per_group: dict[str, int] = {}

    def deps_done(job: Job) -> bool:
        return _deps_status(job, done)[0]

    def stand_free(stand: Stand) -> bool:
        if per_stand.get(stand.id, 0) >= 1:              # 1 активное задание на стенд (Этап 1)
            return False
        if per_group.get(stand.isolation_group, 0) >= 1:  # общая группа блокирует параллелизм
            return False
        return len(active) < plan.max_parallel_stands       # потолок параллельных стендов

    while pending or active:
        made_dispatch = False
        marked_terminal = False
        # DISPATCH-фаза: заполнить ВСЕ свободные стенды совместимой работой
        # (параллелизм), обновляя занятость по мере выдачи.
        for stand in plan.stands:
            if not stand_free(stand):
                continue
            # первая по очереди работа с готовыми зависимостями и влезающая в бюджет;
            # ready-но-неподъёмные по бюджету сливаются в budget_exhausted и пропускаются
            chosen: Job | None = None
            for job in list(pending):
                if not deps_done(job):
                    continue
                if committed + job_cost(job) > plan.max_total_target_calls:
                    pending.remove(job)
                    done[job.id] = JobRun(
                        job_id=job.id, stand_id=None, outcome=OUTCOME_BUDGET_EXHAUSTED,
                        detail=f"committed {committed} + cost {job_cost(job)} > cap {plan.max_total_target_calls}",
                    )
                    marked_terminal = True
                    continue
                chosen = job
                break
            if chosen is None:
                continue
            # re-check чистоты стенда перед выдачей (грязный/UNKNOWN — не выдаём сюда)
            if clean_checker(stand).status != "clean":
                continue
            committed += job_cost(chosen)
            pending.remove(chosen)
            per_stand[stand.id] = per_stand.get(stand.id, 0) + 1
            per_group[stand.isolation_group] = per_group.get(stand.isolation_group, 0) + 1
            active[asyncio.ensure_future(runner(chosen, stand, output))] = (chosen, stand)
            made_dispatch = True

        if active:
            finished, _ = await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                job, stand = active.pop(task)
                run = task.result()
                run.target_calls_committed = job_cost(job)
                done[job.id] = run
                per_stand[stand.id] -= 1
                per_group[stand.isolation_group] -= 1
            continue
        if not made_dispatch and not marked_terminal:
            # ничего не запущено и не выдано: прогресс невозможен — слить остаток
            _drain_blocked(pending, done, clean_checker, plan)
            break

    return done


def _drain_blocked(pending: list[Job], done: dict[str, JobRun], clean_checker: CleanChecker, plan: Plan) -> None:
    """Оставшиеся невыдаваемые задания получают честный терминальный исход:
    неготовые зависимости → BLOCKED; иначе стенды нечистые → dirty/unknown."""
    # худшая чистота среди стендов (одна проверка на слив — прогресс уже невозможен)
    statuses = [clean_checker(s).status for s in plan.stands]
    if any(st == "dirty" for st in statuses):
        stand_outcome = OUTCOME_STAND_DIRTY
    elif all(st == "unknown" for st in statuses):
        stand_outcome = OUTCOME_STAND_CLEAN_UNKNOWN
    else:
        stand_outcome = OUTCOME_BLOCKED
    for job in list(pending):
        dispatchable, dep_detail = _deps_status(job, done)
        if not dispatchable:
            # D2: зависимость завершилась не-completed → называем её и исход;
            # зависимость ещё висит (тоже сливается) → общая формулировка.
            outcome = OUTCOME_BLOCKED
            detail = dep_detail or "неудовлетворимые зависимости requires"
        else:
            outcome = stand_outcome
            detail = "нет чистого стенда (clean_check не прошёл ни на одном стенде)"
        done[job.id] = JobRun(job_id=job.id, stand_id=None, outcome=outcome, detail=detail)
        pending.remove(job)


# ------------------------------------------------------------------ сводка
def _ascii_slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


def plan_warnings(plan: Plan) -> list[str]:
    """Неблокирующие предупреждения плана для сводки (FIX-PACK-2 D5).

    `isolation_group` — маркер ОБЩЕГО РЕСУРСА (одна Mongo → одна группа →
    сериализация), а не ошибка. Стенды из РАЗНЫХ групп с пересекающимися
    принципалами теперь ЛЕГАЛЬНЫ (две независимые копии стенда идут
    параллельно), но помечаются предупреждением: параллельные прогоны с одними
    принципалами двусмысленны для атрибуции. План при этом валиден — стоп ДО
    запуска (validate_plan) по этому поводу больше не срабатывает."""
    warnings: list[str] = []
    for a, b in combinations(plan.stands, 2):
        overlap = set(a.principals) & set(b.principals)
        if a.isolation_group != b.isolation_group and overlap:
            warnings.append(
                f"стенды {a.id!r} и {b.id!r} в разных isolation_group "
                f"({a.isolation_group!r} vs {b.isolation_group!r}) делят принципалов "
                f"({sorted(overlap)}): параллельный прогон легален, но атрибуция по "
                "принципалу неоднозначна"
            )
    return warnings


def build_summary(plan: Plan, output: str | Path, runs: dict[str, JobRun]) -> dict[str, Any]:
    """Сводка пакета: batch_id, дочерние experiment_id, статусы, ASR как N of M,
    расходы, ссылки на артефакты. UNKNOWN ≠ False (asr_value=None, не 0);
    секретов нет (только id/пути/числа)."""
    output = Path(output)
    batch_id = _ascii_slug(output.name) or "batch"
    by_outcome: dict[str, int] = {}
    committed_total = 0
    actual_total = 0
    any_estimate = False
    jobs_out = []
    for job in plan.jobs:
        r = runs.get(job.id)
        if r is None:
            r = JobRun(job_id=job.id, stand_id=None, outcome=OUTCOME_BLOCKED, detail="не запланировано")
        by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
        committed_total += r.target_calls_committed
        if isinstance(r.target_calls_actual, int):
            actual_total += r.target_calls_actual
        any_estimate = any_estimate or r.target_calls_estimate
        jobs_out.append({
            "job_id": r.job_id,
            "scenario": job.scenario,
            "control": job.control,
            "iterations": job.iterations,
            "stand": r.stand_id,
            "stand_principals": list(r.stand_principals) if r.stand_principals is not None else None,
            "outcome": r.outcome,
            "dispatched": r.outcome not in NOT_DISPATCHED,
            "experiment_id": r.experiment_id,
            "asr": {"n": r.asr_n, "m": r.asr_m, "value": r.asr_value},  # value=None → UNKNOWN, не 0
            "control_outcome": r.control_outcome,
            # actual — ФАКТ вызовов цели из леджера (D1); estimate=True → леджера
            # не было, actual — грубая оценка (знаменатель ASR), не факт.
            "target_calls": {"committed": r.target_calls_committed, "actual": r.target_calls_actual,
                             "estimate": r.target_calls_estimate},
            "artifacts": {"run_dir": r.run_dir, "control_run_dir": r.control_run_dir},
            "detail": r.detail,
        })
    return {
        "schema_version": BATCH_SUMMARY_SCHEMA_VERSION,
        "batch_id": batch_id,
        "plan_version": plan.version,
        "caps": {
            "max_parallel_stands": plan.max_parallel_stands,
            "max_total_target_calls": plan.max_total_target_calls,
            "committed_target_calls": committed_total,
            "actual_target_calls": actual_total,
            # D1: любой job без леджера сделал actual грубой оценкой — честный флаг
            "actual_target_calls_estimate": any_estimate,
        },
        # D5: неблокирующие предупреждения плана (пересечение принципалов у разных групп)
        "warnings": plan_warnings(plan),
        "stands": [
            {"id": s.id, "isolation_group": s.isolation_group, "principals": list(s.principals),
             "slots": s.slots, "clean_check_declared": s.clean_check is not None}
            for s in plan.stands
        ],
        "jobs": jobs_out,
        "totals": {"jobs": len(plan.jobs), "by_outcome": by_outcome},
    }


def _state_from_runs(runs: dict[str, JobRun]) -> dict[str, Any]:
    """Минимальное состояние для пересборки сводки без перезапуска заданий."""
    return {job_id: {
        "stand_id": r.stand_id, "outcome": r.outcome, "run_dir": r.run_dir,
        "control_scenario": r.control_scenario, "control_outcome": r.control_outcome,
        "control_run_dir": r.control_run_dir, "target_calls_committed": r.target_calls_committed,
        "stand_principals": list(r.stand_principals) if r.stand_principals is not None else None,
        "detail": r.detail,
    } for job_id, r in runs.items()}


def write_batch(plan: Plan, output: str | Path, runs: dict[str, JobRun]) -> tuple[Path, Path]:
    """Пишет summary.json и batch-state.json (состояние для пересборки).
    Возвращает (путь сводки, путь состояния)."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    summary = build_summary(plan, output, runs)
    summary_path = output / "summary.json"
    state_path = output / "batch-state.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    state_path.write_text(json.dumps(_state_from_runs(runs), ensure_ascii=False, indent=2), encoding="utf-8")
    return summary_path, state_path


def rebuild_summary(plan: Plan, output: str | Path) -> Path:
    """Пересобирает summary.json из batch-state.json и артефактов дочерних
    прогонов, НЕ перезапуская задания. ASR/experiment_id перечитываются из
    campaign.json/experiment.json (если каталоги на месте).

    FIX-PACK-2 D1+D4: target_calls_actual — ФАКТ из budget-ledger.jsonl
    (executed target_call), не знаменатель ASR; при наличии control_run_dir
    расход контроля добавляется СИММЕТРИЧНО живому пути (прежде терялся).
    Леджера нет → грубая оценка с пометкой estimate."""
    output = Path(output)
    state = _read_json(output / "batch-state.json") or {}
    runs: dict[str, JobRun] = {}
    for job_id, st in state.items():
        run_dir = st.get("run_dir")
        control_run_dir = st.get("control_run_dir")
        campaign = read_campaign(run_dir) if run_dir else None
        n, m, value = asr_from_campaign(campaign)
        # D1: факт вызовов цели из леджера прогона (или оценка m с пометкой).
        actual, estimate = resolve_target_calls_actual(run_dir, m)
        # D4: расход контроля добавляется так же, как на живом пути.
        if control_run_dir:
            _cn, cm, _cv = asr_from_campaign(read_campaign(control_run_dir))
            c_actual, c_est = resolve_target_calls_actual(control_run_dir, cm)
            if isinstance(c_actual, int):
                actual = c_actual if not isinstance(actual, int) else actual + c_actual
            estimate = bool(estimate or c_est)
        sp = st.get("stand_principals")
        runs[job_id] = JobRun(
            job_id=job_id, stand_id=st.get("stand_id"), outcome=st.get("outcome", OUTCOME_UNKNOWN),
            experiment_id=read_experiment_id(run_dir) if run_dir else None,
            asr_n=n, asr_m=m, asr_value=value,
            target_calls_committed=int(st.get("target_calls_committed") or 0),
            target_calls_actual=actual, target_calls_estimate=estimate,
            run_dir=run_dir, control_scenario=st.get("control_scenario"),
            control_outcome=st.get("control_outcome"), control_run_dir=control_run_dir,
            stand_principals=tuple(sp) if isinstance(sp, list) else None,
            detail=st.get("detail"),
        )
    summary = build_summary(plan, output, runs)
    summary_path = output / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary_path
