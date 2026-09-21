"""src/memnotsafe/core/worker.py — оркестратор N воркеров + lease/fencing
(P13-a, G3-SPEC §3; offline-карточка — фундамент live G3.1/G3.2 в P13-d).

Слои:

* `FileLease` — файловый замок на эксклюзивные операции (окно reset): создание
  `O_EXCL`, TTL, монотонный fencing-токен. Mongo сознательно НЕ используется
  (G3-SPEC: lease не зависит от наблюдаемости — у адаптера Mongo-доступ
  опционален). Каталог замков живёт внутри run-каталога оркестратора и
  пробрасывается воркерам env-ом `MEMNOTSAFE_LEASE_DIR` — сам слой P13-a
  замок НЕ берёт: эксклюзивные операции исполняют воркеры/живые карточки.
  Политика второго `acquire` при живом замке — НЕМЕДЛЕННЫЙ ОТКАЗ (None):
  ожидание — решение живой карточки, не этого слоя. Замок с истёкшим TTL
  эксклюзивности не держит: новый `acquire` снимает orphan-замок (упавший
  воркер) и занимает место с НОВЫМ монотонным токеном; прежний держатель
  отвергается по токену — его `release(старый_токен)` вернёт False и ничего
  не снимет. Токен нового держателя всегда строго больше заменённого
  (max(счётчик, токены живых замков) + 1) — fencing при перекладывании
  безусловен; сквозная строгая монотонность между ОДНОВРЕМЕННЫМИ acquire
  разных процессов не заявляется (счётчик обновляется best-effort,
  эксклюзивность держит сам O_EXCL) — offline-контракт P13-a.
  `clock` инжектируемый (норма VERDICT-P12, паттерн P11-1): lease-время
  монотонное, дефолт `time.monotonic`; TTL в тестах замораживается скриптом.

* `orchestrate` — запуск N воркеров подпроцессами (asyncio) и сбор их
  исходов: упавший/убитый воркер НЕ блокирует сбор остальных (wait каждого
  процесса независим). Каждому воркеру — свой env-скоуп:
  `MEMNOTSAFE_WORKER_INDEX` (номер, с 1) и `MEMNOTSAFE_LEASE_DIR` (каталог
  замков оркестратора).

* `orchestrate_campaign` — прикладной уровень: N воркеров = N подпроцессов
  CLI-кампании (`python -m memnotsafe.cli campaign`), один и тот же сценарий,
  каждому свой run-каталог `<output>-w<i>`, оркестратору — `<output>/locks`
  и сводка `<output>-orchestrator.json`. rc оркестратора: 0, если все
  воркеры завершились с 0, иначе 1 (новых exit-кодов нет).

Общий `experiment_id` НЕ пробрасывается флагом или env — минимальный выбор
карточки: experiment_id есть детерминированный digest `ExperimentSpec`
(P10b), НЕ включающий run-каталог/run_id/created_at, поэтому оркестратор
обязан давать всем воркерам ОДИНАКОВЫЕ аргументы кампании (отличается только
`--output`) — тогда `experiment.json` каждого воркера несёт один и тот же
id. Общность проверяется после прогона (сводка + тест), а не доверяется.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

ORCHESTRATOR_SUMMARY_SCHEMA_VERSION = 1
WORKER_INDEX_ENV = "MEMNOTSAFE_WORKER_INDEX"
LEASE_DIR_ENV = "MEMNOTSAFE_LEASE_DIR"


# ---------------------------------------------------------------------- lease


@dataclass(frozen=True)
class Lease:
    """Приобретённый замок: имя, fencing-токен и абсолютный deadline
    (в единицах clock оркестратора/теста)."""

    name: str
    fencing_token: int
    expires_at: float
    path: Path


class FileLease:
    """Файловый lease с TTL и fencing-токенами в одном каталоге.

    Токены глобальны для каталога: каждый успешный acquire получает
    max(счётчик каталога, токены всех живых замков) + 1 — перекладывание
    истёкшего замка даёт токен строго больше заменённого (ядро fencing),
    последовательные приобретения строго возрастают."""

    def __init__(self, directory: str | Path, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._clock = clock

    def _counter_path(self) -> Path:
        return self.directory / "fencing.counter"

    def _lock_path(self, name: str) -> Path:
        return self.directory / f"{name}.lock"

    def _max_token_seen(self) -> int:
        highest = 0
        counter = self._counter_path()
        if counter.exists():
            try:
                highest = max(highest, int(counter.read_text(encoding="utf-8").strip() or "0"))
            except ValueError:
                pass  # повреждённый счётчик не ломает монотонность: замки ниже
        for lock in self.directory.glob("*.lock"):
            data = _read_json(lock)
            if data is not None:
                highest = max(highest, int(data.get("fencing_token", 0)))
        return highest

    def acquire(self, name: str, ttl: float) -> Lease | None:
        """Взять замок `name` на `ttl` секунд. Живой замок — немедленный None
        (политика отказа, докстринг модуля); истёкший/orphan — снят и
        переложен с новым монотонным токеном."""
        now = self._clock()
        lock_path = self._lock_path(name)
        if lock_path.exists():
            data = _read_json(lock_path)
            if data is not None and now < float(data["expires_at"]):
                return None
            lock_path.unlink()  # TTL истёк: эксклюзивности нет, перекладываем
        token = self._max_token_seen() + 1
        expires_at = now + ttl
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return None  # проиграли гонку создания — чужой живой замок
        try:
            os.write(fd, json.dumps(
                {"name": name, "fencing_token": token, "acquired_at": now, "expires_at": expires_at}
            ).encode("utf-8"))
        finally:
            os.close(fd)
        self._counter_path().write_text(str(token), encoding="utf-8")
        return Lease(name=name, fencing_token=token, expires_at=expires_at, path=lock_path)

    def release(self, token: int) -> bool:
        """Освободить замок по fencing-токену держателя. Устаревший токен
        (замок переложен/снят) — False без побочных эффектов."""
        for lock in self.directory.glob("*.lock"):
            data = _read_json(lock)
            if data is not None and int(data.get("fencing_token", -1)) == token:
                lock.unlink()
                return True
        return False


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------- orchestrate


@dataclass(frozen=True)
class WorkerOutcome:
    """Исход одного воркера: argv, ожидаемый run-каталог и rc процесса
    (отрицательный — убит сигналом; None не встречается: wait всегда даёт rc)."""

    index: int
    argv: list[str]
    run_dir: Path
    returncode: int


async def orchestrate(
    worker_argv: Sequence[Sequence[str]],
    *,
    run_dirs: Sequence[str | Path],
    orchestrator_dir: str | Path,
    extra_env: dict[str, str] | None = None,
) -> list[WorkerOutcome]:
    """Запустить N воркеров подпроцессами и собрать исходы ВСЕХ независимо:
    упавший/убитый воркер не блокирует сбор остальных (каждый wait свой).

    Воркерам даётся env-скоуп поверх текущего окружения:
    `MEMNOTSAFE_WORKER_INDEX` (1..N) и `MEMNOTSAFE_LEASE_DIR` (каталог замков
    оркестратора `<orchestrator_dir>/locks`; создаётся здесь). Замок сам этот
    слой не берёт — эксклюзивные операции за воркерами/live-карточками.
    `extra_env` — прикладные переменные поверх скоупа (например PYTHONPATH,
    чтобы дочерний CLI видел пакет при запуске из дерева исходников)."""
    orchestrator_dir = Path(orchestrator_dir)
    locks_dir = orchestrator_dir / "locks"
    locks_dir.mkdir(parents=True, exist_ok=True)

    async def _spawn_and_wait(index: int, argv: Sequence[str]) -> WorkerOutcome:
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        env[WORKER_INDEX_ENV] = str(index)
        env[LEASE_DIR_ENV] = str(locks_dir)
        proc = await asyncio.create_subprocess_exec(*argv, env=env)
        rc = await proc.wait()
        return WorkerOutcome(index=index, argv=list(argv),
                             run_dir=Path(run_dirs[index - 1]), returncode=rc)

    return list(await asyncio.gather(*(
        _spawn_and_wait(i, argv) for i, argv in enumerate(worker_argv, start=1)
    )))


def orchestrator_rc(outcomes: Sequence[WorkerOutcome]) -> int:
    """0, только если ВСЕ воркеры завершились с 0; иначе 1. Новых кодов нет."""
    return 0 if outcomes and all(o.returncode == 0 for o in outcomes) else 1


def write_orchestrator_summary(
    summary_path: str | Path,
    outcomes: Sequence[WorkerOutcome],
    *,
    lease_dir: str | Path,
) -> Path:
    """Сводка оркестратора `<output>-orchestrator.json`: состав воркеров,
    argv, run-каталоги, rc каждого, каталог замков и ОБЩНОСТЬ experiment_id
    (проверена чтением experiment.json готовых run-каталогов; у незавершившихся
    воркеров файла нет — честное null, не выдуманный id)."""
    experiment_ids = [
        (_read_json(Path(o.run_dir) / "experiment.json") or {}).get("experiment_id")
        for o in outcomes
    ]
    known = [e for e in experiment_ids if e]
    common = len(known) == len(experiment_ids) and len(set(known)) <= 1 and bool(known)
    payload = {
        "schema_version": ORCHESTRATOR_SUMMARY_SCHEMA_VERSION,
        "workers": [
            {"index": o.index, "argv": o.argv, "run_dir": str(o.run_dir),
             "returncode": o.returncode, "experiment_id": experiment_ids[i]}
            for i, o in enumerate(outcomes)
        ],
        "experiment_id_common": common,
        "lease_dir": str(lease_dir),
    }
    path = Path(summary_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


async def orchestrate_campaign(
    scenario: str | Path,
    *,
    output: str | Path,
    workers: int = 2,
    iterations: int | None = None,
) -> tuple[list[WorkerOutcome], Path]:
    """N воркеров = N подпроцессов CLI-кампании: один сценарий, одинаковые
    аргументы (кроме --output), run-каталоги `<output>-w<i>`, замки и сводка —
    у оркестратора (`<output>/locks`, `<output>-orchestrator.json`).
    Возвращает (исходы, путь сводки)."""
    if workers < 1:
        raise ValueError(f"workers должен быть >= 1, получил {workers}")
    output = Path(output)
    base_argv = [sys.executable, "-m", "memnotsafe.cli", "campaign",
                 "--scenario", str(scenario)]
    if iterations is not None:
        base_argv += ["--iterations", str(iterations)]
    # Дочерний CLI обязан видеть пакет даже когда pytest запущен без
    # PYTHONPATH (sys.path-вставки тестов в подпроцесс не попадают):
    # подставляем src корня исходного дерева, если живём в нём.
    src_root = Path(__file__).resolve().parents[2]
    extra_env: dict[str, str] | None = None
    if (src_root / "memnotsafe").is_dir():
        existing = os.environ.get("PYTHONPATH", "")
        extra_env = {"PYTHONPATH": str(src_root) + (os.pathsep + existing if existing else "")}
    worker_argv: list[list[str]] = []
    run_dirs: list[Path] = []
    for i in range(1, workers + 1):
        worker_output = Path(f"{output}-w{i}")
        worker_argv.append(base_argv + ["--output", str(worker_output)])
        run_dirs.append(worker_output)
    outcomes = await orchestrate(worker_argv, run_dirs=run_dirs, orchestrator_dir=output,
                                 extra_env=extra_env)
    summary = write_orchestrator_summary(
        Path(f"{output}-orchestrator.json"), outcomes, lease_dir=output / "locks"
    )
    return outcomes, summary
