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
  ожидание освобождения замка — решение живой карточки, не этого слоя (слой
  ждёт только мьютекс каталога на время чужой секции, см. (б) ниже). Замок с истёкшим TTL
  эксклюзивности не держит: новый `acquire` снимает orphan-замок (упавший
  воркер) и занимает место с НОВЫМ монотонным токеном; прежний держатель
  отвергается по токену — его `release(старый_токен)` вернёт False и ничего
  не снимет. Fencing при перекладывании безусловен (P13-a-r2, краш-окно
  закрыто): максимум токенов считается ДО снятия перекладываемого замка —
  его токен читается из самого файла замка, поэтому потеря/повреждение
  `fencing.counter` монотонность takeover'а не ломают; счётчик инкрементится
  ДО создания замка и атомарно (временный файл + `os.replace`) — краш между
  счётчиком и замком оставляет счётчик уже продвинутым, равных токенов у
  перекладываний одного имени не возникает, устаревший release (точное
  совпадение токена) не может снять чужой замок.
  Межпроцессная сериализация (P13-a-r3): критические секции `acquire`
  (проверка живости → вычисление токена → запись счётчика → снятие истёкшего
  → O_EXCL-создание → запись содержимого) и `release` (поиск по токену →
  unlink) исполняются под ОДНИМ мьютексом каталога замков — OS-level lock на
  дескрипторе инертного файла `fencing.mutex` (Windows: `msvcrt.locking`
  байта 0 — замок обязательный, посторонний читатель байта 0 на время секции
  получает EACCES, читать там нечего; POSIX: `fcntl.flock`; вилка —
  `_mutex_lock`/`_mutex_unlock`). Нормальный выход и исключение внутри секции
  снимают мьютекс явно (`finally`); краш и kill держателя — сама ОС при
  закрытии дескриптора, без TTL и без чистки (на Windows освобождение после
  смерти процесса не мгновенно — порядка миллисекунд, ожидающие переживают
  это повтором). Файл не несёт состояния, участники протокола его не удаляют
  и не заменяют (`os.replace` поверх залоченного файла на Windows невозможен
  — потому не `fencing.counter`), под `*.lock` он не подпадает; появиться он
  может и от `release` с устаревшим токеном — на замки и счётчик это не
  влияет. Закрыто построением для участников протокола:
  (1) takeover одного имени двумя процессами — повторная проверка только
  `exists()` снимала ЖИВОЙ замок соперника, оба считали себя держателями;
  (2) полузаписанный замок — пустой файл между O_EXCL и записью читался как
  «не живой» (Windows: PermissionError на unlink открытого файла, POSIX:
  молчаливое затирание); (3) release по устаревшему чтению снимал
  переложенный замок с ДРУГИМ токеном; (4) окно r2 «равные токены РАЗНЫХ
  имён» — счётчик читается и пишется только под мьютексом; попутно
  `os.replace` счётчика и unlink замка больше не встречают открытое чтение
  другого участника (Windows). Остаётся (по имени): (а) держатель,
  переживший свой TTL, теряет эксклюзивность по контракту lease — ресурс
  обязан проверять fencing-токен, мьютекс этого не меняет; (б) мьютекс
  блокирующий и без таймаута — секция это несколько файловых операций плюс
  один вызов инжектируемого `clock`; медленный или зависший (не мёртвый)
  держатель, включая медленный `clock`, задерживает соседей на время
  задержки — в том числе acquire ДРУГИХ имён и отказ по живому замку;
  (в) участники вне протокола не сериализуются: ручное удаление/правка
  файлов каталога; чужие открытые дескрипторы `.lock`/счётчика (Windows:
  unlink/`os.replace` тогда бросают PermissionError наружу — в том числе
  дескриптор только что убитого участника, доживающий миллисекунды после
  смерти процесса); процессы на коде ДО r3 в том же каталоге (заново
  открывают все три окна — каталог замков делят только процессы r3+);
  удаление/замена `fencing.mutex` посторонним (POSIX: новые участники
  получают другой inode, мьютекс раздваивается; Windows отказывает sharing
  violation); удаление самого каталога под живым объектом (release —
  FileNotFoundError, а не False; acquire падал так и раньше); разные
  каталоги замков друг с другом не сериализуются; (г) локальная ФС одного
  хоста — байтовые/flock-замки на сетевых ФС и сравнимость `time.monotonic`
  между хостами не гарантированы. Ожидание мьютекса — не источник
  lease-времени: `now` читается инжектируемым `clock` уже под мьютексом.
  `clock` инжектируемый (норма VERDICT-P12, паттерн P11-1): lease-время
  монотонное, дефолт `time.monotonic`; TTL в тестах замораживается скриптом.

* `orchestrate` — запуск N воркеров подпроцессами (asyncio) и сбор их
  исходов: упавший/убитый воркер НЕ блокирует сбор остальных (wait каждого
  процесса независим), НЕ СТАРТОВАВШИЙ (ошибка спауна) даёт честный исход
  с returncode=None и причиной в поле error — исходы соседей не теряются
  (P13-a-r2). Каждому воркеру — свой env-скоуп:
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
import errno
import json
import os
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

ORCHESTRATOR_SUMMARY_SCHEMA_VERSION = 1
WORKER_INDEX_ENV = "MEMNOTSAFE_WORKER_INDEX"
LEASE_DIR_ENV = "MEMNOTSAFE_LEASE_DIR"
# FIX-PACK-2 D6: привязка дочернего прогона к стенду (record-only, для
# атрибуции). Дочерний CLI эти переменные ИГНОРИРУЕТ — принципалы берутся из
# профиля плана, а не из env; поле нужно, чтобы сводка знала, на каком стенде
# (с какими принципалами) выполнилось задание.
BATCH_STAND_ID_ENV = "MEMNOTSAFE_BATCH_STAND_ID"
BATCH_PRINCIPALS_ENV = "MEMNOTSAFE_BATCH_PRINCIPALS"


def batch_child_env(base_env: dict[str, str], stand) -> dict[str, str]:
    """env дочернего прогона со стенд-атрибуцией (FIX-PACK-2 D6, record-only):
    КОПИЯ base_env + MEMNOTSAFE_BATCH_STAND_ID / MEMNOTSAFE_BATCH_PRINCIPALS
    (принципалы через запятую). Дочерний CLI эти переменные НЕ читает —
    принципалы берутся из профиля плана; поле нужно, чтобы фиксировать, на каком
    стенде выполнилось задание. base_env не мутируется."""
    env = dict(base_env)
    env[BATCH_STAND_ID_ENV] = stand.id
    env[BATCH_PRINCIPALS_ENV] = ",".join(stand.principals)
    return env

# P13-a-r3: платформенная вилка мьютекса каталога замков (тесты — Windows-хост,
# live — Linux-контейнеры). Оба примитива — stdlib; замок держится на
# дескрипторе и снимается ОС при его закрытии, в том числе при смерти процесса.
if sys.platform == "win32":
    import msvcrt

    def _mutex_lock(fd: int) -> None:
        """Заблокировать байт 0 дескриптора, дожидаясь освобождения. `LK_NBLCK`
        в цикле с короткой паузой вместо `LK_LOCK`: у последнего шаг повтора
        1 с и потолок 10 попыток — секундная латентность и ложный OSError под
        очередью. Это опрос без очереди ожидания (в отличие от `flock` на
        live-Linux): под плотной конкуренцией держатель, входящий повторно,
        может обгонять спящих — справедливости нет, потолок паузы 5 мс держит
        хвост ожидания малым. Пауза — ожидание, не источник lease-времени."""
        delay = 0.001
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError as exc:
                if exc.errno != errno.EACCES:  # занятый байт под LK_NBLCK — только EACCES
                    raise
            time.sleep(delay)
            delay = min(delay * 2, 0.005)

    def _mutex_unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _mutex_lock(fd: int) -> None:
        """Эксклюзивный flock, блокирующий; снимается ОС при закрытии
        дескриптора и смерти процесса."""
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _mutex_unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


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
    max(счётчик каталога, токены всех замков, включая перекладываемый) + 1 —
    перекладывание истёкшего замка даёт токен строго больше заменённого
    (ядро fencing), последовательные приобретения строго возрастают. Порядок
    (P13-a-r2): максимум → атомарная запись счётчика (temp + os.replace) →
    снятие истёкшего замка → O_EXCL-создание нового. Краш в ЛЮБОЙ точке
    между ними оставляет счётчик уже продвинутым или замок-предшественник
    на месте — равных токенов у перекладываний не возникает. Все чтения и
    записи каталога (счётчик, замки) — только под мьютексом `_serialized`
    (P13-a-r3): решение «живой/истёкший», токен и файловые операции acquire
    и release не перемежаются с чужими."""

    def __init__(self, directory: str | Path, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._clock = clock

    def _counter_path(self) -> Path:
        return self.directory / "fencing.counter"

    def _lock_path(self, name: str) -> Path:
        return self.directory / f"{name}.lock"

    def _mutex_path(self) -> Path:
        return self.directory / "fencing.mutex"

    @contextmanager
    def _serialized(self) -> Iterator[None]:
        """Критическая секция каталога (P13-a-r3): дескриптор `fencing.mutex`
        открывается на секцию, OS-lock берётся блокирующе и снимается в
        finally вместе с закрытием дескриптора — исключение внутри секции,
        краш и kill держателя мьютекс не удерживают. Реентерабельности нет
        и не нужно: секции не вкладываются."""
        fd = os.open(self._mutex_path(), os.O_RDWR | os.O_CREAT)
        try:
            _mutex_lock(fd)
            try:
                yield
            finally:
                _mutex_unlock(fd)
        finally:
            os.close(fd)

    def _write_counter_atomic(self, token: int) -> None:
        """Атомарный апдейт счётчика: временный файл в ТОМ ЖЕ каталоге +
        os.replace (P13-a-r2). Вызывается ДО создания замка — краш-окно
        «замок записан, счётчик нет» закрыто построением."""
        tmp = self.directory / f"fencing.counter.{os.getpid()}.{token}.tmp"
        tmp.write_text(str(token), encoding="utf-8")
        os.replace(tmp, self._counter_path())

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
        """Взять замок `name` на `ttl` секунд. Живой замок — None без ожидания
        его освобождения (политика отказа, докстринг модуля; ждём только
        мьютекс каталога); истёкший/orphan — снят и
        переложен с новым монотонным токеном. Максимум токенов вычисляется
        ДО снятия старого замка, счётчик атомарно продвигается ДО создания
        нового (см. FileLease): потеря/повреждение счётчика монотонность
        takeover'а не ломают, устаревший release чужой замок не снимет.
        P13-a-r3: вся последовательность — одна критическая секция под
        мьютексом каталога; `now` читается уже под мьютексом (ожидание
        мьютекса не укорачивает TTL и не служит вторым источником времени)."""
        lock_path = self._lock_path(name)
        with self._serialized():
            now = self._clock()
            if lock_path.exists():
                data = _read_json(lock_path)
                if data is not None and now < float(data["expires_at"]):
                    return None
            # P13-a-r2: максимум ДО unlink — токен перекладываемого замка читается
            # из его файла; без этого потеря счётчика давала равные токены.
            token = self._max_token_seen() + 1
            # P13-a-r2: счётчик ДО замка и атомарно — краш между ними оставляет
            # счётчик продвинутым (следующий acquire стартует выше).
            self._write_counter_atomic(token)
            if lock_path.exists():
                # TTL истёк или файл полузаписан крашем создателя: эксклюзивности
                # нет, перекладываем; под мьютексом файл не открыт ни одним
                # участником протокола (чужие дескрипторы — окно (в)).
                lock_path.unlink()
            expires_at = now + ttl
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                # Под мьютексом для участников протокола недостижимо; страховка
                # от файла, положенного мимо протокола, — честный отказ.
                return None
            try:
                os.write(fd, json.dumps(
                    {"name": name, "fencing_token": token, "acquired_at": now, "expires_at": expires_at}
                ).encode("utf-8"))
            finally:
                os.close(fd)
            return Lease(name=name, fencing_token=token, expires_at=expires_at, path=lock_path)

    def release(self, token: int) -> bool:
        """Освободить замок по fencing-токену держателя. Устаревший токен
        (замок переложен/снят) — False без побочных эффектов на замки и
        счётчик (инертный `fencing.mutex` при этом может появиться). P13-a-r3:
        поиск и снятие — одна секция под мьютексом каталога: замок,
        переложенный между чтением и unlink с другим токеном, снят быть
        не может."""
        with self._serialized():
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
    """Исход одного воркера: argv, ожидаемый run-каталог, rc процесса
    (отрицательный — убит сигналом) и маркер ошибки спауна. returncode=None —
    воркер НЕ СТАРТОВАЛ (бинарь не найден и т.п.): поле `error` называет
    причину (P13-a-r2); исход не теряется и попадает в сводку с честным null
    вместо rc (новых exit-кодов CLI не вводится — rc оркестратора остаётся 1)."""

    index: int
    argv: list[str]
    run_dir: Path
    returncode: int | None
    error: str | None = None


async def orchestrate(
    worker_argv: Sequence[Sequence[str]],
    *,
    run_dirs: Sequence[str | Path],
    orchestrator_dir: str | Path,
    extra_env: dict[str, str] | None = None,
) -> list[WorkerOutcome]:
    """Запустить N воркеров подпроцессами и собрать исходы ВСЕХ независимо:
    упавший/убитый воркер не блокирует сбор остальных (каждый wait свой).

    P13-a-r2: исключение СПАУНА одного воркера (бинарь не найден, OSError)
    конвертируется в его собственный исход (returncode=None + error) — исходы
    остальных и сводка не теряются. Политика осиротения (зафиксирована):
    соседние воркеры НЕ отменяются — отмена asyncio-задачи не убивает
    подпроцесс и создала бы сирот БЕЗ исходов (ровно дефект FINDING-2);
    оркестратор ДОЖИДАЕТСЯ всех стартовавших и собирает каждый исход.

    `run_dirs` обязан покрывать `worker_argv` 1:1 (i-му воркеру — i-й
    run-каталог): расхождение длин — контрактный ValueError с сообщением,
    не IndexError из задачи.

    Воркерам даётся env-скоуп поверх текущего окружения:
    `MEMNOTSAFE_WORKER_INDEX` (1..N) и `MEMNOTSAFE_LEASE_DIR` (каталог замков
    оркестратора `<orchestrator_dir>/locks`; создаётся здесь). Замок сам этот
    слой не берёт — эксклюзивные операции за воркерами/live-карточками.
    `extra_env` — прикладные переменные поверх скоупа (например PYTHONPATH,
    чтобы дочерний CLI видел пакет при запуске из дерева исходников)."""
    if len(run_dirs) != len(worker_argv):
        raise ValueError(
            f"run_dirs ({len(run_dirs)}) не соответствует worker_argv "
            f"({len(worker_argv)}): каждому воркеру — свой run-каталог 1:1"
        )
    orchestrator_dir = Path(orchestrator_dir)
    locks_dir = orchestrator_dir / "locks"
    locks_dir.mkdir(parents=True, exist_ok=True)

    async def _spawn_and_wait(index: int, argv: Sequence[str]) -> WorkerOutcome:
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        env[WORKER_INDEX_ENV] = str(index)
        env[LEASE_DIR_ENV] = str(locks_dir)
        try:
            proc = await asyncio.create_subprocess_exec(*argv, env=env)
            rc = await proc.wait()
        except OSError as exc:
            # спаун/ожидание невозможны — честный маркер, исход не теряется
            return WorkerOutcome(
                index=index, argv=list(argv),
                run_dir=Path(run_dirs[index - 1]), returncode=None,
                error=f"воркер не стартовал: {type(exc).__name__}: {exc}",
            )
        return WorkerOutcome(index=index, argv=list(argv),
                             run_dir=Path(run_dirs[index - 1]), returncode=rc)

    return list(await asyncio.gather(*(
        _spawn_and_wait(i, argv) for i, argv in enumerate(worker_argv, start=1)
    )))


def orchestrator_rc(outcomes: Sequence[WorkerOutcome]) -> int:
    """0, только если ВСЕ воркеры завершились с 0; иначе 1 (нестартовавший
    rc=None — тоже неуспех). Новых кодов нет."""
    return 0 if outcomes and all(o.returncode == 0 for o in outcomes) else 1


def write_orchestrator_summary(
    summary_path: str | Path,
    outcomes: Sequence[WorkerOutcome],
    *,
    lease_dir: str | Path,
) -> Path:
    """Сводка оркестратора `<output>-orchestrator.json`: состав воркеров,
    argv, run-каталоги, rc каждого (null — воркер не стартовал, причина —
    в поле error, P13-a-r2), каталог замков и ОБЩНОСТЬ experiment_id
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
             "returncode": o.returncode, "error": o.error,
             "experiment_id": experiment_ids[i]}
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


async def orchestrate_plan(plan_path: str | Path, *, output: str | Path) -> tuple[Path, int]:
    """CARD-MULTI-1 — точка входа планировщика пакетов проверок (Этап 1, офлайн).

    Загружает и ВАЛИДИРУЕТ план (PlanError — стоп ДО первого запуска), затем
    отдаёт его планировщику `core.plan.run_plan` с дефолтным исполнителем задания
    — подпроцессом CLI-кампании (тот же приём PYTHONPATH, что у
    orchestrate_campaign) — и дефолтной проверкой чистоты (hook clean_check
    профиля). Пишет summary.json + batch-state.json. rc: 0, если ВСЕ задания
    выполнились (COMPLETED); иначе 1 (новых exit-кодов нет). Движок стадий и
    старый orchestrate --scenario не затрагиваются.

    FIX-PACK-2: расход задания — ФАКТ из budget-ledger.jsonl (D1); сводка
    пишется даже при исключении воркера, недовыполненные помечаются UNKNOWN
    (D3); стенд/принципалы пробрасываются дочернему процессу env-ом и
    попадают в сводку (D6, record-only)."""
    import subprocess

    from memnotsafe.core import plan as plan_mod

    output = Path(output)
    the_plan = plan_mod.load_plan(plan_path)
    plan_mod.validate_plan(the_plan)  # стоп ДО первого запуска

    # Дочерний CLI обязан видеть пакет из дерева исходников (как orchestrate_campaign).
    src_root = Path(__file__).resolve().parents[2]
    child_env = dict(os.environ)
    if (src_root / "memnotsafe").is_dir():
        existing = os.environ.get("PYTHONPATH", "")
        child_env["PYTHONPATH"] = str(src_root) + (os.pathsep + existing if existing else "")

    async def _run_child(scenario: str, target: str, iterations: int, run_dir: Path,
                         stand: "plan_mod.Stand | None" = None) -> tuple[int | None, dict | None, str]:
        argv = [sys.executable, "-m", "memnotsafe.cli", "campaign",
                "--scenario", str(scenario), "--target", str(target),
                "--iterations", str(iterations), "--output", str(run_dir), "--quiet"]
        # D6: пробрасываем стенд/принципалы дочернему процессу env-ом (record-only;
        # дочерний CLI их не читает). Копируем env только когда есть что добавить.
        env = batch_child_env(child_env, stand) if stand is not None else child_env
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, env=env,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            rc: int | None = proc.returncode
            stderr_text = (stderr or b"").decode("utf-8", "replace")
        except OSError as exc:
            rc, stderr_text = None, f"{type(exc).__name__}: {exc}"
        campaign = plan_mod.read_campaign(run_dir)
        return rc, campaign, stderr_text

    async def _runner(job: "plan_mod.Job", stand: "plan_mod.Stand", out: Path) -> "plan_mod.JobRun":
        run_dir = out / job.id
        rc, campaign, stderr_text = await _run_child(job.scenario, stand.target, job.iterations, run_dir, stand)
        n, m, value = plan_mod.asr_from_campaign(campaign)
        # D1: расход — ФАКТ из budget-ledger.jsonl (executed target_call), а не
        # знаменатель ASR (число КЕЙСОВ). Леджера нет → грубая оценка m с пометкой.
        actual, estimate = plan_mod.resolve_target_calls_actual(str(run_dir), m)
        run = plan_mod.JobRun(
            job_id=job.id, stand_id=stand.id,
            outcome=plan_mod.classify_outcome(rc, campaign, stderr_text),
            experiment_id=plan_mod.read_experiment_id(run_dir),
            asr_n=n, asr_m=m, asr_value=value,
            target_calls_actual=actual, target_calls_estimate=estimate,
            run_dir=str(run_dir), control_scenario=job.control,
            stand_principals=stand.principals,   # D6: атрибуция прогона к стенду
        )
        if job.control:
            ctrl_dir = out / f"{job.id}-control"
            crc, ccamp, cerr = await _run_child(job.control, stand.target, job.iterations, ctrl_dir, stand)
            run.control_outcome = plan_mod.classify_outcome(crc, ccamp, cerr)
            run.control_run_dir = str(ctrl_dir)
            _cn, cm, _cv = plan_mod.asr_from_campaign(ccamp)
            # D1: расход контроля — тоже факт из его леджера (симметрично атаке).
            c_actual, c_est = plan_mod.resolve_target_calls_actual(str(ctrl_dir), cm)
            if isinstance(c_actual, int):
                run.target_calls_actual = (
                    c_actual if not isinstance(run.target_calls_actual, int)
                    else run.target_calls_actual + c_actual
                )
            run.target_calls_estimate = bool(run.target_calls_estimate or c_est)
        return run

    def _clean_checker(stand: "plan_mod.Stand") -> "plan_mod.CleanResult":
        if not stand.clean_check:
            return plan_mod.CleanResult(status="unknown", detail="нет hook clean_check в профиле")
        try:
            proc = subprocess.run(
                list(stand.clean_check), env=child_env, timeout=30,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return plan_mod.CleanResult(status="dirty", detail=f"clean_check не запустился: {type(exc).__name__}")
        return (plan_mod.CleanResult(status="clean") if proc.returncode == 0
                else plan_mod.CleanResult(status="dirty", detail=f"clean_check rc={proc.returncode}"))

    # FIX-PACK-2 D3: краш/исключение воркера НЕ должен обрывать пакет без сводки.
    # run_plan наполняет ИМЕННО этот `runs` (тот же объект) — при исключении мы
    # видим частичный прогресс, помечаем недовыполненные задания UNKNOWN
    # (detail = тип исключения), ВСЁ РАВНО пишем summary.json + batch-state.json,
    # затем пробрасываем исключение дальше (rc-путь при этом не исполняется).
    runs: dict[str, plan_mod.JobRun] = {}
    summary_path = output / "summary.json"
    interrupted: str | None = None
    try:
        await plan_mod.run_plan(the_plan, output, runner=_runner,
                                clean_checker=_clean_checker, results=runs)
    except BaseException as exc:  # noqa: BLE001 — метка исхода + проброс, не глотаем
        interrupted = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        for job in the_plan.jobs:
            if job.id not in runs:
                runs[job.id] = plan_mod.JobRun(
                    job_id=job.id, stand_id=None, outcome=plan_mod.OUTCOME_UNKNOWN,
                    detail=(f"пакет прерван исключением: {interrupted}" if interrupted
                            else "задание не попало в результаты планировщика"),
                )
        plan_mod.write_batch(the_plan, output, runs)
    rc = 0 if runs and all(r.outcome == plan_mod.OUTCOME_COMPLETED for r in runs.values()) else 1
    return summary_path, rc
