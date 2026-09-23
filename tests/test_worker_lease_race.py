"""tests/test_worker_lease_race.py — CARD-P13-a-r3: межпроцессная сериализация
takeover/release в FileLease (P0, блокер live P13-d).

Замки (offline: подпроцессы интерпретатора в tmp, без сети, без Docker):

  1. гонка takeover одного имени: A прошёл проверку живости истёкшего замка,
     B за это время завершил СВОЙ takeover, A продолжил — держателей не два:
     проигравший получил None, замок победителя цел, его токен снимается release;
  2. полузаписанный замок (создан O_EXCL, содержимое ещё не записано, дескриптор
     у держателя открыт) + конкурентный acquire — ни голого исключения наружу
     (Windows: PermissionError на unlink открытого файла), ни второго держателя;
     проигравший — None;
  3. release-vs-takeover: release со свежим токеном, в окно которого вклинился
     takeover того же имени, не снимает замок с ДРУГИМ токеном;
  4. регресс-контроль под мьютексом: последовательные acquire/release,
     TTL-перехват orphan, монотонность при потерянном/битом счётчике
     (наследие r2), строго возрастающие токены через ПРОЦЕССЫ;
  5. смерть держателя мьютекса не блокирует каталог: процесс, убитый внутри
     критической секции, отдаёт мьютекс силами ОС — следующий acquire проходит;
  6. окно r2 «равные токены РАЗНЫХ имён»: B вычислил токен между вычислением
     токена A и записью счётчика — токены обязаны различаться.

Шов (детерминизм, а не гонка на удачу): одноразовый хук на внутренней точке
кода под тестом (`_read_json` / `_write_counter_atomic` / `os.write`) запускает
второго участника ПОДПРОЦЕССОМ и ждёт одного из двух маркеров: «готов»
(участник завершил операцию — так на чистой базе: дефект виден, RED) или
«жду мьютекс» (участник встал на мьютекс каталога — так под мьютексом: хук
отпускает, секция завершается, участник получает честный отказ или следующий
токен, GREEN). Маркер «жду» пишет сам участник хуком на `_mutex_lock`
(на базе функции нет — маркера нет); таймаут SEAM_TIMEOUT — страховка.
lease-время в обоих процессах заморожено инжектируемым clock (норма
VERDICT-P12), живых TTL-таймеров нет. Единственное тайминг-допущение — у
RED-доказательства, не у GREEN: на базе участник обязан завершить acquire за
SEAM_TIMEOUT после маркера «вошёл» (измерено ≤ 6 мс при 2 с — запас ~300×);
GREEN от тайминга не зависит — вставший на мьютекс участник не может
завершиться, пока секция не закрыта.

Импорт воркер-модуля — внутри тестов (прецедент P12): модуль на базе есть,
RED — падение конкретных тестов на дефектах §1 карточки, а не на импорте.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Ожидание результата второго участника ВНУТРИ шва: на базе ему хватает
# миллисекунд (несколько файловых операций); под мьютексом он заблокирован и
# таймаут отрабатывает полностью — цена детерминизма, не признак дефекта.
SEAM_TIMEOUT = 2.0
# Ожидание старта интерпретатора подпроцесса (маркер «вошёл»).
START_TIMEOUT = 30.0


class FuncClock:
    """Ручные монотонные часы: тест двигает время явно."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------- подпроцессы

# Участник: acquire(name, ttl=5.0) с замороженными часами; маркер «вошёл» —
# перед вызовом, маркер «готов» с результатом — после; результат и в stdout.
ACQUIRE = r'''
import json, sys
from pathlib import Path
from memnotsafe.core import worker
from memnotsafe.core.worker import FileLease
lease_dir, name, now, tag = sys.argv[1:5]
# Маркер «жду мьютекс каталога»: есть только у кода с мьютексом (на базе
# _mutex_lock нет — маркер не пишется, шов ждёт «готов»/таймаут).
_orig_lock = getattr(worker, "_mutex_lock", None)
if _orig_lock is not None:
    def _marked_lock(fd):
        Path(tag + ".waiting").write_text("1", encoding="utf-8")
        return _orig_lock(fd)
    worker._mutex_lock = _marked_lock
lease = FileLease(lease_dir, clock=lambda: float(now))
Path(tag + ".entering").write_text("1", encoding="utf-8")
try:
    held = lease.acquire(name, 5.0)
    result = {"token": None if held is None else held.fencing_token}
except Exception as exc:  # голое исключение наружу — факт для теста, не скрываем
    result = {"error": type(exc).__name__, "message": str(exc)}
Path(tag + ".done").write_text(json.dumps(result), encoding="utf-8")
print(json.dumps(result))
'''

# Держатель с полузаписанным замком: одноразовый шов на os.write — замок уже
# создан O_EXCL (дескриптор открыт), содержимое не записано; ждёт файла go.
HALF_WRITTEN_HOLDER = r'''
import json, os, sys, time
from pathlib import Path
from memnotsafe.core.worker import FileLease
lease_dir, name, tag, go = sys.argv[1:5]
orig_write = os.write
def seam(fd, data):
    os.write = orig_write
    Path(tag + ".at_seam").write_text("1", encoding="utf-8")
    deadline = time.monotonic() + 30.0
    while not Path(go).exists() and time.monotonic() < deadline:
        time.sleep(0.005)
    return orig_write(fd, data)
os.write = seam
lease = FileLease(lease_dir, clock=lambda: 0.0)
held = lease.acquire(name, 5.0)
result = {"token": None if held is None else held.fencing_token}
Path(tag + ".done").write_text(json.dumps(result), encoding="utf-8")
print(json.dumps(result))
'''

# Держатель, «зависший» внутри критической секции acquire (до создания замка):
# будет убит тестом — мьютекс обязан освободиться силами ОС.
STALL_INSIDE_SECTION = r'''
import sys, time
from pathlib import Path
from memnotsafe.core.worker import FileLease
lease_dir, tag = sys.argv[1:3]
lease = FileLease(lease_dir, clock=lambda: 0.0)
orig = lease._max_token_seen
def seam():
    Path(tag + ".inside").write_text("1", encoding="utf-8")
    time.sleep(120)
    return orig()
lease._max_token_seen = seam
lease.acquire("victim", 5.0)
'''


def _src_root() -> str:
    """src своего worktree (W10): подпроцесс обязан импортировать ТОТ ЖЕ модуль,
    что и тест, а не установленный пакет."""
    from memnotsafe.core import worker

    return str(Path(worker.__file__).resolve().parents[2])


def _env() -> dict[str, str]:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = _src_root() + (os.pathsep + existing if existing else "")
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _spawn(script: str, *args: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", script, *args], env=_env(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )


def _wait_file(path: Path, timeout: float, proc: subprocess.Popen | None = None) -> bool:
    """Ждать файл-маркер; если передан процесс и он умер раньше маркера —
    вернуть сразу (диагностика вместо полного ожидания)."""
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            break
        time.sleep(0.005)
    return path.exists()


def _wait_seam(tag: str) -> str:
    """Ожидание внутри шва: участник либо завершил операцию («готов» — база),
    либо встал на мьютекс каталога («жду» — код с мьютексом); таймаут —
    страховка. Возвращает, что наблюдалось."""
    deadline = time.monotonic() + SEAM_TIMEOUT
    done, waiting = Path(tag + ".done"), Path(tag + ".waiting")
    while time.monotonic() < deadline:
        if done.exists():
            return "done"
        if waiting.exists():
            return "waiting"
        time.sleep(0.005)
    return "timeout"


def _start_marker(path: Path, proc: subprocess.Popen, who: str) -> None:
    """Маркер старта участника обязан появиться; иначе — падение с его stderr."""
    if not _wait_file(path, START_TIMEOUT, proc):
        err = proc.communicate()[1][-800:] if proc.poll() is not None else "(процесс жив, маркера нет)"
        raise AssertionError(f"{who} не стартовал: rc={proc.poll()} stderr={err}")


def _finish(proc: subprocess.Popen, timeout: float = 30.0) -> dict:
    """Дождаться участника и разобрать его результат (последняя строка stdout).
    Зависание — честный маркер error=TimeoutExpired, процесс убивается."""
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return {"error": "TimeoutExpired", "stderr": err[-2000:]}
    lines = [line for line in out.splitlines() if line.strip()]
    if not lines:
        return {"error": "no-output", "rc": proc.returncode, "stderr": err[-2000:]}
    try:
        result = json.loads(lines[-1])
    except ValueError:
        return {"error": "bad-output", "rc": proc.returncode, "stdout": out[-2000:], "stderr": err[-2000:]}
    if err.strip():
        result["stderr"] = err[-2000:]
    return result


def _lock_on_disk(lease_dir: Path, name: str) -> dict:
    return json.loads((lease_dir / f"{name}.lock").read_text(encoding="utf-8"))


def _kill_if_alive(*procs: subprocess.Popen | None) -> None:
    for proc in procs:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.communicate()


# ============================================================ замок 1: takeover


def test_takeover_race_same_name_has_single_holder(tmp_path: Path, monkeypatch) -> None:
    """Дефект 1 карточки. A (тест-процесс, clock 6.0) начал takeover истёкшего
    замка: после чтения живости шов запускает B (подпроцесс, clock 6.0), который
    выполняет свой takeover того же имени. На базе A продолжает по устаревшему
    решению: снимает ЖИВОЙ замок B и кладёт свой — два держателя. Под мьютексом
    B ждёт, A завершает takeover, B получает None."""
    from memnotsafe.core import worker

    lease_dir = tmp_path / "locks"
    dead = worker.FileLease(lease_dir, clock=FuncClock(0.0)).acquire("reset", 5.0)
    assert dead is not None  # «умерший» держатель: к 6.0 его замок истёк
    a_lease = worker.FileLease(lease_dir, clock=FuncClock(6.0))
    tag = str(tmp_path / "B")
    state: dict = {"proc": None, "fired": False}
    orig_read = worker._read_json

    def seam(path: Path):
        data = orig_read(path)
        if not state["fired"]:
            state["fired"] = True
            state["proc"] = _spawn(ACQUIRE, str(lease_dir), "reset", "6.0", tag)
            _start_marker(Path(tag + ".entering"), state["proc"], "B")
            _wait_seam(tag)
        return data

    monkeypatch.setattr(worker, "_read_json", seam)
    try:
        a_held = a_lease.acquire("reset", 5.0)
        assert state["fired"], "шов не сработал: проверка живости не читала замок"
        b_res = _finish(state["proc"])
    finally:
        _kill_if_alive(state["proc"])

    assert "error" not in b_res, b_res
    holders = {"A": None if a_held is None else a_held.fencing_token, "B": b_res["token"]}
    live = {who: tok for who, tok in holders.items() if tok is not None}
    assert len(live) == 1, (
        f"два держателя одного имени — дефект 1 (takeover снял живой замок): {holders}"
    )
    (winner_token,) = live.values()
    assert winner_token > dead.fencing_token
    assert _lock_on_disk(lease_dir, "reset")["fencing_token"] == winner_token, (
        "замок на диске не принадлежит победителю"
    )
    assert worker.FileLease(lease_dir, clock=FuncClock(6.0)).release(winner_token) is True


# ====================================================== замок 2: полузаписанный


def test_half_written_lock_no_exception_no_double_holder(tmp_path: Path) -> None:
    """Дефект 2 карточки. B (подпроцесс) создал замок O_EXCL и остановлен на
    шве перед записью содержимого (дескриптор открыт, файл пустой). A
    (подпроцесс) делает acquire того же имени. На базе A читает пустой файл как
    «не живой» и идёт на unlink: Windows — PermissionError наружу, POSIX —
    замок затёрт и два держателя. Под мьютексом A ждёт завершения B и получает
    честный None; замок B цел, токен B снимается release."""
    from memnotsafe.core import worker

    lease_dir = tmp_path / "locks"
    lease_dir.mkdir()
    b_tag, a_tag, go = str(tmp_path / "B"), str(tmp_path / "A"), tmp_path / "go"
    b_proc = _spawn(HALF_WRITTEN_HOLDER, str(lease_dir), "reset", b_tag, str(go))
    a_proc = None
    try:
        _start_marker(Path(b_tag + ".at_seam"), b_proc, "B (до шва)")
        assert (lease_dir / "reset.lock").stat().st_size == 0, "ожидался пустой (полузаписанный) замок"
        a_proc = _spawn(ACQUIRE, str(lease_dir), "reset", "0.0", a_tag)
        _start_marker(Path(a_tag + ".entering"), a_proc, "A")
        # база: A завершается сам (исключением или чужим замком); мьютекс: A ждёт B
        _wait_seam(a_tag)
        go.write_text("1", encoding="utf-8")
        b_res = _finish(b_proc)
        a_res = _finish(a_proc)
    finally:
        _kill_if_alive(a_proc, b_proc)

    assert "error" not in a_res, (
        f"голое исключение из acquire при полузаписанном замке — дефект 2: {a_res}"
    )
    assert b_res.get("token") is not None, b_res
    assert a_res["token"] is None, (
        f"второй держатель при полузаписанном замке — дефект 2: A={a_res}, B={b_res}"
    )
    assert _lock_on_disk(lease_dir, "reset")["fencing_token"] == b_res["token"]
    assert worker.FileLease(lease_dir, clock=FuncClock(0.0)).release(b_res["token"]) is True


# ============================================= замок 3: release против takeover


def test_release_racing_takeover_keeps_other_token_lock(tmp_path: Path, monkeypatch) -> None:
    """Дефект 3 карточки. Держатель H (тест-процесс) делает release(своего
    токена); после чтения замка шов запускает X (подпроцесс, clock 6.0 — замок H
    истёк), который перекладывает то же имя с НОВЫМ токеном. На базе H
    продолжает по устаревшему чтению и снимает по пути замок X. Под мьютексом X
    ждёт, H снимает свой замок, затем X кладёт свой — замок X цел."""
    from memnotsafe.core import worker

    lease_dir = tmp_path / "locks"
    holder = worker.FileLease(lease_dir, clock=FuncClock(0.0))
    first = holder.acquire("reset", 5.0)
    assert first is not None
    tag = str(tmp_path / "X")
    state: dict = {"proc": None, "fired": False}
    orig_read = worker._read_json

    def seam(path: Path):
        data = orig_read(path)
        if not state["fired"]:
            state["fired"] = True
            state["proc"] = _spawn(ACQUIRE, str(lease_dir), "reset", "6.0", tag)
            _start_marker(Path(tag + ".entering"), state["proc"], "X")
            _wait_seam(tag)
        return data

    monkeypatch.setattr(worker, "_read_json", seam)
    try:
        released = holder.release(first.fencing_token)
        assert state["fired"], "шов не сработал: release не читал замок"
        x_res = _finish(state["proc"])
    finally:
        _kill_if_alive(state["proc"])

    assert "error" not in x_res, x_res
    assert x_res["token"] is not None and x_res["token"] > first.fencing_token, (
        f"takeover X обязан состояться (до или после release): {x_res}"
    )
    assert (lease_dir / "reset.lock").exists(), (
        "release снял замок с ЧУЖИМ токеном — дефект 3: замок X пропал"
    )
    assert _lock_on_disk(lease_dir, "reset")["fencing_token"] == x_res["token"]
    assert released is True  # свой замок на момент решения был на месте
    assert worker.FileLease(lease_dir, clock=FuncClock(6.0)).release(x_res["token"]) is True


# ====================================================== замок 4: регресс-контроль


def test_regression_sequences_hold_under_mutex(tmp_path: Path) -> None:
    """Наследие P13-a/r2 продолжает работать под мьютексом: последовательные
    acquire/release, TTL-перехват orphan + устаревший release False, монотонность
    при потерянном и битом счётчике; затем три ПРОЦЕССА по очереди — токены
    строго растут дальше, каталог содержит ровно их замки (служебные файлы
    каталога за замки не принимаются)."""
    from memnotsafe.core.worker import FileLease

    lease_dir = tmp_path / "locks"
    clock = FuncClock(0.0)
    lease = FileLease(lease_dir, clock=clock)
    tokens = []
    for _ in range(3):
        held = lease.acquire("reset", 5.0)
        assert held is not None
        tokens.append(held.fencing_token)
        assert lease.release(held.fencing_token) is True
    assert tokens[0] < tokens[1] < tokens[2], tokens

    h1 = lease.acquire("reset", 5.0)
    assert h1 is not None
    clock.now = 4.999
    assert lease.acquire("reset", 5.0) is None, "неистёкший замок снят раньше TTL"
    clock.now = 6.0
    h2 = lease.acquire("reset", 5.0)
    assert h2 is not None and h2.fencing_token > h1.fencing_token
    assert lease.release(h1.fencing_token) is False, "устаревший токен принят"

    (lease_dir / "fencing.counter").unlink()
    clock.now = 12.0
    h3 = lease.acquire("reset", 5.0)
    assert h3 is not None and h3.fencing_token > h2.fencing_token
    (lease_dir / "fencing.counter").write_text("не-число", encoding="utf-8")
    clock.now = 18.0
    h4 = lease.acquire("reset", 5.0)
    assert h4 is not None and h4.fencing_token > h3.fencing_token
    assert lease.release(h4.fencing_token) is True

    cross = []
    for i, name in enumerate(("w1", "w2", "w3")):
        res = _finish(_spawn(ACQUIRE, str(lease_dir), name, "18.0", str(tmp_path / f"P{i}")))
        assert res.get("token") is not None, res
        cross.append(res["token"])
    assert cross[0] > h4.fencing_token and cross == sorted(cross) and len(set(cross)) == 3, cross
    assert sorted(p.name for p in lease_dir.glob("*.lock")) == ["w1.lock", "w2.lock", "w3.lock"]
    for tok in cross:
        assert lease.release(tok) is True


# ================================================ замок 5: смерть держателя


def test_killed_mutex_holder_does_not_block_directory(tmp_path: Path) -> None:
    """Держатель K убит внутри критической секции acquire (до создания замка).
    Без какой-либо чистки следующий acquire в каталоге обязан пройти: мьютекс
    держится на дескрипторе, ОС снимает его при смерти процесса. Зависание —
    честный TimeoutExpired, не вечное ожидание теста."""
    lease_dir = tmp_path / "locks"
    lease_dir.mkdir()
    tag = str(tmp_path / "K")
    k_proc = _spawn(STALL_INSIDE_SECTION, str(lease_dir), tag)
    a_proc = None
    try:
        _start_marker(Path(tag + ".inside"), k_proc, "K")
        k_proc.kill()
        k_proc.communicate(timeout=30.0)
        a_tag = str(tmp_path / "A")
        a_proc = _spawn(ACQUIRE, str(lease_dir), "reset", "0.0", a_tag)
        _start_marker(Path(a_tag + ".entering"), a_proc, "A")
        res = _finish(a_proc, timeout=10.0)  # 10 с — только на сам acquire, не на старт интерпретатора
    finally:
        _kill_if_alive(a_proc, k_proc)

    assert res.get("token") is not None, (
        f"каталог заблокирован после смерти держателя мьютекса: {res}"
    )
    assert not (lease_dir / "victim.lock").exists(), "убитый до создания замка замка не оставил"


# ============================================= замок 6: разные имена, один токен


def test_concurrent_different_names_get_distinct_tokens(tmp_path: Path, monkeypatch) -> None:
    """Окно r2 (названо в докстринге r2 как остаточное): A вычислил токен и на
    шве перед записью счётчика запускается B с ДРУГИМ именем. На базе B видит
    старый максимум и берёт тот же токен — два замка с равным fencing-токеном.
    Под мьютексом B ждёт, A записывает счётчик и замок, B получает следующий."""
    from memnotsafe.core import worker

    lease_dir = tmp_path / "locks"
    a_lease = worker.FileLease(lease_dir, clock=FuncClock(0.0))
    tag = str(tmp_path / "B")
    state: dict = {"proc": None, "fired": False}
    orig_write = a_lease._write_counter_atomic

    def seam(token: int) -> None:
        if not state["fired"]:
            state["fired"] = True
            state["proc"] = _spawn(ACQUIRE, str(lease_dir), "beta", "0.0", tag)
            _start_marker(Path(tag + ".entering"), state["proc"], "B")
            _wait_seam(tag)
        orig_write(token)

    monkeypatch.setattr(a_lease, "_write_counter_atomic", seam)
    try:
        a_held = a_lease.acquire("alpha", 5.0)
        assert state["fired"], "шов не сработал: счётчик не записывался"
        b_res = _finish(state["proc"])
    finally:
        _kill_if_alive(state["proc"])

    assert a_held is not None and "error" not in b_res and b_res["token"] is not None, (a_held, b_res)
    assert a_held.fencing_token != b_res["token"], (
        f"равные токены у разных имён (окно r2 не закрыто): A={a_held.fencing_token}, B={b_res['token']}"
    )
    assert {a_held.fencing_token, b_res["token"]} == {1, 2}
    assert int((lease_dir / "fencing.counter").read_text(encoding="utf-8")) == 2
    assert _lock_on_disk(lease_dir, "alpha")["fencing_token"] == a_held.fencing_token
    assert _lock_on_disk(lease_dir, "beta")["fencing_token"] == b_res["token"]
