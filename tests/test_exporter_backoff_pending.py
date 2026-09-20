"""tests/test_exporter_backoff_pending.py — карточка P11-3: backoff спула + pending O(1).

Backoff (карточка §5.2): после ОТКАЗА приёмника replay спула при следующих
flush() пропускается, пока не истёк backoff — экспонента от 1 с, ×2, потолок
60 с, через инжектированный clock; успех сбрасывает. Решение исполнителя
(раскрыто в хендофе §4): ПЕРВЫЙ отказ ретраится немедленно — иначе ломаются
тесты P11-1 (flush сразу после первого отказа обязан доотправить, карточка
запрещает их править); backoff включается со второго отказа подряд, ряд
задержек 1, 2, 4, …, 60 — «экспонента от 1 с» карточки соблюдена.

pending O(1) (карточка §5.3): pending не перечитывает файлы спула при повторных
вызовах без изменений — кэш {имя: число событий}; свои записи считаются при
_spool_write, удаления — при unlink, чужие/дорестартные — один раз.
Контроль чтения — подмена экземплярного метода _read_spool_file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.tracing.exporter import TraceExporter


class _Clock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


class _DeadSink:
    def __init__(self) -> None:
        self.calls = 0

    def send(self, batch: list[dict]) -> None:
        self.calls += 1
        raise ConnectionError("sink down")


class _FlakySink:
    def __init__(self, fail_first: int) -> None:
        self._fail_first = fail_first
        self.calls = 0
        self.received: list[list[dict]] = []

    def send(self, batch: list[dict]) -> None:
        self.calls += 1
        if self._fail_first > 0:
            self._fail_first -= 1
            raise ConnectionError("sink down")
        self.received.append(list(batch))


def _row(i: int) -> dict:
    return {"event_id": f"evt-{i:04d}", "event": "state_change", "case_id": "CASE-P113"}


def _flat(sink: _FlakySink) -> list[str]:
    return [row["event_id"] for batch in sink.received for row in batch]


def test_backoff_skips_replay_until_expired(tmp_path: Path) -> None:
    clock = _Clock()
    sink = _FlakySink(fail_first=2)
    exporter = TraceExporter(sink, batch_size=2, spool_dir=tmp_path / "spool", clock=clock)

    for i in range(1, 5):
        exporter.record(_row(i))  # [1,2] — отказ №1 (немедленный ретрай разрешён)
    sink_calls_after_records = sink.calls
    assert sink_calls_after_records == 1

    exporter.flush()  # отказ №2 -> backoff 1 c c момента t=1000
    assert sink.calls == 2
    baseline = sink.calls

    exporter.flush()  # backoff активен — sink не дёргается
    assert sink.calls == baseline, "flush дёрнул sink до истечения backoff"

    clock.now = 1000.999
    exporter.flush()
    assert sink.calls == baseline, "flush дёрнул sink за миг до истечения backoff"

    clock.now = 1001.0
    exporter.flush()  # backoff истёк — replay пошёл, приёмник жив
    assert _flat(sink) == [f"evt-{i:04d}" for i in range(1, 5)]
    assert exporter.pending == 0
    assert not list((tmp_path / "spool").glob("batch-*.json"))


def test_backoff_exponent_and_cap(tmp_path: Path) -> None:
    clock = _Clock()
    sink = _DeadSink()
    exporter = TraceExporter(sink, batch_size=2, spool_dir=tmp_path / "spool", clock=clock)
    exporter.record(_row(1))
    exporter.record(_row(2))  # отказ №1 — ретрай немедленный
    exporter.flush()  # отказ №2 -> backoff 1 c от текущего момента

    observed_delays: list[float] = []
    for _ in range(9):
        failure_at = clock.now  # очередная неудача произошла «сейчас»
        delay_found = None
        for seconds in range(0, 121):
            clock.now = failure_at + seconds
            before = sink.calls
            exporter.flush()
            if sink.calls > before:
                delay_found = seconds  # граница истечения backoff — первая секунда, когда send разрешён
                break
        assert delay_found is not None, "backoff не истёк — замок завис"
        observed_delays.append(float(delay_found))

    assert observed_delays == [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0, 60.0]


def test_success_resets_backoff(tmp_path: Path) -> None:
    clock = _Clock()
    sink = _FlakySink(fail_first=2)
    exporter = TraceExporter(sink, batch_size=2, spool_dir=tmp_path / "spool", clock=clock)

    exporter.record(_row(1))
    exporter.record(_row(2))  # отказ №1
    exporter.flush()  # отказ №2 -> backoff 1 c
    clock.now += 1.0
    exporter.flush()  # доставка успешна, backoff сброшен
    assert _flat(sink) == ["evt-0001", "evt-0002"]
    assert exporter.pending == 0

    # после сброса новая доставка идёт сразу, без ожидания
    exporter.record(_row(3))
    exporter.record(_row(4))  # batch заполнен -> прямая отправка немедленно
    assert _flat(sink) == [f"evt-{i:04d}" for i in range(1, 5)]
    assert exporter.pending == 0


def test_flush_drains_queue_to_spool_under_backoff(tmp_path: Path) -> None:
    clock = _Clock()
    sink = _DeadSink()
    exporter = TraceExporter(sink, batch_size=2, spool_dir=tmp_path / "spool", clock=clock)

    for i in range(1, 3):
        exporter.record(_row(i))  # отказ №1, спул [1,2]
    exporter.flush()  # отказ №2 -> backoff
    baseline_calls = sink.calls

    for i in range(3, 6):
        exporter.record(_row(i))  # остаются в очереди (батч не полон, часы стоят)
    assert exporter.pending == 5

    exporter.flush()  # backoff: очередь обязана уйти в спул, sink не дёргается
    assert sink.calls == baseline_calls
    assert exporter.pending == 5  # честный pending: ничего не потерялось
    files = sorted((tmp_path / "spool").glob("batch-*.json"))
    # [1,2] — от отказа, [3,4] — батч укомплектовался при записи (ушёл в спул
    # под backoff, без попытки send), [5] — докатан из очереди этим flush
    assert [len(json.loads(p.read_text(encoding="utf-8"))) for p in files] == [2, 2, 1]

    clock.now += 60.0  # гарантированно за потолком любого активного backoff
    exporter.flush()  # всё ещё мёртвый sink: попытка была, порядок не тронут
    assert exporter.pending == 5


def test_pending_reads_each_spool_file_once(tmp_path: Path) -> None:
    sink = _DeadSink()
    exporter = TraceExporter(sink, batch_size=2, spool_dir=tmp_path / "spool", clock=_Clock())

    for i in range(1, 6):  # спул [1,2] [3,4], очередь [5]
        exporter.record(_row(i))
    assert exporter.pending == 5

    reads: list[str] = []
    real_read = exporter._read_spool_file

    def counting_read(path: Path) -> list[dict]:
        reads.append(path.name)
        return real_read(path)

    exporter._read_spool_file = counting_read  # type: ignore[method-assign]

    assert exporter.pending == 5
    assert exporter.pending == 5
    assert reads == [], "свои файлы читаться не должны: счёт уже в кэше _spool_write"

    # чужой/дорестартный файл: считается РОВНО один раз
    foreign = tmp_path / "spool" / "batch-00000099.json"
    foreign.write_text(json.dumps([_row(i) for i in range(10, 17)]), encoding="utf-8")
    assert exporter.pending == 12
    assert exporter.pending == 12
    assert reads == ["batch-00000099.json"], f"лишние чтения: {reads}"

    # удаление файла (внешнее) немедленно видно: glob — источник истины имён
    foreign.unlink()
    assert exporter.pending == 5


def test_pending_counts_restart_files_once(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    spool.mkdir(parents=True)
    (spool / "batch-00000001.json").write_text(
        json.dumps([_row(i) for i in range(1, 4)]), encoding="utf-8"
    )
    (spool / "batch-00000002.json").write_text(
        json.dumps([_row(i) for i in range(4, 8)]), encoding="utf-8"
    )

    exporter = TraceExporter(_DeadSink(), spool_dir=spool, clock=_Clock())
    reads: list[str] = []
    real_read = exporter._read_spool_file

    def counting_read(path: Path) -> list[dict]:
        reads.append(path.name)
        return real_read(path)

    exporter._read_spool_file = counting_read  # type: ignore[method-assign]

    assert exporter.pending == 7
    assert exporter.pending == 7
    assert sorted(reads) == ["batch-00000001.json", "batch-00000002.json"]
    assert reads.count("batch-00000001.json") == 1, "дорестартный файл прочитан более раза"
