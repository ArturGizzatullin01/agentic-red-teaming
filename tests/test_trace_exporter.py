"""tests/test_trace_exporter.py — карточка P11-1: экспорт трасс, семантика сбоя.

Главный инвариант (MASTER-PLAN §6/§7, P11): сбой экспорта НИКОГДА не теряет
пакет доказательств. Локальный events.jsonl (TraceRecorder) остаётся
источником истины и пишется всегда — экспортёр только наблюдатель-доставщик.
Спул на диске: один JSON-файл (список событий) на пакет, имена с возрастающей
последовательностью — FIFO по имени файла; пока спул не пуст, новые пакеты
становятся ЗА ним (прямой send запрещён) — порядок внутри run не нарушается.
"""

from __future__ import annotations

import json
from pathlib import Path

from memnotsafe.tracing.exporter import TraceExporter
from memnotsafe.tracing.recorder import TraceRecorder, read_events_jsonl


class _DeadSink:
    """Приёмник, всегда падающий (транспорт приёмника недоступен)."""

    def send(self, batch: list[dict]) -> None:
        raise ConnectionError("sink down")


class _FlakySink:
    """Приёмник, падающий первые fail_first вызовов send(), затем живой."""

    def __init__(self, fail_first: int) -> None:
        self._fail_first = fail_first
        self.received: list[list[dict]] = []

    def send(self, batch: list[dict]) -> None:
        if self._fail_first > 0:
            self._fail_first -= 1
            raise ConnectionError("sink down")
        self.received.append(list(batch))


class _CollectingSink:
    """Живой приёмник: собирает пакеты без сбоев."""

    def __init__(self) -> None:
        self.received: list[list[dict]] = []

    def send(self, batch: list[dict]) -> None:
        self.received.append(list(batch))


def _row(i: int) -> dict:
    """Ровно тот же вид строки, который TraceRecorder.record_raw пишет в JSONL."""
    return {"event_id": f"evt-{i:04d}", "event": "state_change", "case_id": "CASE-P11"}


def _spool_batches(spool_dir: Path) -> list[list[dict]]:
    files = sorted(p for p in spool_dir.glob("batch-*.json"))
    return [json.loads(p.read_text(encoding="utf-8")) for p in files]


def _flat(sink: _FlakySink | _CollectingSink) -> list[str]:
    return [row["event_id"] for batch in sink.received for row in batch]


def test_sink_failure_spools_and_local_jsonl_survives(tmp_path: Path) -> None:
    """PASS_IF 4a: приёмник падает на 1-м send -> события в спуле, локальный
    JSONL TraceRecorder'а не пострадал, pending > 0."""
    recorder = TraceRecorder(tmp_path / "events.jsonl")
    exporter = TraceExporter(_DeadSink(), batch_size=2, spool_dir=tmp_path / "spool")

    for i in range(1, 4):
        row = _row(i)
        recorder.record_raw(row)  # источник истины — первым
        exporter.record(row)      # наблюдатель — вторым

    recorded = read_events_jsonl(tmp_path / "events.jsonl")
    assert [r["event_id"] for r in recorded] == ["evt-0001", "evt-0002", "evt-0003"]
    assert exporter.pending == 3
    assert exporter.pending > 0
    assert _spool_batches(tmp_path / "spool") == [[_row(1), _row(2)]]


def test_spool_replayed_fifo_after_receiver_recovery(tmp_path: Path) -> None:
    """PASS_IF 4b: приёмник ожил -> спул доотправлен FIFO, pending = 0."""
    sink = _FlakySink(fail_first=1)
    exporter = TraceExporter(sink, batch_size=2, spool_dir=tmp_path / "spool")

    for i in range(1, 6):
        exporter.record(_row(i))

    assert sink.received == []  # первый send упал, остальные — за спулом
    exporter.flush()
    assert _flat(sink) == [f"evt-{i:04d}" for i in range(1, 6)]
    assert exporter.pending == 0
    assert _spool_batches(tmp_path / "spool") == []


def test_queue_overflow_spills_to_spool_without_loss(tmp_path: Path) -> None:
    """PASS_IF 4c: переполнение очереди памяти -> перелив в спул (не drop,
    не блокировка); count_in == count_out + pending на каждом шаге."""
    sink = _CollectingSink()
    exporter = TraceExporter(sink, batch_size=100, queue_limit=4, spool_dir=tmp_path / "spool")

    count_in = 0
    for i in range(1, 11):
        exporter.record(_row(i))
        count_in += 1
        assert sink.received == []  # прямой send при непустом спуле запрещён
        assert count_in == len(_flat(sink)) + exporter.pending

    assert exporter.pending == 10
    exporter.flush()
    assert _flat(sink) == [f"evt-{i:04d}" for i in range(1, 11)]
    assert exporter.pending == 0


def test_flush_with_dead_sink_is_safe_and_honest(tmp_path: Path) -> None:
    """PASS_IF 4d: flush при мёртвом приёмнике -> без исключения наружу,
    pending честный; повторный flush не «доставляет» и не теряет."""
    exporter = TraceExporter(_DeadSink(), batch_size=2, spool_dir=tmp_path / "spool")
    for i in range(1, 6):
        exporter.record(_row(i))

    exporter.flush()
    exporter.flush()
    assert exporter.pending == 5
    spooled = _spool_batches(tmp_path / "spool")
    assert [r["event_id"] for batch in spooled for r in batch] == [f"evt-{i:04d}" for i in range(1, 6)]


def test_order_preserved_across_failure_and_recovery(tmp_path: Path) -> None:
    """PASS_IF 6: порядок событий внутри run не нарушается никогда — пакеты
    после сбоя становятся за спулом, replay строго по последовательности."""
    sink = _FlakySink(fail_first=1)
    exporter = TraceExporter(sink, batch_size=2, spool_dir=tmp_path / "spool")
    for i in range(1, 6):
        exporter.record(_row(i))

    exporter.flush()
    assert _flat(sink) == [f"evt-{i:04d}" for i in range(1, 6)]
    assert _spool_batches(tmp_path / "spool") == []
    assert exporter.pending == 0


def test_interval_and_batch_size_params_drive_lazy_flush(tmp_path: Path) -> None:
    """batch_size и flush_interval_s — параметры конструктора; интервал
    срабатывает лениво (без фоновых потоков) по часам, инъекция clock."""
    sink = _CollectingSink()
    now = {"t": 100.0}
    exporter = TraceExporter(
        sink, batch_size=100, flush_interval_s=5.0,
        spool_dir=tmp_path / "spool", clock=lambda: now["t"],
    )

    exporter.record(_row(1))  # очередь открыта в t=100
    assert sink.received == []
    now["t"] = 110.0          # интервал истёк к моменту второй записи
    exporter.record(_row(2))

    assert _flat(sink) == ["evt-0001", "evt-0002"]
    assert exporter.pending == 0


def test_pending_counts_queue_and_spool_honestly(tmp_path: Path) -> None:
    """pending = очередь в памяти + все события спула; видно каждый пакет."""
    exporter = TraceExporter(_DeadSink(), batch_size=2, spool_dir=tmp_path / "spool")
    for i in range(1, 6):
        exporter.record(_row(i))

    assert len(list((tmp_path / "spool").glob("batch-*.json"))) == 2  # [1,2] и [3,4]
    assert exporter.pending == 5  # 4 в спуле + 1 в памяти
