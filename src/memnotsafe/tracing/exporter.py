"""src/memnotsafe/tracing/exporter.py — экспорт трасс во внешний приёмник (P11-1).

Экспортёр — НАБЛЮДАТЕЛЬ поверх TraceRecorder, не замена и не обёртка:
локальный events.jsonl остаётся источником истины и пишется всегда, даже при
мёртвом приёмнике (evidence-first не ослабляется). Экспортируются ФАКТЫ
(события трейса как plain dict, тот же вид строки, что TraceRecorder.record_raw
пишет в JSONL), а не вердикты: evidence_kind помечает поднимаемость судьёй,
а не измеренность (замечание MASTER-PLAN v3.2 к P11).

Семантика сбоя (MASTER-PLAN §6 таблица сбоев / §7 P11 DoD: «сбой экспорта
не теряет пакет»):
  - приёмник считается отказавшим, если send() поднял исключение;
  - недоставленный пакет уходит в спул на диск (директория-параметр) —
    один JSON-файл на пакет, имя batch-<seq:08d>.json, seq монотонен
    (продолжается от существующих файлов — рестарт не ломает FIFO);
  - ПОКА СПУЛ НЕ ПУСТ, прямые отправки запрещены: новые пакеты становятся
    в спул за неотправленными — порядок событий внутри run не нарушается
    никогда (требование P11-1);
  - при восстановлении приёмника flush() вычитывает спул строго по seq (FIFO)
    и доотправляет; первый же новый отказ останавливает replay (порядок
    важнее ретраев), повторная попытка — следующий flush;
  - переполнение очереди памяти (queue_limit) — перелив СТАРЫХ событий в спул,
    не drop и не блокировка вызывающего;
  - flush() не бросает исключений наружу: недоставленное честно видно через
    pending (очередь памяти + все события спула), успех не маскируется.

Контракт однопоточный: экспортёр не порождает потоков/задач и не трогает
глобальное состояние — вызывающий (будущая интеграция P11-2/P11-3) решает,
из какого цикла его дёргать. Никаких сторонних зависимостей: приёмник —
чистый Protocol, реальный шлюз подключается снаружи.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Protocol


class TraceSink(Protocol):
    """Приёмник пакетов событий (например, внешний trace-шлюз этапа P11-3).

    Отказ приёмника — ЛЮБОЕ исключение из send(); оно не должно покидать
    экспортёр: пакет обязан доехать через спул позже, а не уронить прогон.
    """

    def send(self, batch: list[dict[str, Any]]) -> None: ...  # pragma: no cover


class TraceExporter:
    """Доставщик уже зафиксированных событий наружу; см. докстринг модуля."""

    def __init__(
        self,
        sink: TraceSink,
        *,
        batch_size: int = 200,
        flush_interval_s: float = 5.0,
        spool_dir: Path,
        queue_limit: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if batch_size < 1:
            raise ValueError(f"batch_size={batch_size!r}: должен быть >= 1")
        if queue_limit < 1:
            raise ValueError(f"queue_limit={queue_limit!r}: должен быть >= 1")
        if flush_interval_s <= 0:
            raise ValueError(f"flush_interval_s={flush_interval_s!r}: должен быть > 0")
        self._sink = sink
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._queue_limit = queue_limit
        self._clock = clock
        self._spool_dir = Path(spool_dir)
        self._spool_dir.mkdir(parents=True, exist_ok=True)
        self._queue: list[dict[str, Any]] = []
        self._first_queued_at: float | None = None
        self._seq = self._max_spool_seq() + 1

    # -- публичный контракт -------------------------------------------------

    def record(self, event: dict[str, Any]) -> None:
        """Принять одно событие (тот же plain-dict, что пишет recorder).

        Доставка ленивая: пакет уходит при заполнении batch_size, по истечении
        flush_interval_s (проверяется при следующей записи — фоновых потоков
        нет) или при явном flush(). Переполнение очереди памяти переливает
        самые старые события в спул, не блокируя вызывающего.
        """
        self._queue.append(event)
        if self._first_queued_at is None:
            self._first_queued_at = self._clock()
        if len(self._queue) >= self._batch_size:
            self._ship_queue()
        elif self._clock() - self._first_queued_at >= self._flush_interval_s:
            self._ship_queue()
        while len(self._queue) > self._queue_limit:
            overflow = self._queue[: len(self._queue) - self._queue_limit]
            del self._queue[: len(self._queue) - self._queue_limit]
            self._spool_write(overflow)
            if self._first_queued_at is None:
                self._first_queued_at = self._clock()

    def flush(self) -> None:
        """Доотправить всё возможное: сначала спул FIFO, затем очередь.

        Исключений наружу не бросает: первый же отказ приёмника останавливает
        replay (порядок важнее ретраев), недоставленное остаётся в спуле и
        видно через pending. Повторная попытка — следующий flush().
        """
        for path in self._spool_files():
            batch = json.loads(path.read_text(encoding="utf-8"))
            try:
                self._sink.send(batch)
            except Exception:
                break
            path.unlink()
        if self._queue:
            queue, self._queue = self._queue, []
            first_queued_at, self._first_queued_at = self._first_queued_at, None
            self._deliver(queue, _first_queued_at=first_queued_at)

    @property
    def pending(self) -> int:
        """Число недоставленных событий: очередь памяти + весь спул."""
        total = len(self._queue)
        for path in self._spool_files():
            total += len(json.loads(path.read_text(encoding="utf-8")))
        return total

    # -- внутреннее ---------------------------------------------------------

    def _ship_queue(self) -> None:
        queue, self._queue = self._queue, []
        first_queued_at, self._first_queued_at = self._first_queued_at, None
        self._deliver(queue, _first_queued_at=first_queued_at)

    def _deliver(self, events: list[dict[str, Any]], *, _first_queued_at: float | None) -> None:
        """Порядок важнее скорости: пока спул не пуст, новые — только в спул."""
        if self._spool_files():
            self._spool_write(events)
            return
        try:
            self._sink.send(list(events))
        except Exception:
            self._spool_write(events)

    def _spool_write(self, events: list[dict[str, Any]]) -> None:
        if not events:
            return
        seq, self._seq = self._seq, self._seq + 1
        final = self._spool_dir / f"batch-{seq:08d}.json"
        tmp = self._spool_dir / f".batch-{seq:08d}.json.tmp"
        tmp.write_text(json.dumps(events, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, final)  # атомарно: недописанного пакета в спуле не бывает

    def _spool_files(self) -> list[Path]:
        return sorted(self._spool_dir.glob("batch-*.json"))

    def _max_spool_seq(self) -> int:
        best = 0
        for path in self._spool_dir.glob("batch-*.json"):
            try:
                best = max(best, int(path.stem.removeprefix("batch-")))
            except ValueError:
                continue  # чужой файл в спуле порядку не помеха
        return best
