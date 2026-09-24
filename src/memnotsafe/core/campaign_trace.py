"""src/memnotsafe/core/campaign_trace.py — ARC-2: экспортный дубль трасс кампании
(персистенс/экспорт, вынесен из core/campaign.py при расщеплении). Ни ядра, ни
периферии не тянет: прокси поверх TraceRecorder для точки сборки recorder в
Campaign.run. Имя публичное (импортируется в core/campaign.py); поведение
прежнее — код перенесён дословно.
"""

from __future__ import annotations

from memnotsafe.tracing.recorder import TraceRecorder


class ExportingRecorder:
    """P11-3: прозрачный дубль событий в экспортёр поверх настоящего рекордера.

    Recorder остаётся источником истины и пишет ПЕРВЫМ (полный локальный
    JSONL, без масок); затем тот же plain-dict уходит в
    TraceExporter.record(), где маскируется на входе (P11-2) и доставляется
    по семантике P11-1 (батчинг, спул при отказе, backoff). Всё, кроме записи
    событий, делегируется рекордеру как есть — для раннера и слоёв кампании
    прокси неотличим от TraceRecorder.
    """

    __slots__ = ("_recorder", "_exporter")

    def __init__(self, recorder: TraceRecorder, exporter) -> None:
        self._recorder = recorder
        self._exporter = exporter

    def record(self, event) -> None:
        self._recorder.record(event)
        self._exporter.record(event.to_dict() if hasattr(event, "to_dict") else event)

    def record_raw(self, row: dict) -> None:
        self._recorder.record_raw(row)
        self._exporter.record(row)

    def __getattr__(self, name: str):  # делегирование всего прочего рекордеру
        return getattr(self._recorder, name)
