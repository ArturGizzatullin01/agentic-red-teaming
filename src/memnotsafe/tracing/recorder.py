"""src/memnotsafe/tracing/recorder.py — JSONL-трейсер: пишет каждое событие на диск сразу
(не буферизует до конца прогона — падение раннера на 9-м шаге всё равно оставляет
трейс первых 8 читаемым, это и есть evidence-first)."""

from __future__ import annotations

import json
from pathlib import Path

from memnotsafe.tracing.events import TraceEvent


class TraceRecorder:
    """Пишет события одного run'а в events.jsonl (общий файл кампании) и
    опционально в отдельный traces/<case_id>.json (для конкретного кейса —
    удобно для report/replay без парсинга всего campaign-файла)."""

    def __init__(self, events_path: Path, traces_dir: Path | None = None):
        self.events_path = events_path
        self.traces_dir = traces_dir
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        if traces_dir:
            traces_dir.mkdir(parents=True, exist_ok=True)
        self._case_buffers: dict[str, list[dict]] = {}

    def record(self, event: TraceEvent) -> None:
        self.record_raw(event.to_dict())

    def record_raw(self, row: dict) -> None:
        """Как record(), но для событий, уже собранных адаптером как plain dict
        (SendResult.events) — избегаем требовать от каждого адаптера импортировать
        TraceEvent, лишь бы форма dict совпадала со схемой из events.py."""
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        case_id = row.get("case_id", "")
        self._case_buffers.setdefault(case_id, []).append(row)

    def case_events(self, case_id: str) -> list[dict]:
        return list(self._case_buffers.get(case_id, []))

    def flush_case_trace(self, case_id: str) -> Path | None:
        if not self.traces_dir:
            return None
        path = self.traces_dir / f"{case_id}.json"
        path.write_text(
            json.dumps(self.case_events(case_id), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path

    def record_case_transcript(self, case_id: str, builder) -> Path | None:
        """002-reporting: сохранить журнал диалога кейса (полный или наблюдённая
        часть при ошибке) в traces/<case_id>-transcript.json. Отдельно от
        events-трассы: другой consumer, другой wire-контракт (schema_version)."""
        if not self.traces_dir:
            return None
        path = self.traces_dir / f"{case_id}-transcript.json"
        path.write_text(
            json.dumps(builder.to_wire(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path


def read_events_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out
