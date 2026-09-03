"""core/tracer.py — трасса прогона атаки: локальный JSONL всегда, Langfuse — best-effort enrichment.

Почему так: `verify-finding.md` требует ссылку на трассу для любой засчитанной находки,
а Langfuse нигде не развёрнут ни в стенде, ни у нас (grep по стенду — пусто). Ждать
поднятия отдельной инфраструктуры Langfuse ради MVP — блокер без причины. Поэтому
инструмент трассирует СВОИ собственные вызовы target.py (мы и так видим весь
raw_request/raw_response) в локальный JSONL — этого достаточно, чтобы invariant
"trace_ref present" был математически истинным, а не костылём "поверь на слово".

Если оператор всё же задал LANGFUSE_PUBLIC_KEY/LANGFUSE_SECRET_KEY/LANGFUSE_HOST —
CompositeTracer одновременно зеркалит те же спаны в Langfuse (best-effort: любая
ошибка SDK/сети гасится и логируется, но не валит прогон и не блокирует local_jsonl).
TraceRef после этого несёт оба указателя, если Langfuse доступен, или только local
path, если нет — код-потребитель (core/judge.py) считает trace_ref "present", если
непусто хотя бы local_path.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from core.target import ChatResult

logger = logging.getLogger("core.tracer")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TraceRef:
    local_path: str
    langfuse_url: str | None = None

    @property
    def present(self) -> bool:
        return bool(self.local_path) or bool(self.langfuse_url)

    def as_dict(self) -> dict:
        return {"local_path": self.local_path, "langfuse_url": self.langfuse_url}


class RunTraceHandle(Protocol):
    def log_chat(self, chat_result: ChatResult, *, note: str = "") -> None: ...
    def log_event(self, name: str, payload: dict) -> None: ...
    def finish(self) -> TraceRef: ...


class Tracer(Protocol):
    def start_run(self, run_id: str, metadata: dict) -> RunTraceHandle: ...


# --- локальный JSONL-трейсер (гарантированная база) -------------------------------------


class _LocalRunHandle:
    def __init__(self, run_id: str, path: Path, metadata: dict):
        self._path = path
        self._run_id = run_id
        with self._path.open("w", encoding="utf-8") as f:
            f.write(json.dumps({"kind": "run_start", "run_id": run_id, "ts": _utc_now().isoformat(),
                                 "metadata": metadata}, ensure_ascii=False) + "\n")

    def log_chat(self, chat_result: ChatResult, *, note: str = "") -> None:
        line = {
            "kind": "chat",
            "label": chat_result.label,
            "note": note,
            "session_id": chat_result.session_id,
            "ts": chat_result.ts.isoformat(),
            "latency_ms": chat_result.latency_ms,
            "request": chat_result.raw_request,
            "response": chat_result.raw_response,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")

    def log_event(self, name: str, payload: dict) -> None:
        line = {"kind": "event", "name": name, "ts": _utc_now().isoformat(), "payload": payload}
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")

    def finish(self) -> TraceRef:
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"kind": "run_end", "ts": _utc_now().isoformat()}, ensure_ascii=False) + "\n")
        return TraceRef(local_path=str(self._path))


class LocalJsonlTracer:
    def __init__(self, traces_dir: str | Path = "traces"):
        self._dir = Path(traces_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def start_run(self, run_id: str, metadata: dict) -> _LocalRunHandle:
        path = self._dir / f"{run_id}.jsonl"
        return _LocalRunHandle(run_id, path, metadata)


# --- Langfuse best-effort mirror ---------------------------------------------------------


class _LangfuseRunHandle:
    def __init__(self, local: _LocalRunHandle, lf_trace: Any | None):
        self._local = local
        self._lf_trace = lf_trace

    def log_chat(self, chat_result: ChatResult, *, note: str = "") -> None:
        self._local.log_chat(chat_result, note=note)
        if self._lf_trace is None:
            return
        try:
            self._lf_trace.span(
                name=chat_result.label,
                input=chat_result.raw_request,
                output=chat_result.raw_response,
                start_time=chat_result.ts,
                metadata={"note": note, "session_id": chat_result.session_id,
                          "latency_ms": chat_result.latency_ms},
            )
        except Exception as exc:  # best-effort: Langfuse никогда не валит прогон
            logger.warning("Langfuse span logging failed (non-fatal): %s", exc)

    def log_event(self, name: str, payload: dict) -> None:
        self._local.log_event(name, payload)
        if self._lf_trace is None:
            return
        try:
            self._lf_trace.event(name=name, metadata=payload)
        except Exception as exc:
            logger.warning("Langfuse event logging failed (non-fatal): %s", exc)

    def finish(self) -> TraceRef:
        ref = self._local.finish()
        if self._lf_trace is None:
            return ref
        try:
            self._lf_trace.update(output={"local_trace": ref.local_path})
            url = self._lf_trace.get_trace_url()
            return TraceRef(local_path=ref.local_path, langfuse_url=url)
        except Exception as exc:
            logger.warning("Langfuse finish/flush failed (non-fatal), falling back to local-only: %s", exc)
            return ref


class CompositeTracer:
    """Default тул-трейсер: local JSONL всегда + Langfuse, если сконфигурирован.

    Инструментируем СВОИ вызовы к target.py (клиентская сторона), не сам стенд —
    поэтому не требует никаких правок/редеплоя target-стенда и работает с любым
    target-агнотстик таргетом.
    """

    def __init__(self, traces_dir: str | Path = "traces"):
        self._local = LocalJsonlTracer(traces_dir)
        self._langfuse_client = None
        pub, sec = os.environ.get("LANGFUSE_PUBLIC_KEY"), os.environ.get("LANGFUSE_SECRET_KEY")
        if pub and sec:
            try:
                from langfuse import (
                    Langfuse,  # optional dependency — не ставим требованием
                )

                self._langfuse_client = Langfuse(
                    public_key=pub, secret_key=sec,
                    host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
                )
            except Exception as exc:
                logger.warning("Langfuse недоступен (пакет не установлен или ошибка init) — "
                                "работаем на локальном JSONL-трейсере: %s", exc)
                self._langfuse_client = None

    def start_run(self, run_id: str, metadata: dict) -> _LangfuseRunHandle:
        local_handle = self._local.start_run(run_id, metadata)
        lf_trace = None
        if self._langfuse_client is not None:
            try:
                lf_trace = self._langfuse_client.trace(
                    name=metadata.get("attack_id", "attack_run"), id=run_id, metadata=metadata
                )
            except Exception as exc:
                logger.warning("Langfuse trace() failed (non-fatal): %s", exc)
        return _LangfuseRunHandle(local_handle, lf_trace)


def new_run_id() -> str:
    return uuid.uuid4().hex[:16]
