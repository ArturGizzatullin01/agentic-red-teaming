"""src/memnotsafe/tracing/langfuse_sink.py — реальный приёмник трасс: self-hosted Langfuse (P11-3).

Offline-часть карточки P11-3: код + тесты; live-поднятие Langfuse и гейт G2 —
отдельный шаг A0/владельца (compose-сниппет приложен артефактом в
handoff/inbox/langfuse-stack2-snippet.yml, НЕ в репозитории).

Ключи — ТОЛЬКО из env (LANGFUSE_HOST / LANGFUSE_PUBLIC_KEY /
LANGFUSE_SECRET_KEY) или явных параметров конструктора; в репо и артефактах
их нет. До sink события идут уже замаскированными (P11-2: маска на входе
TraceExporter.record) — но и сам приёмник ничего секретного никуда не пишет.

Семантика (контракт P11-1 — «отказ приёмника»):
  - send() = ОДИН POST {LANGFUSE_HOST}/api/public/ingestion, Basic auth
    (public key : secret key), тело {"batch": [...]}; таймаут ≤ 5 с
    (DEFAULT_TIMEOUT_S, параметр конструктора);
  - HTTP 4xx/5xx и сетевые ошибки -> исключение наружу (urllib поднимает
    HTTPError/URLError сам — их и ждёт экспортёр);
  - 2xx -> успех;
  - ретраев ВНУТРИ send() нет сознательно: ретрай — забота экспортёра
    (спул + backoff), иначе двойная доставка.

Маппинг в ingestion API v3 (форма тел сверена со сгенерированными типами
официального langfuse-python SDK, Fern-модель ingestion):
  каждый элемент батча = {"type": "trace-create" | "event-create",
                          "id": <uuid>, "timestamp": <iso>, "body": {...}};
  run -> trace:      trace-create, body.id = run_id (одна кампания = один
                     trace; повторный trace-create с тем же id идемпотентен —
                     каждый пакет самоописан, replay спула безопасен);
  событие -> observation типа event-create (точечное событие, без
                     длительности): body.id = event_id, body.traceId = run_id,
                     body.name = тип события, body.startTime = timestamp
                     события, body.metadata = остальные (замаскированные)
                     поля события.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Mapping

from memnotsafe.tracing.exporter import TraceExporter

FLAG_VAR = "MEMNOTSAFE_TRACE_EXPORT"
HOST_VAR = "LANGFUSE_HOST"
PUBLIC_KEY_VAR = "LANGFUSE_PUBLIC_KEY"
SECRET_KEY_VAR = "LANGFUSE_SECRET_KEY"

INGESTION_PATH = "/api/public/ingestion"
DEFAULT_TIMEOUT_S = 5.0

# Поля события, уходящие в свои места ingestion-тела; остальное -> body.metadata.
_RESERVED_EVENT_FIELDS = frozenset({"event_id", "run_id", "event", "timestamp"})


def _trace_id(event: Mapping[str, Any]) -> str:
    """Идентификатор trace для события: run_id; запасной порядок раскрыт в хендофе."""
    return str(event.get("run_id") or event.get("case_id") or "unknown-run")


def build_ingestion_body(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Собрать элементы ingestion-батча из plain-dict событий трассы.

    Пакет самоописан: для каждого встретившегося run_id кладётся свой
    trace-create (дубль по id не создаёт второй trace), затем event-create
    на каждое событие. Функция чистая — используется и тестами формы.
    """
    items: list[dict[str, Any]] = []
    seen_runs: list[str] = []
    for event in events:
        run = _trace_id(event)
        if run not in seen_runs:
            seen_runs.append(run)
    for run in seen_runs:
        first_ts = next(
            (str(e.get("timestamp")) for e in events if _trace_id(e) == run and e.get("timestamp")),
            None,
        )
        items.append(
            {
                "type": "trace-create",
                "id": uuid.uuid4().hex,
                "timestamp": first_ts,
                "body": {"id": run, "name": run},
            }
        )
    for event in events:
        metadata = {
            key: value for key, value in event.items() if key not in _RESERVED_EVENT_FIELDS
        }
        items.append(
            {
                "type": "event-create",
                "id": uuid.uuid4().hex,
                "timestamp": str(event.get("timestamp")),
                "body": {
                    "id": event.get("event_id"),
                    "traceId": _trace_id(event),
                    "name": str(event.get("event") or "event"),
                    "startTime": event.get("timestamp"),
                    "metadata": metadata,
                },
            }
        )
    return items


class LangfuseTraceSink:
    """Приёмник пакетов событий для self-hosted Langfuse (контракт TraceSink)."""

    def __init__(
        self,
        *,
        host: str | None = None,
        public_key: str | None = None,
        secret_key: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        env: Mapping[str, str] | None = None,
    ) -> None:
        env_map = os.environ if env is None else env
        resolved = {
            HOST_VAR: host if host is not None else env_map.get(HOST_VAR),
            PUBLIC_KEY_VAR: public_key if public_key is not None else env_map.get(PUBLIC_KEY_VAR),
            SECRET_KEY_VAR: secret_key if secret_key is not None else env_map.get(SECRET_KEY_VAR),
        }
        missing = sorted(name for name, value in resolved.items() if not value)
        if missing:
            raise ValueError(
                f"LangfuseTraceSink: отсутствуют обязательные параметры/env: "
                f"{', '.join(missing)} (экспорт настроен, но ключей нет — "
                f"это ошибка конфигурации, а не тишина)"
            )
        if timeout_s <= 0 or timeout_s > DEFAULT_TIMEOUT_S:
            raise ValueError(
                f"timeout_s={timeout_s!r}: должен быть в (0, {DEFAULT_TIMEOUT_S}]"
            )
        self._url = str(resolved[HOST_VAR]).rstrip("/") + INGESTION_PATH
        self._timeout_s = timeout_s
        auth = base64.b64encode(
            f"{resolved[PUBLIC_KEY_VAR]}:{resolved[SECRET_KEY_VAR]}".encode("utf-8")
        ).decode()
        self._auth_header = f"Basic {auth}"

    def send(self, batch: list[dict[str, Any]]) -> None:
        """Один POST на ingestion; любое исключение = отказ приёмника (P11-1)."""
        payload = json.dumps(
            {"batch": build_ingestion_body(batch)}, ensure_ascii=False
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": self._auth_header,
            },
        )
        with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
            response.read()  # дочитать ответ, чтобы соединение закрылось чисто
            status = response.status
        if not 200 <= status < 300:  # на случай нестандартных кодов без исключения
            raise ConnectionError(f"langfuse ingestion: HTTP {status}")


def build_langfuse_exporter(
    spool_dir: str | Path,
    *,
    env: Mapping[str, str] | None = None,
) -> TraceExporter | None:
    """Собрать экспортёр по env; БЕЗ флага — None (ноль изменений поведения).

    Флаг MEMNOTSAFE_TRACE_EXPORT=1 включает экспорт; ключи Langfuse обязательны
    и проверяются здесь же — громкий ValueError при создании (не при send и не
    молчаливый None): настроенный, но сломанный экспорт должен быть виден сразу.
    """
    env_map = os.environ if env is None else env
    if env_map.get(FLAG_VAR) != "1":
        return None
    sink = LangfuseTraceSink(env=env_map)
    return TraceExporter(sink, spool_dir=Path(spool_dir))
