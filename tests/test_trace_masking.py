"""tests/test_trace_masking.py — карточка P11-2: маскирование при экспорте.

Граница честности: локальный events.jsonl пишется ПОЛНЫМ (он и есть
доказательство), маскируется только пакет, уходящий наружу — в приёмник
или в спул (утечка спула ≠ утечка секретов). Предмет измерения (payload
атаки / effective_context) маскером не трогается — он не структурное поле.

Все секретоподобные значения ниже — ЗАВЕДОМЫЕ ПЛЕЙСХОЛДЕРЫ для проверки
правил, не реальные секреты.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from memnotsafe.tracing.exporter import TraceExporter
from memnotsafe.tracing.masking import SENSITIVE_KEYS, mask_event
from memnotsafe.tracing.recorder import TraceRecorder, read_events_jsonl

# <MASKED:<имя-правила>:<sha8-от-значения>> — детерминированная форма:
# необратима, но склеивает повторы одного значения.
MASKED_RE = re.compile(r"^<MASKED:(?P<rule>[a-z0-9_]+):[0-9a-f]{8}>$")

# Плейсхолдеры под правила карточки (§2): ключи, паттерны, PII.
KEY_SECRET = "AQVNTESTPLACEHOLDER0001"
SK_SECRET = "sk-TESTPLACEHOLDER1234"
BEARER_SECRET = "Bearer TESTTOKEN999"
JWT_SECRET = "eyJTESTHEADER.eyJTESTPAYLOAD.TESTSIG"
EMAIL_PII = "user1005@example.com"
PHONE_PII = "+7 495 123 45 67"


class _DeadSink:
    """Приёмник, всегда падающий (транспорт недоступен)."""

    def send(self, batch: list[dict]) -> None:
        raise ConnectionError("sink down")


class _CollectingSink:
    """Живой приёмник: собирает пакеты без сбоев."""

    def __init__(self) -> None:
        self.received: list[list[dict]] = []

    def send(self, batch: list[dict]) -> None:
        self.received.append(list(batch))


def _masked_form(value: object) -> re.Match | None:
    """value обязан быть строкой ровно формы <MASKED:rule:sha8>."""
    return MASKED_RE.match(value) if isinstance(value, str) else None


def test_key_rules_mask_all_listed_names() -> None:
    """PASS_IF 3a: каждое имя ключа из списка (case-insensitive) маскирует
    значение; нестроковое значение под чувствительным ключом тоже маскируется."""
    for key in SENSITIVE_KEYS:
        masked = mask_event({"arguments": {key: KEY_SECRET}})
        got = masked["arguments"][key]
        m = _masked_form(got)
        assert m is not None, (key, got)
        assert m.group("rule") == key
        assert got != KEY_SECRET

    # те же имена в другом регистре ключа и в detail/metadata/errors
    for field in ("detail", "metadata", "errors"):
        masked = mask_event({field: {"Api_Key": KEY_SECRET}})
        m = _masked_form(masked[field]["Api_Key"])
        assert m is not None and m.group("rule") == "api_key", field

    # нестроковое значение под чувствительным ключом — тоже маска
    m = _masked_form(mask_event({"arguments": {"password": 12345}})["arguments"]["password"])
    assert m is not None and m.group("rule") == "password"


def test_pattern_rules_mask_secret_forms() -> None:
    """PASS_IF 3a: строковые паттерны §2 (sk-, Bearer, JWT) маскируются
    внутри структурных полей — с именем правила в форме."""
    masked = mask_event(
        {
            "detail": {"a": f"ключ {SK_SECRET} утёк"},
            "arguments": {"b": f"заголовок {BEARER_SECRET} тут"},
            "errors": [f"auth failed on {JWT_SECRET}"],
        }
    )
    for got in (
        masked["detail"]["a"],
        masked["arguments"]["b"],
        masked["errors"][0],
    ):
        assert isinstance(got, str)
    m = _masked_form(re.search(r"<MASKED:sk_key:[0-9a-f]{8}>", masked["detail"]["a"]).group(0))
    assert m is not None and m.group("rule") == "sk_key"
    assert SK_SECRET not in masked["detail"]["a"]

    m = _masked_form(re.search(r"<MASKED:bearer:[0-9a-f]{8}>", masked["arguments"]["b"]).group(0))
    assert m is not None and m.group("rule") == "bearer"
    assert BEARER_SECRET not in masked["arguments"]["b"]

    m = _masked_form(re.search(r"<MASKED:jwt:[0-9a-f]{8}>", masked["errors"][0]).group(0))
    assert m is not None and m.group("rule") == "jwt"
    assert JWT_SECRET not in masked["errors"][0]


def test_pii_forms_masked_only_in_metadata() -> None:
    """PASS_IF 3a/§2.3: email/phone маскируются ТОЛЬКО в metadata — в
    arguments/detail это предмет измерения, остаётся как есть."""
    masked = mask_event(
        {
            "metadata": {"owner": f"контакт {EMAIL_PII}, тел {PHONE_PII}"},
            "detail": {"text": f"контакт {EMAIL_PII}, тел {PHONE_PII}"},
            "arguments": {"note": EMAIL_PII},
        }
    )
    assert EMAIL_PII not in masked["metadata"]["owner"]
    assert PHONE_PII not in masked["metadata"]["owner"]
    assert "email" in re.search(r"<MASKED:email:[0-9a-f]{8}>", masked["metadata"]["owner"]).group(0)
    assert "phone" in re.search(r"<MASKED:phone:[0-9a-f]{8}>", masked["metadata"]["owner"]).group(0)

    # тот же текст вне metadata не тронут
    assert masked["detail"]["text"] == f"контакт {EMAIL_PII}, тел {PHONE_PII}"
    assert masked["arguments"]["note"] == EMAIL_PII


def test_same_secret_same_digest_different_secret_different_digest() -> None:
    """PASS_IF 3b: повторы одного значения склеиваются одинаковым digest,
    разные значения дают разные digest (корреляция без восстановления)."""
    first = mask_event({"arguments": {"api_key": KEY_SECRET}})
    second = mask_event({"detail": {"nested": [{"api_key": KEY_SECRET}]}})
    assert first["arguments"]["api_key"] == second["detail"]["nested"][0]["api_key"]

    other = mask_event({"arguments": {"api_key": "AQVNTESTPLACEHOLDER0002"}})
    assert other["arguments"]["api_key"] != first["arguments"]["api_key"]

    sk1 = mask_event({"detail": {"x": SK_SECRET}})
    sk2 = mask_event({"detail": {"x": "sk-TESTPLACEHOLDER6789"}})
    assert sk1["detail"]["x"] != sk2["detail"]["x"]


def test_deep_nested_structures_are_masked() -> None:
    """PASS_IF 3c: маскирование в глубину — вложенные dict/list в
    arguments/detail, строка-паттерн на дне структуры."""
    event = {
        "arguments": {
            "l1": {
                "l2": [
                    {"session_token": KEY_SECRET},
                    {"inner": f"…{SK_SECRET}…"},
                ]
            }
        },
        "detail": {"chain": [{"deep": {"cookie": KEY_SECRET}}]},
    }
    masked = mask_event(event)
    m = _masked_form(masked["arguments"]["l1"]["l2"][0]["session_token"])
    assert m is not None and m.group("rule") == "session_token"
    assert SK_SECRET not in masked["arguments"]["l1"]["l2"][1]["inner"]
    m = _masked_form(masked["detail"]["chain"][0]["deep"]["cookie"])
    assert m is not None and m.group("rule") == "cookie"
    assert KEY_SECRET not in json.dumps(masked, ensure_ascii=False)


def test_local_jsonl_full_export_masked(tmp_path: Path) -> None:
    """PASS_IF 3d: локальный events.jsonl содержит значение БЕЗ маски,
    экспортный пакет — с маской (граница честности соблюдена)."""
    recorder = TraceRecorder(tmp_path / "events.jsonl")
    sink = _CollectingSink()
    exporter = TraceExporter(sink, batch_size=10, spool_dir=tmp_path / "spool")
    event = {
        "event_id": "evt-0001",
        "event": "tool_call",
        "case_id": "CASE-P112",
        "session_id": "sess-1",
        "arguments": {"api_key": KEY_SECRET, "note": "обычный текст"},
    }

    recorder.record_raw(event)  # источник истины — первым, ПОЛНЫМ
    exporter.record(event)      # наблюдатель — вторым, маскированным
    exporter.flush()

    recorded = read_events_jsonl(tmp_path / "events.jsonl")
    assert recorded[0]["arguments"]["api_key"] == KEY_SECRET  # JSONL без маски

    batch = sink.received[0]
    assert _masked_form(batch[0]["arguments"]["api_key"]) is not None
    assert batch[0]["arguments"]["api_key"] != KEY_SECRET
    assert batch[0]["arguments"]["note"] == "обычный текст"
    assert KEY_SECRET not in json.dumps(batch, ensure_ascii=False)


def test_spool_stores_masked_batches(tmp_path: Path) -> None:
    """PASS_IF 3e: спул P11-1 хранит ЗАМАСКИРОВАННЫЕ пакеты — утеча спула
    не равна утечке секретов."""
    exporter = TraceExporter(_DeadSink(), batch_size=2, spool_dir=tmp_path / "spool")
    for i in (1, 2):
        exporter.record(
            {
                "event_id": f"evt-{i:04d}",
                "event": "state_change",
                "case_id": "CASE-P112",
                "detail": {"api_key": KEY_SECRET, "trace": f"…{SK_SECRET}…"},
            }
        )

    spool_files = sorted((tmp_path / "spool").glob("batch-*.json"))
    assert len(spool_files) == 1
    text = spool_files[0].read_text(encoding="utf-8")
    assert KEY_SECRET not in text
    assert SK_SECRET not in text
    batch = json.loads(text)
    assert _masked_form(batch[0]["detail"]["api_key"]) is not None
    assert exporter.pending == 2


def test_experiment_payload_passes_unmasked() -> None:
    """PASS_IF 3f: payload атаки / effective_context — предмет измерения,
    маскер по структурным полям их не трогает (тело эксперимента полное)."""
    event = {
        "event_id": "evt-0009",
        "event": "llm_decision",
        "case_id": "CASE-P112",
        "payload": {"text": f"атака с {SK_SECRET} и {BEARER_SECRET}"},
        "effective_context": {"prompt": f"включая {JWT_SECRET}"},
        "memory_refs": ["rec-1005"],
        "arguments": {"tool": "book"},
    }
    masked = mask_event(event)
    assert masked["payload"] == event["payload"]
    assert masked["effective_context"] == event["effective_context"]
    assert masked["memory_refs"] == ["rec-1005"]  # id, не контент
    assert masked["arguments"] == {"tool": "book"}


def test_mask_event_does_not_mutate_input() -> None:
    """Входное событие остаётся нетронутым (маска — новая структура):
    вызывающий (recorder уже записал полный JSONL) не получает побочных
    изменений своих dict'ов."""
    inner = {"api_key": KEY_SECRET}
    event = {"event_id": "evt-0010", "arguments": inner, "detail": {"l": [SK_SECRET]}}
    snapshot = json.dumps(event, ensure_ascii=False)

    masked = mask_event(event)

    assert json.dumps(event, ensure_ascii=False) == snapshot
    assert masked is not event
    assert masked["arguments"] is not inner
    assert masked["arguments"]["api_key"] != KEY_SECRET
