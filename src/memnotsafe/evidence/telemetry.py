"""src/memnotsafe/evidence/telemetry.py — контракт внешней телеметрии
context_tool_evidence (P09-full, фича 010).

Модуль определяет СТРОГУЮ схему v1 записи, разделяющей четыре сущности,
которые запрещено подменять друг другом:

0. expected_effect — декларация цели (GoalContract); в этот слот НЕ входит:
   это намерение модели, а не наблюдение;
1. effective_context — ФАКТ: что реально попало в контекст финалайзера
   жертвы (выборка стенда, а не интенция);
2. adapter_tool_calls — аргументы, ПОДГОТОВЛЕННЫЕ адаптером к вызову
   инструмента;
3. actual_tool_calls — аргументы, РЕАЛЬНО полученные инструментом.

Корреляция: каждое наблюдение несёт session_id, actor_user_id, phase и
call_id. Первичный ключ корреляции — call_id; case_marker НЕ заменяет
call_id и в записи инструмента присутствует только когда применим.

Фазы — ровно три, данные разных фаз неявно не объединяются:
m1-delivery (события доставки), m2-pretrigger (СОСТОЯНИЕ между снимками
M1 и M2 — собственных событий не имеет, константа резервируется схемой),
m3-trigger-finalize (trigger-фаза жертвы). Фазовая принадлежность сессий —
прерогатива раннера: сборщик берёт её из wire-транскрипта, никогда из
событий адаптера.

Граница честности: «инструмент не вызывался» доказано ТОЛЬКО при полном
tool-логе И живом heartbeat канала (proven_no_call); любое другое
состояние канала оставляет вывод UNKNOWN. Отсутствие канала/секции —
unavailable, не «отсутствие события».

chat_prompt_revision: None = неизвестно; реконструировать задним числом
запрещено. Стенд молча не меняется: адаптер отдаёт сырые ФАКТЫ
(context_tool_evidence()), сборка и валидация — на этом слое; требования
к будущему каналу стендa — в handoff владельцу (specs/010, checkpoint).
"""

from __future__ import annotations

TELEMETRY_SCHEMA_VERSION = 1

PHASE_M1_DELIVERY = "m1-delivery"
PHASE_M2_PRETRIGGER = "m2-pretrigger"
PHASE_M3_TRIGGER_FINALIZE = "m3-trigger-finalize"
TELEMETRY_PHASES = (PHASE_M1_DELIVERY, PHASE_M2_PRETRIGGER, PHASE_M3_TRIGGER_FINALIZE)

# Единственный допустимый источник effective_context — внешняя телеметрия
# стенда (в offline-путях — собственные факты адаптера). Ни декларация
# модели, ни реконструкция значения не допускаются.
SOURCE_EXTERNAL_TELEMETRY = "external_telemetry"

_CALL_KEYS = ("call_id", "session_id", "actor_user_id", "phase", "tool", "args", "case_marker")
_RECORD_KEYS = ("record_id", "fragment", "truncated", "scope", "source_user")
_CONTEXT_KEYS = ("phase", "session_id", "actor_user_id", "source", "records")
_CHANNEL_KEYS = ("heartbeat_alive", "heartbeat_counter")
_TOP_KEYS = (
    "schema_version",
    "effective_context",
    "actual_tool_calls",
    "adapter_tool_calls",
    "tool_log_complete",
    "channel",
    "stand_version",
    "chat_prompt_revision",
)


class TelemetryError(ValueError):
    """Контрактное нарушение записи телеметрии: чужая схема, неизвестные
    ключи, неверные типы, пустой/дублирующийся call_id. Диагностическая
    ошибка, не сырой краш."""


def _non_empty_str(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise TelemetryError(f"телеметрия: {what} обязан быть непустой строкой, получено {value!r}")
    return value


def _strict_bool(value: object, what: str) -> bool:
    # 1/0 и другие правдоподобные суррогаты запрещены: канал обязан сказать
    # ровно True/False, иначе это не телеметрия, а её имитация.
    if not isinstance(value, bool):
        raise TelemetryError(f"телеметрия: {what} обязан быть bool, получено {value!r}")
    return value


def _int_ge(value: object, minimum: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TelemetryError(f"телеметрия: {what} обязан быть целым >= {minimum}, получено {value!r}")
    return value


def _str_or_none(value: object, what: str) -> str | None:
    if value is None:
        return None
    return _non_empty_str(value, what)


def _parse_tool_call(raw: object, what: str, seen_call_ids: set[str]) -> dict:
    if not isinstance(raw, dict):
        raise TelemetryError(f"телеметрия: элемент {what} обязан быть JSON-объектом, получено {type(raw).__name__}")
    unknown = [k for k in raw if k not in _CALL_KEYS]
    if unknown:
        raise TelemetryError(f"телеметрия: {what}: неизвестные ключи {sorted(unknown)}")
    call_id = _non_empty_str(raw.get("call_id"), f"{what}.call_id")
    if call_id in seen_call_ids:
        raise TelemetryError(f"телеметрия: {what}: дублирующийся call_id {call_id!r}")
    seen_call_ids.add(call_id)
    phase = raw.get("phase")
    if phase not in TELEMETRY_PHASES:
        raise TelemetryError(
            f"телеметрия: {what}.call_id={call_id!r}: phase {phase!r} вне известных фаз {list(TELEMETRY_PHASES)}"
        )
    args = raw.get("args")
    if args is not None and not isinstance(args, dict):
        raise TelemetryError(f"телеметрия: {what}.call_id={call_id!r}: args обязан быть объектом или null")
    return {
        "call_id": call_id,
        "session_id": _non_empty_str(raw.get("session_id"), f"{what}.session_id"),
        "actor_user_id": _non_empty_str(raw.get("actor_user_id"), f"{what}.actor_user_id"),
        "phase": phase,
        "tool": _non_empty_str(raw.get("tool"), f"{what}.tool"),
        "args": args,
        "case_marker": _str_or_none(raw.get("case_marker"), f"{what}.case_marker"),
    }


def _parse_context_section(raw: object, what: str) -> dict:
    if not isinstance(raw, dict):
        raise TelemetryError(f"телеметрия: секция {what} обязана быть JSON-объектом")
    unknown = [k for k in raw if k not in _CONTEXT_KEYS]
    if unknown:
        raise TelemetryError(f"телеметрия: {what}: неизвестные ключи {sorted(unknown)}")
    phase = raw.get("phase")
    if phase not in TELEMETRY_PHASES:
        raise TelemetryError(f"телеметрия: {what}: phase {phase!r} вне известных фаз {list(TELEMETRY_PHASES)}")
    source = raw.get("source")
    if source != SOURCE_EXTERNAL_TELEMETRY:
        raise TelemetryError(
            f"телеметрия: {what}: source обязан быть {SOURCE_EXTERNAL_TELEMETRY!r}, получено {source!r} "
            "(эффективный контекст — это наблюдение, не декларация)"
        )
    raw_records = raw.get("records")
    if not isinstance(raw_records, list):
        raise TelemetryError(f"телеметрия: {what}.records обязан быть списком")
    records: list[dict] = []
    for idx, rec in enumerate(raw_records):
        if not isinstance(rec, dict):
            raise TelemetryError(f"телеметрия: {what}.records[{idx}] обязан быть JSON-объектом")
        unknown = [k for k in rec if k not in _RECORD_KEYS]
        if unknown:
            raise TelemetryError(f"телеметрия: {what}.records[{idx}]: неизвестные ключи {sorted(unknown)}")
        # фикс приёмки: неправильный тип fragment НЕ приводится к пустой строке —
        # обрезанный/нечитаемый фрагмент обязан остаться фактом источника
        fragment = rec.get("fragment")
        if not isinstance(fragment, str):
            raise TelemetryError(
                f"телеметрия: {what}.records[{idx}].fragment обязан быть строкой, получено {type(fragment).__name__}"
            )
        records.append(
            {
                "record_id": _non_empty_str(rec.get("record_id"), f"{what}.records[{idx}].record_id"),
                "fragment": fragment,
                "truncated": _strict_bool(rec.get("truncated"), f"{what}.records[{idx}].truncated"),
                "scope": _str_or_none(rec.get("scope"), f"{what}.records[{idx}].scope"),
                "source_user": _str_or_none(rec.get("source_user"), f"{what}.records[{idx}].source_user"),
            }
        )
    return {
        "phase": phase,
        "session_id": _non_empty_str(raw.get("session_id"), f"{what}.session_id"),
        "actor_user_id": _non_empty_str(raw.get("actor_user_id"), f"{what}.actor_user_id"),
        "source": source,
        "records": records,
    }


def parse_context_tool_evidence(raw: object) -> dict:
    """Валидирует запись телеметрии по строгой схеме v1 и возвращает
    нормализованный dict. Любое отклонение — TelemetryError (контрактная
    ошибка, видная replay), а не тихий пропуск и не сырой краш.

    Строгость (фикс приёмки RETURN_FOR_FIX d09299a): ВСЕ ключи верхнего
    уровня обязательны — отсутствующий ключ ОТЛИЧАЕТСЯ от явного null.
    Явный null легитимен только там, где он означает честное «недоступно/
    неизвестно» (effective_context, stand_version, chat_prompt_revision,
    args, case_marker, scope, source_user); неправильный тип fragment
    НЕ превращается в пустую строку."""
    if not isinstance(raw, dict):
        raise TelemetryError(
            f"телеметрия: запись обязана быть JSON-объектом, получено {type(raw).__name__}"
        )
    unknown = [k for k in raw if k not in _TOP_KEYS]
    if unknown:
        raise TelemetryError(f"телеметрия: неизвестные ключи верхнего уровня {sorted(unknown)}")
    missing = [k for k in _TOP_KEYS if k not in raw]
    if missing:
        # отсутствующее поле — не «неизвестно», а неполная запись: канал
        # обязан сказать явный null, если значение недоступно
        raise TelemetryError(f"телеметрия: отсутствуют обязательные ключи {sorted(missing)}")
    version = raw.get("schema_version")
    if isinstance(version, bool) or version != TELEMETRY_SCHEMA_VERSION:
        raise TelemetryError(
            f"телеметрия: schema_version={version!r} не поддерживается (ожидается {TELEMETRY_SCHEMA_VERSION})"
        )

    eff = raw.get("effective_context")
    if eff is not None:
        if not isinstance(eff, list):
            raise TelemetryError(
                f"телеметрия: effective_context обязан быть списком секций или null, получено {type(eff).__name__}"
            )
        eff = [_parse_context_section(section, f"effective_context[{i}]") for i, section in enumerate(eff)]

    actual: list[dict] = []
    seen_actual: set[str] = set()
    raw_actual = raw.get("actual_tool_calls")
    if not isinstance(raw_actual, list):
        raise TelemetryError("телеметрия: actual_tool_calls обязан быть списком")
    for item in raw_actual:
        actual.append(_parse_tool_call(item, "actual_tool_calls", seen_actual))

    prepared: list[dict] = []
    seen_prepared: set[str] = set()
    raw_prepared = raw.get("adapter_tool_calls")
    if not isinstance(raw_prepared, list):
        raise TelemetryError("телеметрия: adapter_tool_calls обязан быть списком")
    for item in raw_prepared:
        prepared.append(_parse_tool_call(item, "adapter_tool_calls", seen_prepared))

    channel_raw = raw.get("channel")
    if not isinstance(channel_raw, dict):
        raise TelemetryError("телеметрия: channel обязан быть JSON-объектом")
    unknown = [k for k in channel_raw if k not in _CHANNEL_KEYS]
    if unknown:
        raise TelemetryError(f"телеметрия: channel: неизвестные ключи {sorted(unknown)}")
    channel = {
        "heartbeat_alive": _strict_bool(channel_raw.get("heartbeat_alive"), "channel.heartbeat_alive"),
        "heartbeat_counter": _int_ge(channel_raw.get("heartbeat_counter"), 0, "channel.heartbeat_counter"),
    }

    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "effective_context": eff,
        "actual_tool_calls": actual,
        "adapter_tool_calls": prepared,
        "tool_log_complete": _strict_bool(raw.get("tool_log_complete"), "tool_log_complete"),
        "channel": channel,
        "stand_version": _str_or_none(raw.get("stand_version"), "stand_version"),
        "chat_prompt_revision": _str_or_none(raw.get("chat_prompt_revision"), "chat_prompt_revision"),
    }


def proven_no_call(record: dict) -> bool:
    """"Инструмент не вызывался" — доказано ТОЛЬКО при полном tool-логе
    и живом heartbeat. Всё остальное (неполный лог, мёртвый канал,
    неизвестное состояние) возвращает False: вывод запрещён, остаётся
    UNKNOWN. Запись предполагается провалидированной
    (parse_context_tool_evidence); на сыром объекте возвращается False."""
    if not isinstance(record, dict) or record.get("schema_version") != TELEMETRY_SCHEMA_VERSION:
        return False
    return (
        record.get("actual_tool_calls") == []
        and record.get("tool_log_complete") is True
        and isinstance(record.get("channel"), dict)
        and record["channel"].get("heartbeat_alive") is True
    )


def adapter_actual_divergence(record: dict) -> list[dict]:
    """Явные расхождения подготовленных и фактических аргументов по call_id:
    context_mismatch (совпал call_id, но разошлись session_id/actor_user_id/
    phase/tool — фикс приёмки: call_id-совпадение обязан также Согласовать
    контекстные поля), args_mismatch (контекст сошёлся, args различаются),
    actual_without_adapter / prepared_without_actual. Список может быть
    пуст — расхождений нет; отсутствие секций НЕ сглаживается."""
    if not isinstance(record, dict):
        return []
    prepared = {c["call_id"]: c for c in record.get("adapter_tool_calls") or [] if isinstance(c, dict)}
    actual = {c["call_id"]: c for c in record.get("actual_tool_calls") or [] if isinstance(c, dict)}
    out: list[dict] = []
    for call_id, a in actual.items():
        p = prepared.get(call_id)
        if p is None:
            out.append({"kind": "actual_without_adapter", "call_id": call_id})
            continue
        context_fields = ("session_id", "actor_user_id", "phase", "tool")
        mismatched = [f for f in context_fields if p.get(f) != a.get(f)]
        if mismatched:
            # совпал только call_id — этого недостаточно: вызов с тем же id,
            # но в другой сессии/фазе/у актёра/у другого инструмента — РАЗНЫЙ вызов
            out.append({"kind": "context_mismatch", "call_id": call_id, "fields": mismatched})
        elif p.get("args") != a.get("args"):
            out.append(
                {
                    "kind": "args_mismatch",
                    "call_id": call_id,
                    "prepared_args": p.get("args"),
                    "actual_args": a.get("args"),
                }
            )
    for call_id in prepared:
        if call_id not in actual:
            out.append({"kind": "prepared_without_actual", "call_id": call_id})
    return out


# Транскрипт раннера — единственный авторитет фазовой принадлежности сессий.
_TRANSCRIPT_PHASE_MAP = {
    "delivery": PHASE_M1_DELIVERY,
    "trigger": PHASE_M3_TRIGGER_FINALIZE,
}


def session_phases_from_transcript(transcript: dict | None) -> dict[str, str]:
    """session_id → фаза телеметрии по wire-транскрипту раннера.
    baseline-сессии сюда не попадают (их место — excluded_sessions_from_transcript);
    сессии без атрибуции не выдумываются."""
    out: dict[str, str] = {}
    for message in (transcript or {}).get("messages") or []:
        if not isinstance(message, dict):
            continue
        phase = _TRANSCRIPT_PHASE_MAP.get(message.get("phase"))
        sid = message.get("session_id")
        if phase and sid and sid not in out:
            out[sid] = phase
    return out


def baseline_sessions_from_transcript(transcript: dict | None) -> frozenset[str]:
    """session_id baseline-сессий: раннер знает их не-атакующую роль;
    сборщик исключает их ЯВНО (по решению раннера), а не молча."""
    out: set[str] = set()
    for message in (transcript or {}).get("messages") or []:
        if not isinstance(message, dict):
            continue
        if message.get("phase") == "baseline" and message.get("session_id"):
            out.add(message["session_id"])
    return frozenset(out)


def build_context_tool_evidence(
    adapter_facts: dict,
    *,
    session_phase: dict[str, str],
    excluded_sessions: frozenset[str] = frozenset(),
) -> dict:
    """Собирает parse-ready запись из сырых фактов адаптера. Формат фактов
    (duck-typed контракт адаптеров, mock — эталонная реализация):

        {
          "effective_context_by_session": {sid: {"actor_user_id", "records": [
              {"record_id", "fragment", "truncated", "scope", "source_user"}]}},
          "actual_tool_calls_by_session":   {sid: [{"call_id", "tool", "args",
              "actor_user_id", "case_marker"?}]},
          "prepared_tool_calls_by_session": {sid: [...]},  # тот же формат
          "tool_log_complete": bool, "heartbeat_alive": bool,
          "heartbeat_counter": int, "stand_version": str|None,
          "chat_prompt_revision": str|None,
        }

    Консерватизм (фикс приёмки RETURN_FOR_FIX d09299a): наблюдения сессий,
    у которых НЕТ фазовой атрибуции и которые не исключены раннером явно
    (excluded_sessions — baseline), НЕ выбрасываются молча — сборщик
    поднимает TelemetryError, и кампания честно переводит слот в
    unavailable с причиной. Иначе реальный вызов мог бы исчезнуть из
    записи при tool_log_complete=True — «доказанное отсутствие вызовов»
    из потерянных данных. Результат проходит
    parse_context_tool_evidence: сборщик не может выдать схему, которую
    читатель отвергнет."""
    if not isinstance(adapter_facts, dict):
        raise TelemetryError(
            f"факты адаптера обязаны быть JSON-объектом, получено {type(adapter_facts).__name__}"
        )

    # --- консервативная проверка атрибуции ДО всякой сборки
    known = set(session_phase) | set(excluded_sessions)
    unattributed: list[str] = []
    for field in ("effective_context_by_session", "actual_tool_calls_by_session", "prepared_tool_calls_by_session"):
        raw = adapter_facts.get(field) or {}
        if not isinstance(raw, dict):
            raise TelemetryError(f"{field} обязан быть JSON-объектом")
        for sid, payload in raw.items():
            has_data = bool(payload) if not isinstance(payload, dict) or field != "effective_context_by_session" else bool(payload.get("records"))
            if sid not in known and has_data and sid not in unattributed:
                unattributed.append(sid)
    if unattributed:
        raise TelemetryError(
            "телеметрия: сессии без фазовой атрибуции содержат наблюдения "
            f"{sorted(unattributed)} — выбросить их и объявить лог полным нельзя; "
            "нужна атрибуция раннера либо явное исключение (baseline)"
        )

    eff_sections: list[dict] = []
    raw_eff = adapter_facts.get("effective_context_by_session") or {}
    for sid, section in raw_eff.items():
        phase = session_phase.get(sid)
        if phase is None:
            # sid в excluded_sessions: раннер явно исключил (baseline — не атака)
            continue
        if not isinstance(section, dict):
            raise TelemetryError(f"эффективный контекст сессии {sid!r} обязан быть JSON-объектом")
        eff_sections.append(
            {
                "phase": phase,
                "session_id": sid,
                "actor_user_id": section.get("actor_user_id"),
                "source": SOURCE_EXTERNAL_TELEMETRY,
                "records": list(section.get("records") or []),
            }
        )

    def _calls(field: str) -> list[dict]:
        raw = adapter_facts.get(field) or {}
        out: list[dict] = []
        for sid, calls in raw.items():
            phase = session_phase.get(sid)
            if phase is None:
                continue
            for call in calls or []:
                out.append({**call, "session_id": sid, "phase": phase})
        return out

    record = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "effective_context": eff_sections or None,
        "actual_tool_calls": _calls("actual_tool_calls_by_session"),
        "adapter_tool_calls": _calls("prepared_tool_calls_by_session"),
        "tool_log_complete": adapter_facts.get("tool_log_complete"),
        "channel": {
            "heartbeat_alive": adapter_facts.get("heartbeat_alive"),
            "heartbeat_counter": adapter_facts.get("heartbeat_counter"),
        },
        "stand_version": adapter_facts.get("stand_version"),
        "chat_prompt_revision": adapter_facts.get("chat_prompt_revision"),
    }
    return parse_context_tool_evidence(record)
