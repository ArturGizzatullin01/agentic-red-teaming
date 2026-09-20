"""src/memnotsafe/tracing/masking.py — маскирование чувствительных полей при
экспорте трасс (P11-2, MASTER-PLAN §6: «маскирование входов/metadata/errors →
утечка через вторичный канал», §7 P11 DoD: «чувствительные данные не утекают»).

Граница маскирования (карточка P11-2):
  - маскируется ТОЛЬКО экспортируемый пакет — после записи полного события
    в локальный events.jsonl (он и есть доказательство) и ДО отправки в
    приёмник/спул; спул хранит уже замаскированные пакеты, поэтому утечка
    спула не равна утечке секретов;
  - маскер работает по СТРУКТУРНЫМ полям события (arguments/detail/metadata/
    errors) — тело эксперимента (payload атаки, effective_context) предмет
    измерения и проходит наружу немаскированным; memory_refs — это id
    записей, не контент, и не трогается;
  - локальный events.jsonl маскированием не затрагивается вообще — маску
    получает копия события на входе экспортёра (P11-1 TraceExporter.record).

Правила (минимальный набор карточки §2):
  1. имена ключей (case-insensitive): password, token, secret, api_key,
     authorization, cookie, session_token — маскируется значение ЦЕЛИКОМ
     (нестроковое — по канонической JSON-форме);
  2. паттерны в строковых значениях структурных полей: sk-[A-Za-z0-9_-]{8,},
     Bearer\\s+\\S+, JWT-форма eyJ…\\.eyJ…\\.…;
  3. PII-формы (email, телефон с ведущим «+») — ТОЛЬКО внутри metadata
     (в payload атаки/arguments они — предмет измерения).

Подмена: <MASKED:<имя-правила>:<sha8-от-значения>> — необратимо (8 hex-символов
sha256 не восстанавливаются), но детерминизм digest'а позволяет склеивать
повторы одного значения в трейсе: digest — для корреляции, не для восстановления.
Маска — новая структура: входное событие не мутируется.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

# §2.1: имена ключей, значения которых маскируются целиком.
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "token",
        "secret",
        "api_key",
        "authorization",
        "cookie",
        "session_token",
    }
)

# §2.2: паттерны секретных форм в строках структурных полей.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sk_key", re.compile(r"sk-[A-Za-z0-9_-]{8,}")),
    ("bearer", re.compile(r"Bearer\s+\S+")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
)

# §2.3: PII-формы — применяются только внутри metadata. Телефон — с ведущим
# «+» (международная форма): не ловит числовые id в metadata как ложные
# срабатывания.
PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("phone", re.compile(r"\+\d[\d\s()-]{7,}\d")),
)

# Структурные поля события (схема tracing/events.py + plain-dict адаптеров):
# только их содержимое проходит маскирование; payload/effective_context
# (тело эксперимента) и memory_refs (id записей) не входят.
STRUCTURAL_FIELDS = ("arguments", "detail", "metadata", "errors")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _mask(rule: str, value: str) -> str:
    return f"<MASKED:{rule}:{_digest(value)}>"


def _canonical(value: Any) -> str:
    """Строковая форма значения для digest'а (нестроковые чувствительные
    значения тоже обязаны маскироваться и коррелироваться детерминированно)."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _mask_string(text: str, *, pii: bool) -> str:
    for name, pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m, _name=name: _mask(_name, m.group(0)), text)
    if pii:
        for name, pattern in PII_PATTERNS:
            text = pattern.sub(lambda m, _name=name: _mask(_name, m.group(0)), text)
    return text


def mask_value(value: Any, *, pii: bool = False) -> Any:
    """Глубокое маскирование значения структурного поля.

    pii=True разрешает ПРАВИЛА PII (§2.3) — выставляется только для поддерева
    metadata; чувствительные ключи (§2.1) и секретные паттерны (§2.2)
    применяются на любом уровне структурных полей.
    """
    if isinstance(value, str):
        return _mask_string(value, pii=pii)
    if isinstance(value, dict):
        masked: dict[Any, Any] = {}
        for key, item in value.items():
            key_name = key.lower() if isinstance(key, str) else None
            if key_name is not None and key_name in SENSITIVE_KEYS:
                masked[key] = _mask(key_name, _canonical(item))
            else:
                masked[key] = mask_value(
                    item, pii=pii or (key_name == "metadata")
                )
        return masked
    if isinstance(value, (list, tuple)):
        seq = [mask_value(item, pii=pii) for item in value]
        return seq if isinstance(value, list) else tuple(seq)
    return value


def mask_event(event: dict[str, Any]) -> dict[str, Any]:
    """Замаскированная КОПИЯ события для экспорта; вход не мутируется.

    Топ-уровень события (event_id/session_id/…/payload/effective_context/
    memory_refs) проходит как есть — маскируются только структурные поля
    из STRUCTURAL_FIELDS, metadata — дополнительно с PII-правилами.
    """
    masked = dict(event)
    for field in STRUCTURAL_FIELDS:
        value = masked.get(field)
        if value is not None:
            masked[field] = mask_value(value, pii=(field == "metadata"))
    return masked


def mask_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """mask_event для пакета (удобно точке отправки и тестам)."""
    return [mask_event(event) for event in events]
