"""src/memnotsafe/evidence/matching.py — нормализация текстовых свидетельств.

Единственная зона ответственности (контракт specs/002-evidence-integrity/
contracts/evidence-and-verdict.md): привести marker и текст evidence к общему
письму и сравнить подстрокой. Только текст: URL, ISIN, user_id и прочие
идентификаторы вызывающий код сравнивает отдельно и точно — утилита не гадает
по regex, что за строка ей передана, и не ветвится по смыслу.

Порядок нормализации внутри одного прохода: ANSI CSI -> поимённые кодовые
точки -> NFKC, и весь проход повторяется до фикспоинта. Почему именно так:
(1) удаление ZWSP/CSI СКЛЕИВАЕТ символы — ZWSP и CSI рвут combining-
последовательности (e + ZWSP + U+0301), и после склейки пара обязана
пройти Unicode-нормализацию до é; (2) NFKC до удаления CSI запрещён —
комбинирующая диакритика приклеивается к финальной букве последовательности
(m + U+0301 -> ḿ), ломая сам CSI. Отсюда же фикс-пойнт: один проход не
достаточен (fullwidth-формы NFKC сводит к ASCII только со второго CSI-прохода:
`ESC ［ 31 m`). Факты о NFKC (закреплены тестами): U+FF0D сводит к ASCII
сам, U+2011 — к U+2010, а U+2010–U+2012/…/U+2212 НЕ трогает, поэтому в
таблице обязаны быть ОБА конца U+2011→U+2010-цепочки. Дефисы сведены
поимённой таблицей, а не «диапазоном U+2010–U+FF0D»: правило аудита
запрещает вычищать диапазон целиком. Никакого casefold, транслитерации,
fuzzy и схлопывания обычных пробелов — регистр и пробелы значимы.

Завершимость цикла (идемпотентность — следствие: выходом цикла становится
строка, на которой весь проход тождественен). CSI-sub только удаляет, и
каждый матч содержит ESC; таблица удаляет ZWSP и заменяет поимённые дефисы
на ASCII '-' (замена не создаёт ни ZWSP, ни поимённых дефисов, ни ESC).
Если CSI-sub и таблица в проходе тождественны, выход прохода = NFKC(s) = s
по теореме замыкания Unicode — NFKC(NFKC(x)) == NFKC(x), а s уже является
NFKC-выходом (это стандартное свойство нормализации, от версии таблицы не
зависит); цикл выходит. Бесконечный цикл требовал бы бесконечных
срабатываний CSI-sub или таблицы, а каждое потребляет единицу конечного
ресурса: (a) ESC и ZWSP не производятся ни одним шагом конвейера — для
NFKC проверено полным перебором всех code points (Unicode 16.0.0,
`unicodedata.unidata_version`; свойство зависит от версии таблицы, способ
перепроверки — искать цель в NFKC(cp) по всему диапазону); (b) поимённые
дефисы и '[' появляются в NFKC-выходе только из не-стабильных
символов-источников (дефисы: U+2011, U+207B, U+208B, U+FE31, U+FE32,
U+FE58; '[': U+FE47, U+FF3B — перечень получен тем же перебором), а
не-стабильные символы по теореме замыкания ничем не производятся и
конечны во входе, поэтому замен дефисов конечное число, а новый '[' без
нового ESC CSI-sub'у ничего не даёт. Нетождественное срабатывание всегда
потребляет ресурс из (a)/(b), так что циклов одинаковой длины не
возникает и фикспоинт достижим.

CSI — минимальный набор по грамматике ECMA-48: ESC [ параметры 0x30–0x3F,
промежуточные байты 0x20–0x2F, финальный байт 0x40–0x7E. Удаляются: (1)
полные последовательности; (2) «оборванный» opener ESC [ params, ЗА которым
идёт другой ESC — семантика отмены реального терминала (новый ESC
прерывает накопление CSI); (3) одиночный ESC перед другим ESC — первый
исчезает. Ветки 2–3 работают на любом проходе цикла: без них голый ESC,
переживший удаление соседа, склеивает выжившую '[' в новый opener и
переинтерпретирует обычный текст (поймано фаззингом, см. тесты). Оборванный
opener в конце строки или перед обычным текстом (кириллица и пр. не
являются финальным байтом) остаётся как есть и не поглощает последующий
текст. OSC/DCS и прочие ANSI-виды не поддерживаются — задокументированный
минимум.

Совпадение текста ничего не говорит об adoption или composite success —
вердикт стадий остаётся за oracle'ами (принципы IV–V конституции).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from memnotsafe.evidence.snapshot import SystemSnapshot

# Поимённый список из контракта; ZWSP удаляется. НЕ диапазон — правило аудита.
_NAMED_TRANSLATION = str.maketrans(
    {
        "\u2010": "-",  # HYPHEN
        "\u2011": "-",  # NON-BREAKING HYPHEN — NFKC сводит его к U+2010, в таблице оба конца
        "\u2012": "-",  # FIGURE DASH
        "\u2013": "-",  # EN DASH
        "\u2014": "-",  # EM DASH
        "\u2015": "-",  # HORIZONTAL BAR
        "\u2212": "-",  # MINUS SIGN — NFKC его не трогает
        "\uff0d": "-",  # FULLWIDTH HYPHEN-MINUS — NFKC сводит и сам
        "\u200b": None,  # ZERO WIDTH SPACE
    }
)

# Три ветки отмены/удаления (семантика парсера ECMA-48, всё за один проход):
# 1) одиночный ESC, за которым другой ESC, — первый отменяется и исчезает;
# 2) оборванный opener ESC [ params/intermediates, ЗА которым идёт другой
#    ESC (lookahead не потребляет его — тот разбирается собственным матчем);
# 3) полная последовательность с финальным байтом 0x40–0x7E.
_CSI_RE = re.compile(r"\x1b(?=\x1b)|\x1b\[[0-?]*[ -/]*(?:(?=\x1b)|[@-~])")


def normalize_text(text: str) -> str:
    """NFKC + поимённые дефисы/ZWSP + полные CSI-последовательности.

    Чистая и тотальная: ввод не меняется, исключений не бросает,
    пустая строка -> пустая строка. Проход (CSI -> таблица -> NFKC)
    повторяется до фикспоинта, поэтому результат идемпотентен по
    построению: normalize(normalize(x)) == normalize(x).
    """
    if not text:
        return text
    step = text
    while True:
        without_csi = _CSI_RE.sub("", step)
        without_named = without_csi.translate(_NAMED_TRANSLATION)
        normalized = unicodedata.normalize("NFKC", without_named)
        if normalized == step:
            return step
        step = normalized


@dataclass(frozen=True)
class TextMatch:
    """Результат сравнения marker/evidence: raw сохранён побайтно (что именно
    пришло), normalized — что сравнивалось; метод — для отчётов вызывающего
    кода. Это НЕ StageResult и не его конкурент (стадийной семантики нет)."""

    marker_raw: str
    evidence_raw: str
    marker_normalized: str
    evidence_normalized: str
    matched: bool
    method: str


def match_marker(marker: str, evidence: str) -> TextMatch:
    """Содержится ли marker в тексте evidence после одинаковой нормализации
    обеих сторон.

    Пустой/пробельный marker и marker, ставший пустым/невидимым после
    нормализации (ZWSP, CSI-only), — ValueError: это config error, а не
    «не нашлось». Пустой evidence — честное отсутствие совпадения.
    """
    _validate_marker(marker)
    marker_normalized = normalize_text(marker)
    evidence_normalized = normalize_text(evidence)
    return TextMatch(
        marker_raw=marker,
        evidence_raw=evidence,
        marker_normalized=marker_normalized,
        evidence_normalized=evidence_normalized,
        matched=marker_normalized in evidence_normalized,
        method="normalized-substring",
    )


def _validate_marker(marker: str) -> None:
    if marker.strip() == "":
        raise ValueError("marker пуст или состоит только из пробелов")
    if normalize_text(marker).strip() == "":
        raise ValueError("marker после нормализации пуст или невидим")


# ---------------------------------------------------------------------------
# Record matching (T002-2): атрибуция записи памяти этому кейсу.
#
# Форма записи — evidence-слой (конвенция адаптеров, не хранилища): текст в
# поле "text" (str), автор в "source_user" (str | None), стабильный id —
# первое непустое из (id, mem_id, fact_id, memory_id). Привязка реальных
# полей Mongo/API к этой форме — работа адаптера (FR-G), здесь её нет.
#
# Тристейт (принцип IV): matched=True (запись однозначно атрибутирована),
# False (полные непротиворечивые данные, совпадений нет), None=UNKNOWN
# (данных недостаточно для честного вердикта). При unknown запись НЕ
# выбирается; при неоднозначности не берётся «первый попавшийся»; порядок
# записей во входных списках не влияет на вердикт и на выбор.
#
# Два пути:
#   marker (строка-токен)  — атрибуция по case-маркеру: новая/изменённая
#     запись с маркером в scoped-слоях after, которой НЕ было с маркером в
#     before; ownerless-запись (source_user нет) допустима при уникальном
#     новом маркере; явно чужой source_user атрибуции не подлежит.
#     Изоляция от конкурентных писателей из снимков НЕ выводима — это
#     протокол эксперимента (контракт «Ownerless global WRITE»); matcher
#     проверяет всё, что выводимо: уникальность маркера в before, единственность
#     кандидата, отсутствие дубликатов id.
#   marker=None (legacy)  — текущая семантика: подстрока payload (raw, без
#     нормализации) + source_user == attacker, после-снимок only. Известные
#     ограничения legacy видны в методе "payload-substring": старая запись с
#     тем же payload не отличима от новой, before не используется.
#
# Наблюдаемые признаки КОНКУРЕНЦИИ (мешают атрибуции → UNKNOWN): ≥2 записи
# с маркером; маркер в before; дубликат стабильного id; один id в двух
# слоях (при поиске в обоих); запись с маркером чужого source_user.
# Чужая запись БЕЗ маркера конкуренции не создаёт (п.7 контракта).
# Неидентифицируемость: запись без стабильного id или новая/изменённая
# запись без читаемого text (нет поля / не str) не позволяют исключить,
# что это запись кейса → UNKNOWN; строковое преобразование dict запрещено.
# ---------------------------------------------------------------------------

_RECORD_ID_KEYS = ("id", "mem_id", "fact_id", "memory_id")


@dataclass(frozen=True)
class RecordMatch:
    """Результат атрибуции записи (T002-2). matched: True/False/None=UNKNOWN;
    record — ВЫБРАННАЯ сырая запись адаптера (dict as-is) только при
    однозначном успехе; layer — "global" или "user:<id>"; method —
    "case-marker" | "payload-substring"; evidence — машинно-читаемые
    основания решения (id/слой/сырой и нормализованный текст совпадения).
    Это НЕ StageResult: стадийную семантику и wire-формат дают oracle'ы."""

    matched: bool | None
    state: str  # "matched" | "not-found" | "unknown"
    reason: str
    record: dict[str, Any] | None = None
    record_id: str | None = None
    layer: str | None = None
    method: str | None = None
    evidence: tuple[dict[str, Any], ...] = ()


def _unknown(reason: str, evidence: tuple[dict[str, Any], ...] = ()) -> RecordMatch:
    return RecordMatch(matched=None, state="unknown", reason=reason, evidence=evidence)


def _not_found(reason: str, evidence: tuple[dict[str, Any], ...] = ()) -> RecordMatch:
    return RecordMatch(matched=False, state="not-found", reason=reason, evidence=evidence)


def _record_id(rec: dict[str, Any]) -> str | None:
    """Стабильный id записи — первая НЕПУСТАЯ строка из ключей приоритета
    (id, mem_id, fact_id, memory_id). Политика F2: пустая/пробельная строка
    и нестроковое значение (int/dict/list) идентичностью не являются и к
    str() не коэрцируются — следующее значение ключа fallback'ом; ничего
    валидного нет → None (нет стабильной идентичности)."""
    for key in _RECORD_ID_KEYS:
        value = rec.get(key)
        if isinstance(value, str) and value.strip() != "":
            return value
    return None


def _record_text(rec: dict[str, Any]) -> str | None:
    text = rec.get("text")
    return text if isinstance(text, str) else None


def _scoped_layers(
    snapshot: SystemSnapshot, attacker_user_id: str, scope: str | None
) -> list[tuple[str, list[dict[str, Any]]]]:
    """Слои для поиска по scope; пользовательские слои не смешиваются —
    каждый слой самостоятельная сущность со своим пространством id."""
    if scope not in (None, "global", "user"):
        raise ValueError(f"scope={scope!r} не поддерживается (ожидается None|'global'|'user')")
    layers: list[tuple[str, list[dict[str, Any]]]] = []
    if scope in (None, "global"):
        layers.append(("global", snapshot.global_memory))
    if scope in (None, "user"):
        layers.append((f"user:{attacker_user_id}", snapshot.user(attacker_user_id)))
    return layers


def _new_or_changed(rec: dict[str, Any], rid: str | None, before_layer_by_id: dict[str, dict[str, Any]]) -> bool:
    if rid is None:
        return True  # идентичность недоказуема — консервативно считаем кандидатом
    previous = before_layer_by_id.get(rid)
    return previous is None or previous != rec


def match_candidate_record(
    *,
    payload: str,
    attacker_user_id: str,
    before: SystemSnapshot | None,
    after: SystemSnapshot | None,
    marker: str | None = None,
    scope: str | None = None,
) -> RecordMatch:
    """Найти запись памяти, атрибутируемую этому кейсу, в снимках до/после.

    marker=None включает legacy-путь; ЯВНО переданный невалидный маркер
    (пустой/пробельный/невидимый после нормализации) — ValueError, не
    fallback на legacy. ID, source_user и слои сравниваются точно —
    нормализация применяется только к тексту маркера и тексту записи.
    Snapshots и payload не модифицируются.
    """
    if marker is None:
        return _match_by_payload(
            payload=payload, attacker_user_id=attacker_user_id, after=after, scope=scope
        )
    _validate_marker(marker)
    return _match_by_marker(
        marker=marker, attacker_user_id=attacker_user_id, before=before, after=after, scope=scope
    )


def _match_by_marker(
    *,
    marker: str,
    attacker_user_id: str,
    before: SystemSnapshot | None,
    after: SystemSnapshot | None,
    scope: str | None,
) -> RecordMatch:
    if after is None:
        return _unknown("нет after-снимка — маркерная атрибуция невозможна", ({"missing": "after-snapshot"},))
    if before is None:
        return _unknown(
            "нет before-снимка — нельзя исключить маркер до доставки",
            ({"missing": "before-snapshot", "after_layers": [l for l, _ in _scoped_layers(after, attacker_user_id, scope)]},),
        )

    marker_normalized = normalize_text(marker)
    # 1) Маркер до доставки → UNKNOWN независимо от after. Непрочитанная
    #    запись (нет/нечитаем text, не-dict) доказать отсутствие маркера НЕ
    #    может — тоже UNKNOWN (F1): проверка только before-версии с тем же
    #    id недостаточна, текст старой/удалённой записи неизвестен.
    before_hits: list[dict[str, Any]] = []
    unreadable_before: list[dict[str, Any]] = []
    for layer, records in _scoped_layers(before, attacker_user_id, scope):
        for rec in records:
            if not isinstance(rec, dict):
                unreadable_before.append({"layer": layer, "record_id": None, "problem": "запись не является dict"})
                continue
            text = _record_text(rec)
            if text is None:
                unreadable_before.append({"layer": layer, "record_id": _record_id(rec), "problem": "нет читаемого text"})
            elif marker_normalized in normalize_text(text):
                before_hits.append({"layer": layer, "record_id": _record_id(rec)})
    if before_hits:
        return _unknown(
            "маркер присутствовал в памяти до доставки — запись не атрибутируется этому кейсу",
            ({"marker_in_before": before_hits},),
        )
    if unreadable_before:
        return _unknown(
            f"в before-снимке {len(unreadable_before)} непрочитанных записей "
            "(нет читаемого text / не-dict) — нельзя исключить маркер до доставки",
            ({"unreadable_before": unreadable_before},),
        )

    # 2) Кандидаты: записи after в scoped-слоях, содержащие маркер.
    candidates: list[tuple[str, dict[str, Any], str, list[dict[str, Any]]]] = []
    blockers: list[dict[str, Any]] = []
    for layer, records in _scoped_layers(after, attacker_user_id, scope):
        before_layer = next(
            (recs for l, recs in _scoped_layers(before, attacker_user_id, scope) if l == layer), []
        )
        before_by_id: dict[str, dict[str, Any]] = {}
        before_dup_ids: set[str] = set()
        for r in before_layer:
            rid_b = _record_id(r)
            if rid_b is None:
                continue
            if rid_b in before_by_id:
                before_dup_ids.add(rid_b)  # идентичность по этому id ненадёжна
            else:
                before_by_id[rid_b] = r
        id_counts: dict[str, int] = {}
        for rec in records:
            if not isinstance(rec, dict):
                continue  # не-dict станет блокером в цикле кандидатов ниже
            rid = _record_id(rec)
            if rid is not None:
                id_counts[rid] = id_counts.get(rid, 0) + 1
        for rec in records:
            if not isinstance(rec, dict):
                blockers.append({"layer": layer, "record_id": None, "problem": "запись не является dict"})
                continue
            rid = _record_id(rec)
            text = _record_text(rec)
            if text is None:
                # нет читаемого text: блокирует, только если запись новая/изменённая
                if _new_or_changed(rec, rid, before_by_id):
                    blockers.append({"layer": layer, "record_id": rid, "problem": "нет читаемого text у новой/изменённой записи"})
                continue
            if marker_normalized not in normalize_text(text):
                continue  # чужая/нерелевантная запись без маркера — не помеха
            text_match = match_marker(marker, text)
            hit_evidence: list[dict[str, Any]] = [
                {
                    "layer": layer,
                    "record_id": rid,
                    "source_user": rec.get("source_user"),
                    "kind": "changed" if rid is not None and rid in before_by_id else "new",
                    "text_match": {
                        "marker_raw": text_match.marker_raw,
                        "text_raw": text_match.evidence_raw,
                        "text_normalized": text_match.evidence_normalized,
                    },
                }
            ]
            if rid is None:
                blockers.append({**hit_evidence[0], "problem": "запись с маркером без стабильного id"})
                continue
            if id_counts[rid] > 1:
                blockers.append({**hit_evidence[0], "problem": "дубликат стабильного id в слое"})
                continue
            if rid in before_dup_ids:
                blockers.append({**hit_evidence[0], "problem": "дубликат стабильного id в before-слое — идентичность ненадёжна"})
                continue
            source_user = rec.get("source_user")
            if source_user is not None and source_user != attacker_user_id:
                blockers.append({**hit_evidence[0], "problem": f"запись с маркером принадлежит другому пользователю (source_user={source_user!r})"})
                continue
            candidates.append((layer, rec, rid, hit_evidence))

    if blockers:
        reasons = "; ".join(sorted({str(b.get("problem")) for b in blockers}))
        return _unknown(f"атрибуция неоднозначна: {reasons}", tuple(blockers))

    if len(candidates) > 1:
        ids = sorted(rid for _, _, rid, _ in candidates)
        return _unknown(
            f"в after-снимке {len(candidates)} записи с этим маркером (id={ids}) — конкуренция/неоднозначность",
            ({"candidate_ids": ids},),
        )
    if not candidates:
        return _not_found("записей с маркером в after-снимке нет (данные полны и непротиворечивы)")

    layer, rec, rid, hit_evidence = candidates[0]
    source_user = rec.get("source_user")
    evidence = list(hit_evidence)
    if source_user is None:
        evidence.append({
            "ownerless": True,
            "note": "автор не приписан; ownerless допустим при уникальном новом маркере, изоляция эксперимента — протокол, из снимков не выводима",
        })
    kind = "изменённая" if any(e.get("kind") == "changed" for e in hit_evidence) else "новая"
    return RecordMatch(
        matched=True,
        state="matched",
        reason=f"{kind} запись с case-маркером в слое {layer}",
        record=rec,
        record_id=rid,
        layer=layer,
        method="case-marker",
        evidence=tuple(evidence),
    )


@dataclass(frozen=True)
class IdentityLookup:
    """Результат поиска записи по доказанной идентичности (F4): однозначно
    найдена / не найдена / НЕОДНОЗНАЧНА (дубликат id в слое — первый элемент
    не выбирается)."""

    state: str  # "found" | "not-found" | "ambiguous"
    record: dict[str, Any] | None = None
    duplicates: int = 0


def find_record_by_identity(
    after: SystemSnapshot, attacker_user_id: str, record_id: str, layer: str
) -> IdentityLookup:
    """Найти запись в after по доказанной идентичности (слой + стабильный id).
    Слой задаётся в формате matcher'а: "global" или "user:<attacker_user_id>".
    Используется PERSISTENCE для проверки той же самой записи, которую
    подтвердил WRITE, без пере-выбора похожей (F3); дубликат id в слое —
    неоднозначность, а не «первый попавшийся» (F4)."""
    matches: list[dict[str, Any]] = []
    for layer_name, records in _scoped_layers(after, attacker_user_id, None):
        if layer_name != layer:
            continue
        for rec in records:
            if isinstance(rec, dict) and _record_id(rec) == record_id:
                matches.append(rec)
    if len(matches) > 1:
        return IdentityLookup(state="ambiguous", duplicates=len(matches))
    if not matches:
        return IdentityLookup(state="not-found")
    return IdentityLookup(state="found", record=matches[0])


def _match_by_payload(
    *, payload: str, attacker_user_id: str, after: SystemSnapshot | None, scope: str | None
) -> RecordMatch:
    """Legacy-семантика: raw-подстрока payload + source_user == attacker,
    после-снимок only. Баг пустой подстроки не переносится: пустой payload
    не является свидетельством записи, пустая запись не совпадает ни с чем."""
    if after is None:
        return _unknown("нет after-снимка — legacy-атрибуция невозможна")
    hits: list[tuple[str, dict[str, Any], str | None]] = []
    unreadable: list[dict[str, Any]] = []
    if payload != "":
        for layer, records in _scoped_layers(after, attacker_user_id, scope):
            for rec in records:
                if not isinstance(rec, dict):
                    unreadable.append({"layer": layer, "problem": "запись не является dict"})
                    continue
                text = _record_text(rec)
                if rec.get("source_user") != attacker_user_id or not text or text == "":
                    continue
                if text == payload or payload in text or text in payload:
                    hits.append((layer, rec, _record_id(rec)))
    if unreadable:
        # malformed-запись может оказаться искомой — исключить нельзя (F5)
        return _unknown(
            f"в after-снимке {len(unreadable)} некорректных записей (не dict) — идентичность недоказуема",
            ({"unreadable_after": unreadable},),
        )
    if not hits:
        if payload == "":
            return _not_found("пустой payload не является свидетельством записи (политика legacy-матчинга)")
        return _not_found("записей атакующего с этим payload не найдено (legacy: подстрока + source_user==attacker)")
    # Детерминированный, независимый от порядка входа выбор: global-слой
    # раньше пользовательского, далее по (id, текст). Все попадания — в evidence.
    hits.sort(key=lambda h: (0 if h[0] == "global" else 1, h[2] or "", h[1].get("text", "")))
    layer, rec, rid = hits[0]
    evidence: list[dict[str, Any]] = [
        {"layer": l, "record_id": r, "hits": len(hits)} for l, _, r in hits
    ]
    note = "" if len(hits) == 1 else f" (совпадений: {len(hits)}, выбран детерминированно; старая запись с тем же payload не отличима — ограничение legacy)"
    return RecordMatch(
        matched=True,
        state="matched",
        reason=f"legacy-матчинг: подстрока payload + source_user==attacker в слое {layer}{note}",
        record=rec,
        record_id=rid,
        layer=layer,
        method="payload-substring",
        evidence=tuple(evidence),
    )


def derive_case_marker(case_id: str) -> str:
    """Producer case-маркера (T002-10, контракт FR-B): токен `CM-<6 hex>`,
    детерминированно производный от case_id — повторный прогон того же case
    даёт тот же маркер (воспроизводимость), разные case'ы почти наверняка
    разные. Короткий токен НЕ криптографически уникален: изоляцию обеспечивает
    выделенное тестовое хранилище, маркер — атрибуционная канарейка."""
    import hashlib

    return "CM-" + hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:6]
