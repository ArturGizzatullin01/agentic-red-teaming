"""tests/test_evidence_matching.py — T002-1 (specs/002-evidence-integrity):
нормализация текстовых свидетельств и marker-матчинг (evidence/matching.py).
Контракт — specs/002-evidence-integrity/contracts/evidence-and-verdict.md.

Проверяемые факты о Unicode закреплены тестами честно (проверены в venv по
кодовым точкам, не по глифам): NFKC меняет только U+2011→U+2010 и
U+FF0D→ASCII '-', остальные поимённые дефисы не трогает — таблица содержит
все восемь кодовых точек. CSI: конвейер (CSI → таблица → NFKC) повторяется
до фикспоинта; отменённые/оборванные последовательности не поглощают
текст за собой, а склеенные combining-пары повторно нормализуются.
"""

from __future__ import annotations

import unicodedata

import pytest

from memnotsafe.evidence.matching import match_marker, normalize_text

NAMED_HYPHENS = {
    "U+2010 HYPHEN": "\u2010",
    "U+2011 NON-BREAKING HYPHEN": "\u2011",
    "U+2012 FIGURE DASH": "\u2012",
    "U+2013 EN DASH": "\u2013",
    "U+2014 EM DASH": "\u2014",
    "U+2015 HORIZONTAL BAR": "\u2015",
    "U+2212 MINUS SIGN": "\u2212",
    "U+FF0D FULLWIDTH HYPHEN-MINUS": "\uff0d",
}


# --- поимённые дефисы: каждый отдельно, не диапазоном ---


@pytest.mark.parametrize("cp", list(NAMED_HYPHENS.values()), ids=list(NAMED_HYPHENS))
def test_each_named_hyphen_maps_to_ascii(cp: str) -> None:
    assert normalize_text(f"CAN{cp}4F2A") == "CAN-4F2A"


def test_nfkc_hyphen_facts() -> None:
    """Факты о NFKC, из которых следует порядок и состав таблицы: U+2011 NFKC
    сводит к U+2010, U+FF0D — к ASCII; остальные поимённые дефисы NFKC НЕ
    трогает. Таблица обязана содержать оба конца U+2011→U+2010-цепочки."""
    assert unicodedata.normalize("NFKC", "\u2011") == "\u2010"
    assert unicodedata.normalize("NFKC", "\uff0d") == "-"
    for cp in ("\u2010", "\u2012", "\u2013", "\u2014", "\u2015", "\u2212"):
        assert unicodedata.normalize("NFKC", cp) == cp


def test_fullwidth_hyphen_reduced_by_nfkc_itself() -> None:
    """U+FF0D — единственный поимённый дефис, который NFKC сводит к ASCII
    без таблицы; в таблице он всё равно есть, поэтому в каком бы порядке
    проход его ни встретил, результат одинаковый."""
    assert unicodedata.normalize("NFKC", "\uff0d") == "-"
    assert normalize_text("CM\uff0d4f2a") == "CM-4f2a"


# --- обычный текст не повреждается ---


@pytest.mark.parametrize(
    "text",
    [
        "CAN-4F2A",
        "RU000A0JU4L3",  # ISIN
        "https://attacker.example/can-CM4f2a?x=1",  # URL
        "Лимит 150000 руб., risk-level: HIGH",
        "обычный ответ без спецсимволов",
        "",
    ],
)
def test_plain_ascii_and_ru_untouched(text: str) -> None:
    assert normalize_text(text) == text


# --- ZWSP и ANSI CSI ---


def test_zwsp_removed() -> None:
    assert normalize_text("can\u200bary") == "canary"


def test_complete_csi_removed() -> None:
    assert normalize_text("текст \x1b[31mCAN\x1b[0m хвост") == "текст CAN хвост"


def test_zwsp_and_csi_combined_both_sides_match() -> None:
    marker = "CAN\u200b-4F2A"
    evidence = "контекст: CAN\x1b[31m\u200b\u20114F2A виден жертве"
    result = match_marker(marker, evidence)
    assert result.matched is True


@pytest.mark.parametrize(
    "text",
    [
        "текст\x1b[31",  # нет финального байта — не CSI по грамматике
        "\x1b[31текст",  # кириллица не является финальным байтом
        "хвост\x1b[",  # обрыв посередине
        "хвост\x1b",  # голый ESC
        "\x1b]0;title\x07 x",  # OSC — вне минимального CSI-контракта
    ],
)
def test_incomplete_or_non_csi_escape_preserves_text(text: str) -> None:
    assert normalize_text(text) == text


def test_grammatically_complete_unknown_csi_consumes_only_itself() -> None:
    # 'a' — валидный финальный байт: последовательность полна по грамматике,
    # но следующий за ней обычный текст ('bc') не поглощается
    assert normalize_text("\x1b[31abc") == "bc"


def test_dangling_opener_cancelled_by_next_escape_keeps_tail() -> None:
    # оборванный "\x1b[" отменяется следующим ESC (семантика терминала) и сам
    # удаляется, но НЕ поглощает обычный текст 'x' за полной "\x1b[31m";
    # одиночный проход — без склеивания новой последовательности
    assert normalize_text("\x1b[\x1b[31mx") == "x"
    assert normalize_text("\x1b[31\x1b[45mX") == "X"


# --- регистр, пробелы, fuzzy — значимы, транслитерации нет ---


def test_case_is_significant() -> None:
    assert match_marker("Canary", "тут canary сидит").matched is False


def test_plain_spaces_are_significant() -> None:
    assert match_marker("a b", "ab").matched is False
    assert match_marker("a b", "x a b y").matched is True


def test_no_transliteration() -> None:
    assert match_marker("CAN", "тут СAN (кириллическая С)").matched is False


# --- marker: пустой/пробельный/невидимый → ValueError ---


@pytest.mark.parametrize("marker", ["", " ", "\t \n", "\u00a0"])
def test_empty_or_whitespace_marker_rejected(marker: str) -> None:
    with pytest.raises(ValueError):
        match_marker(marker, "любой evidence")


@pytest.mark.parametrize("marker", ["\u200b", "\x1b[31m", "\x1b[0m\u200b", "\u200b \x1b[0m"])
def test_marker_invisible_after_normalization_rejected(marker: str) -> None:
    # ZWSP не считается пробелом в Python — ловится только проверкой ПОСЛЕ
    # нормализации; CSI-only marker вычищается в пустую строку
    with pytest.raises(ValueError):
        match_marker(marker, "любой evidence")


# --- пустой evidence — отсутствие совпадения, не ошибка ---


@pytest.mark.parametrize("evidence", ["", "\u200b\x1b[0m"])
def test_empty_evidence_is_no_match(evidence: str) -> None:
    result = match_marker("CAN-4F2A", evidence)
    assert result.matched is False


# --- идемпотентность ---


@pytest.mark.parametrize(
    "text",
    [
        "",
        "CAN-4F2A",
        "a\u200bb\x1b[31m\u2011c",
        "\x1b[\x1b[31mx",
        "\x1b[31текст",
        "ＣＡＮ－42",
        "\x1b[m\x1b[m\x1b[m",
        # adversarial из фаззинга (500k триалов): голый ESC перед
        # удаляемой последовательностью не должен склеивать новую
        "\x1b\x1b[31m[\x1b",
        "\x1b\x1b[31m[x",
        "\x1b[3\x1b[45",
        # rework: склеенные combining-последовательности и fullwidth-CSI,
        # который NFKC сводит к '[' только со второго прохода
        "e\u200b\u0301",
        "e\x1b[31m\u0301",
        "\x1b\uff3b31mX",
    ],
)
def test_normalize_is_idempotent(text: str) -> None:
    once = normalize_text(text)
    assert normalize_text(once) == once


def test_fullwidth_csi_needs_second_pass() -> None:
    # NFKC превращает ［ (U+FF3B) в '[' ПОСЛЕ CSI-прохода — цикл обязан
    # вернуться и удалить собранную последовательность
    assert normalize_text("\x1b\uff3b31mX") == "X"


def test_bare_esc_cancelled_by_next_esc_keeps_text() -> None:
    # первый ESC исчезает (отменён вторым), SGR удаляется, а обычный текст
    # '[' и 'x' не переинтерпретируются как CSI-начало
    assert normalize_text("\x1b\x1b[31m[x") == "[x"


# --- склейка combining-последовательностей после удаления ZWSP/CSI ---
# (rework-ревью T002-1): ZWSP/CSI рвёт базу и диакритику; после удаления
# объединённая пара обязана пройти повторную Unicode-нормализацию до é


def test_combining_reunited_after_zwsp_composes() -> None:
    assert normalize_text("e\u200b\u0301") == "é"


def test_combining_reunited_after_csi_composes() -> None:
    # extra-дефект, найденный при rework: NFKC ДО удаления CSI приклеивал
    # acute к финальной 'm' последовательности (получался 'ḿ', ломая CSI)
    assert normalize_text("e\x1b[31m\u0301") == "é"


def test_precomposed_marker_matches_glued_variants() -> None:
    assert match_marker("é", "ответ: e\u200b\u0301 найден").matched is True
    assert match_marker("é", "ответ: e\x1b[0m\u0301 найден").matched is True


def test_decorated_marker_matches_precomposed_symmetrically() -> None:
    """Контракт marker/evidence симметричен: обе стороны проходят одну
    нормализацию, поэтому украшенная (ZWSP+CSI) сторона матчится с
    precomposed в ЛЮБОЙ роли; raw обеих строк сохранён побайтно."""
    decorated = "e\u200b\x1b[31m\u0301"
    evidence_dec = f"ответ: {decorated} найден"
    evidence_pre = "ответ: é найден"
    straight = match_marker("é", evidence_dec)
    reversed_ = match_marker(decorated, evidence_pre)
    assert straight.matched is True
    assert reversed_.matched is True
    assert straight.marker_raw == "é" and straight.evidence_raw == evidence_dec
    assert reversed_.marker_raw == decorated and reversed_.evidence_raw == evidence_pre
    assert straight.marker_normalized == "é" and reversed_.evidence_normalized.count("é") == 1


def test_glued_combining_idempotent() -> None:
    for text in ("e\u200b\u0301", "e\x1b[31m\u0301", "Cafe\u200b\u0301 \x1b[0m"):
        once = normalize_text(text)
        assert normalize_text(once) == once


# --- результат сравнения: dataclass с raw/normalized/matched/method ---


def test_match_result_contract() -> None:
    marker = "CAN-4F2A"
    evidence = "жертва видит CAN\u20114F2A в контексте"
    result = match_marker(marker, evidence)
    assert result.matched is True
    assert result.marker_raw == marker  # raw сохранён побайтно
    assert result.evidence_raw == evidence
    assert result.marker_normalized == "CAN-4F2A"
    assert "CAN-4F2A" in result.evidence_normalized
    assert result.method == "normalized-substring"


def test_match_result_different_text_no_match() -> None:
    result = match_marker("alpha", "beta")
    assert result.matched is False
    assert result.marker_raw == "alpha"
    assert result.evidence_raw == "beta"
