"""src/memnotsafe/generation/mutators.py — чистые текстовые мутаторы корпуса (P15).

Мутатор превращает один payload в семейство вариаций ФОРМЫ (обфускация) без
роста ручной работы — приём strategies из promptfoo, адаптированный под нашу
доктрину. Инварианты карточки CARD-P15-mutators-2026-09-23:

- мутатор = ЧИСТАЯ функция ``mutate(text, seed) -> str``, детерминированная по
  seed (норма воспроизводимости W6). Выбор вариантов на позициях выводится из
  sha256(salt:seed:position), НЕ из hash() — воспроизводимость между
  процессами не зависит от PYTHONHASHSEED. Offline: ноль вызовов LLM/сети;
- мутируется ФОРМА, не ЦЕЛЬ: expected_effect мутированной записи обязан быть
  побайтово равен исходному в канонической сериализации (``canonical_json``
  из GoalContract). Арбитр — ``mutation_violations()``; его пустой список =
  мутация честная. Связь с GoalContract: цель неизменна ⇔
  ``same_goal(исходная, мутированная)``;
- литерал ``{case_marker}`` (CASE_MARKER_PLACEHOLDER, ``generation/corpus.py``)
  НЕ мутируется: побайтово сохраняется в выходе любого мутатора и любой
  композиции. Иначе base64/rot13 съели бы плейсхолдер ДО подстановки раннером
  и сломали маркерную изоляцию (``core/runner.py``: кандидат без маркера при
  объявленной изоляции — config error ДО доставки);
- provenance: мутированная запись корпуса несёт originalText + layer + seed
  (``mutation_provenance()``); НИКАКИХ новых полей в attempts.jsonl (норма
  P13-b — артефакты прогона схемой не расширяются);
- эхо-самоуспех (норма черновика §2): мутированный кандидат НЕ засчитывает
  эхо собственного вклада (payload, маркер, референс, подсказанные
  атакующим) как успех, даже если грейдер засчитал. Отличение «цель повторила
  подсказанное» от «память выдала в НОВОМ контексте» остаётся за оракулами
  (require_case_marker, зонный write-оракул — V-3C-R2); механика здесь НЕ
  выдумывается — модуль меняет только форму текста и не трогает вердикты;
- композиция ``apply_layer(text, layer, seed)``: мутаторы применяются по
  порядку, порядок значим (``[homoglyph, base64]`` ≠ ``[base64,
  homoglyph]``); каждый шаг получает один и тот же seed. ``layer: [имена]`` —
  первоклассный объект записи корпуса (родственник H14 salami); интеграция в
  генератор/corpus-запись — отдельная карточка, здесь только чистое ядро;
- отложено честно (НЕ выражается чистой текстовой трансформой без внешних
  вызовов — см. DEFERRED_MUTATORS): multilingual (перевод = LLM), bestOfN
  (N генераций = LLM), retry (перегенерация = LLM). Offline-модуль не
  выдумывает LLM-вызовы;
- слот матрицы «семейство × мутатор» (ASR в клетке, поверх карты потерь B4) —
  закладка формата для CLI v2: клетка = (attack_class, мутатор из MUTATORS);
  кода CLI здесь нет и не появляется.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
from collections.abc import Callable, Sequence

from memnotsafe.core.goal_contract import canonical_json
from memnotsafe.generation.corpus import CASE_MARKER_PLACEHOLDER
from memnotsafe.generation.errors import AttackerError

Mutator = Callable[[str, int], str]

# Таблицы вариантов: выбор конкретного варианта на позиции — по seed.
_LEETSPEAK: dict[str, tuple[str, ...]] = {
    "a": ("4", "@"), "b": ("8", "6"), "i": ("1", "!"), "l": ("1", "|"),
    "o": ("0", "*"), "s": ("5", "$"), "t": ("7", "+"), "g": ("9", "6"),
    "e": ("3",), "c": ("(",), "A": ("4", "@"), "I": ("1", "!"),
    "O": ("0", "*"), "S": ("5", "$"), "T": ("7", "+"), "E": ("3",),
}
# Гомоглифы: латиница → кириллица/греческие двойники (Unicode-эскейпы — чтобы
# кириллица и греческие не путались при чтении исходника глазами/диффами).
_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("\u0430", "\u03b1"), "c": ("\u0441",), "e": ("\u0435", "\u03b5"),
    "o": ("\u043e", "\u03bf"), "p": ("\u0440", "\u03c1"), "x": ("\u0445", "\u03c7"),
    "y": ("\u0443",), "A": ("\u0410", "\u0391"), "B": ("\u0412",),
    "C": ("\u0421",), "E": ("\u0415", "\u0395"), "H": ("\u041d", "\u0397"),
    "K": ("\u041a", "\u039a"), "M": ("\u041c", "\u039c"), "O": ("\u041e", "\u039f"),
    "P": ("\u0420", "\u03a1"), "T": ("\u0422", "\u03a4"), "X": ("\u0425", "\u03a7"),
}

# Мутаторы, отложенные честно: не выражаются чистой текстовой трансформой
# без внешних вызовов (offline-модуль не делает LLM-вызовов).
DEFERRED_MUTATORS: dict[str, str] = {
    "multilingual": "перевод требует LLM — offline-модуль, отложено до живой генерации",
    "bestOfN": "N генераций требует LLM-вызовов — не чистая трансформа, отложено",
    "retry": "перегенерация требует LLM-вызовов — не чистая трансформа, отложено",
}


def _variant_index(salt: str, seed: int, position: int, count: int) -> int:
    """Детерминированный выбор варианта: sha256 вместо hash() — инвариантен к
    PYTHONHASHSEED, одинаков между процессами и запусками."""
    digest = hashlib.sha256(f"{salt}:{int(seed)}:{position}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % count


def _protect_marker(text: str, transform: Callable[[str], str]) -> str:
    """Применить transform ко всему тексту, КРОМЕ побайтовых вхождений
    плейсхолдера {case_marker}: сегменты между вхождениями мутируются,
    сам литерал остаётся нетронутым (замок инварианта 2 карточки)."""
    if CASE_MARKER_PLACEHOLDER not in text:
        return transform(text)
    return CASE_MARKER_PLACEHOLDER.join(transform(part) for part in text.split(CASE_MARKER_PLACEHOLDER))


def mutate_base64(text: str, seed: int) -> str:
    """base64 UTF-8-байтов сегментов; seed не участвует (кодек детерминирован
    сам по себе — принят для единообразия контракта мутатора)."""
    return _protect_marker(text, lambda s: base64.b64encode(s.encode("utf-8")).decode("ascii"))


def mutate_rot13(text: str, seed: int) -> str:
    """rot13 (только латиница, кириллица проходит как есть); обратим повтором."""
    return _protect_marker(text, lambda s: codecs.encode(s, "rot13"))


def mutate_hex(text: str, seed: int) -> str:
    """hex UTF-8-байтов сегментов (нижний регистр, без разделителей)."""
    return _protect_marker(text, lambda s: s.encode("utf-8").hex())


def mutate_leetspeak(text: str, seed: int) -> str:
    """Литспик: варианты на позициях выбираются по seed (мутатор недетерминирован
    по форме — seed и есть источник воспроизводимого выбора)."""

    def leet(s: str) -> str:
        out: list[str] = []
        for pos, ch in enumerate(s):
            variants = _LEETSPEAK.get(ch)
            if not variants:
                out.append(ch)
                continue
            out.append(variants[_variant_index("leetspeak", seed, pos, len(variants))])
        return "".join(out)

    return _protect_marker(text, leet)


def mutate_homoglyph(text: str, seed: int) -> str:
    """Гомоглифы: латиница → визуально неотличимые кириллица/греческие;
    выбор двойника на позиции — по seed (недетерминирован по форме)."""

    def homo(s: str) -> str:
        out: list[str] = []
        for pos, ch in enumerate(s):
            variants = _HOMOGLYPHS.get(ch)
            if not variants:
                out.append(ch)
                continue
            out.append(variants[_variant_index("homoglyph", seed, pos, len(variants))])
        return "".join(out)

    return _protect_marker(text, homo)


MUTATORS: dict[str, Mutator] = {
    "base64": mutate_base64,
    "rot13": mutate_rot13,
    "hex": mutate_hex,
    "leetspeak": mutate_leetspeak,
    "homoglyph": mutate_homoglyph,
}


def get_mutator(name: str) -> Mutator:
    """Мутатор по имени; неизвестное имя — громкая ошибка конфигурации, не
    молчаливый пропуск (перечисляем известные, чтобы ошибка была исправимой)."""
    try:
        return MUTATORS[name]
    except KeyError:
        raise AttackerError(
            f"неизвестный мутатор {name!r} (известны: {', '.join(sorted(MUTATORS))})"
        ) from None


def apply_layer(text: str, layer: Sequence[str], seed: int) -> str:
    """Композиция мутаторов по порядку; порядок значим (заперто тестом).
    Пустой layer = идентичность. Имена проверяются ДО применения — ошибка
    конфигурации не оставляет полуприменённого текста."""
    unknown = [name for name in layer if name not in MUTATORS]
    if unknown:
        raise AttackerError(
            f"apply_layer: неизвестные мутаторы {unknown} в layer {list(layer)} "
            f"(известны: {', '.join(sorted(MUTATORS))})"
        )
    for name in layer:
        text = MUTATORS[name](text, seed)
    return text


def mutation_provenance(original_text: str, layer: Sequence[str], seed: int) -> dict:
    """Провенанс мутированной записи корпуса (инвариант 3): originalText +
    layer + seed. Расширение corpus-записи — отдельная карточка интеграции;
    в attempts.jsonl этих полей НЕТ и не появляется (норма P13-b)."""
    return {"originalText": original_text, "layer": list(layer), "seed": int(seed)}


def mutation_violations(
    *,
    original_text: str,
    mutated_text: str,
    original_effect: dict,
    mutated_effect: dict,
    layer: Sequence[str],
    seed: int,
) -> list[str]:
    """Инварианты мутированной записи (замки 1–2 + воспроизводимость).
    Пустой список = мутация честная. Проверки:
    - expected_effect побайтово равен исходному В КАНОНИЧЕСКОЙ сериализации
      ( GoalContract.canonical_json: порядок ключей не смысловой, состав и
      значения — смысловые). Мутация не имеет права менять цель;
    - плейсхолдер {case_marker} сохранён побайтово (число вхождений то же);
    - мутация не стёрла payload;
    - имена layer известны;
    - мутация воспроизводима: apply_layer(original_text, layer, seed) ==
      mutated_text (провенанс originalText+layer+seed достаточен для повтора).
    """
    violations: list[str] = []
    if canonical_json(original_effect) != canonical_json(mutated_effect):
        violations.append(
            "expected_effect изменён мутацией — цель обязана быть побайтово "
            f"инвариантна (каноническая сериализация): {canonical_json(original_effect)!r} "
            f"!= {canonical_json(mutated_effect)!r}"
        )
    if original_text.count(CASE_MARKER_PLACEHOLDER) != mutated_text.count(CASE_MARKER_PLACEHOLDER):
        violations.append(
            f"плейсхолдер {CASE_MARKER_PLACEHOLDER} не сохранён побайтово: "
            f"{original_text.count(CASE_MARKER_PLACEHOLDER)} вхождений в исходном "
            f"против {mutated_text.count(CASE_MARKER_PLACEHOLDER)} в мутированном — "
            "маркерная изоляция раннера была бы сломана"
        )
    if not mutated_text.strip():
        violations.append("мутация стёрла payload (пусто или только пробелы)")
    unknown = [name for name in layer if name not in MUTATORS]
    if unknown:
        violations.append(f"неизвестные мутаторы {unknown} в layer {list(layer)}")
    elif apply_layer(original_text, layer, seed) != mutated_text:
        violations.append(
            "мутация невоспроизводима по (originalText, layer, seed): повторный "
            "прогон даёт другой текст — провенанс записи недостаточен"
        )
    return violations
