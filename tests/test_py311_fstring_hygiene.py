"""tests/test_py311_fstring_hygiene.py — P19 (часть 1): замок класса PEP 701 на
ВЕСЬ пакет.

PEP 701 (Python 3.12) снял грамматический запрет «бэкслэш не может стоять в
ВЫРАЖЕНИИ f-строки». На Python 3.11 (нижняя граница пакета, `requires-python
>=3.11`) такой бэкслэш — жёсткий SyntaxError на импорте: один узел делает
НЕИМПОРТИРУЕМЫМ весь модуль. Suite при этом гоняется на 3.12+, где PEP 701
маскирует класс — латентный дефект уезжает во внешнюю поставку (пилот Влада).

FIX-E закрыла один узел в threat_report.py точечным AST-сканом. Здесь тот же
сканер обобщён на всё дерево `src/memnotsafe/`: тест падает, если хоть одно
выражение `FormattedValue` (включая `format_spec` и вложенные f-строки —
`ast.walk` рекурсивен) в любом модуле содержит бэкслэш.

Точность позиций. `ast.get_source_segment` для внутренних узлов f-строки точен
на Python 3.12+ (PEP 701 дал выражениям собственные корректные позиции). На 3.11
позиции подстановок ненадёжны (узлы наследуют начало f-строки) — сканер там
может ложно указывать на бэкслэш в ЛИТЕРАЛЬНОЙ части. Поэтому замок структурный
и рассчитан на интерпретатор suite (3.12+), где он и гоняется; ровно как в
FIX-E (`test_threat_report_fstring_py311.py`). На 3.11 реальный дефект и так
не дал бы `ast.parse` (SyntaxError) — класс не проскочит незамеченным.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import memnotsafe

# Корень пакета: src/memnotsafe/ (сканируем рекурсивно всё дерево модулей).
PACKAGE_ROOT = Path(memnotsafe.__file__).resolve().parent


def fstring_expr_backslash_offenders(path: Path) -> list[tuple[int, str]]:
    """Список (строка, исходный сегмент) для каждого выражения f-строки, чей
    текст содержит бэкслэш — то, что запрещено грамматикой ДО PEP 701 (Python
    <3.12) и делает модуль неимпортируемым.

    Обходим ВЕСЬ модуль (`ast.walk` рекурсивен — вложенные f-строки и
    `format_spec` тоже попадают), берём исходный сегмент именно ВЫРАЖЕНИЯ:
    литеральные части f-строки, где бэкслэш всегда был легален, не проверяем.
    Общий хелпер FIX-E, обобщённый на произвольный модуль (P19)."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            for sub in (part.value, part.format_spec):
                if sub is None:
                    continue
                seg = ast.get_source_segment(src, sub)
                if seg and "\\" in seg:
                    offenders.append((getattr(sub, "lineno", -1), seg))
    return offenders


def iter_package_modules(root: Path = PACKAGE_ROOT) -> Iterator[Path]:
    """Все *.py пакета рекурсивно (детерминированный порядок)."""
    yield from sorted(root.rglob("*.py"))


def test_all_package_modules_have_no_backslash_in_fstring_expression():
    """Ни один модуль `src/memnotsafe/` не содержит бэкслэш в выражении f-строки
    → пакет импортируем на Python 3.11 (нижняя заявленная граница)."""
    offenders: dict[str, list[tuple[int, str]]] = {}
    for module in iter_package_modules():
        found = fstring_expr_backslash_offenders(module)
        if found:
            offenders[str(module.relative_to(PACKAGE_ROOT.parent))] = found
    assert offenders == {}, (
        "выражение(я) f-строки содержат бэкслэш — модуль неимпортируем на "
        f"Python <3.12 (грамматика до PEP 701): {offenders}"
    )


def test_scanner_flags_backslash_in_fstring_expression(tmp_path):
    """RED-замок на искусственном дефектном файле: сканер ЛОВИТ бэкслэш в
    выражении подстановки (иначе замок был бы пустым). База зелёная (FIX-E
    влита), поэтому дефект вносим здесь, в tmp_path."""
    bad = tmp_path / "defect.py"
    # бэкслэш в ВЫРАЖЕНИИ {...} — SyntaxError на 3.11, латентно на 3.12+
    bad.write_text('x = "a\\nb"\ny = f"{x.split(\'\\n\')[0]}"\n', encoding="utf-8")
    offenders = fstring_expr_backslash_offenders(bad)
    assert offenders, "сканер не поймал бэкслэш в выражении f-строки — замок пуст"
    assert "\\" in offenders[0][1]


def test_scanner_ignores_backslash_in_literal_part(tmp_path):
    """Не ложно-срабатывает: бэкслэш в ЛИТЕРАЛЬНОЙ части f-строки (например
    `\\n` вне подстановки) легален на всех версиях и НЕ считается дефектом."""
    ok = tmp_path / "clean.py"
    ok.write_text('name = "x"\nz = f"line\\n{name}"\n', encoding="utf-8")
    assert fstring_expr_backslash_offenders(ok) == []


def test_scanner_covers_format_spec_expression(tmp_path):
    """Бэкслэш в выражении ВНУТРИ format_spec (вложенное поле подстановки) тоже
    под замком — ast.walk рекурсивно доходит до JoinedStr внутри format_spec."""
    spec = tmp_path / "spec.py"
    # f"{v:{'\t'}}" — во вложенном поле format_spec стоит выражение с бэкслэшем
    spec.write_text("v = 1\ns = f\"{v:{'\\t'}}\"\n", encoding="utf-8")
    assert fstring_expr_backslash_offenders(spec), "бэкслэш в выражении format_spec пропущен"
