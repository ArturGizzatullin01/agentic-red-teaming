"""tests/test_threat_report_fstring_py311.py — FIX-E: threat_report.py должен
импортироваться на Python <3.12.

PEP 701 (Python 3.12) снял запрет «бэкслэш не может стоять в ВЫРАЖЕНИИ части
f-строки». На Python 3.11 и старше бэкслэш внутри поля подстановки `{...}` —
жёсткий SyntaxError на этапе импорта: один такой узел делает НЕИМПОРТИРУЕМЫМ
весь модуль, и `threat-report` (бизнес-отчёт, который демонстрирует Влад) не
открывается вовсе.

Замок портативен и не зависит от версии интерпретатора, под которым идёт прогон
(здесь venv = 3.14): `ast.parse(..., feature_version=(3, 11))` на 3.12+ НЕ
возвращает старое поведение токенайзера f-строк — он принимает дефект, поэтому
такой тест был бы зелёным и на базе (эмпирически проверено). Вместо этого мы
проверяем сам довакуумный (pre-PEP-701) инвариант структурно: ни одно выражение
`FormattedValue` (и его format_spec) во всём модуле не содержит бэкслэша. На базе
есть ровно один такой узел (строка 1396) — тест КРАСНЫЙ; после FIX-E (литерал
em-dash вынесен из f-строки в переменную) — их ноль, тест зелёный.

Поведение на разных интерпретаторах на базе:
  • Python <3.12 — импорт модуля падает SyntaxError уже на сборке теста (red);
  • Python ≥3.12 — импорт проходит, но ассерт ловит латентный дефект (red).
После фикса зелено на обоих.
"""

from __future__ import annotations

import ast
from pathlib import Path

from memnotsafe.reporting import threat_report as mod


def _fstring_expr_backslash_offenders(path: Path) -> list[tuple[int, str]]:
    """Список (строка, исходный сегмент) для каждого выражения f-строки, чей
    текст содержит бэкслэш — то, что запрещено грамматикой до PEP 701.

    Обходим ВЕСЬ модуль (ast.walk рекурсивен, вложенные f-строки и format_spec
    тоже попадают), берём исходный сегмент именно выражения — литеральные части
    f-строки, где бэкслэш всегда был легален, не проверяем."""
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


def test_threat_report_has_no_backslash_in_fstring_expression():
    """Инвариант до PEP 701: f-строка с бэкслэшем в `{выражении}` — SyntaxError
    на Python <3.12 → модуль неимпортируем → threat-report мёртв на демо. База:
    ровно один такой узел (строка 1396); после FIX-E: ни одного."""
    path = Path(mod.__file__)
    offenders = _fstring_expr_backslash_offenders(path)
    assert offenders == [], (
        "выражение(я) f-строки содержат бэкслэш — модуль неимпортируем на "
        f"Python <3.12 (грамматика до PEP 701): {offenders}"
    )
