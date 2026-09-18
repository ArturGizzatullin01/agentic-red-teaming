"""tests/test_asr_provenance_line_denominators.py — карточка R-2: в одной
строке два разных знаменателя — дробь independent/successful и независимая
ASR independent/attempts. Правила: каждый процент стоит рядом со СВОЕЙ
дробью; две дроби с разными знаменателями не соседствуют без подписи;
независимая ASR из строки не исчезает.

Проверки ВЫЧИСЛИТЕЛЬНЫЕ, а не сравнением с литералом: строка разбирается,
каждый процент обязан быть немедленно привязан к своей дроби и сходиться с
ней в том же округлении, которым напечатан. Тест, сверяющий строку с
литералом, зазеленел бы и на следующей неверной формулировке.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from memnotsafe.core.models import CampaignResult  # noqa: E402
from memnotsafe.reporting.console import (  # noqa: E402
    asr_provenance_line,
    render_campaign_summary,
)
from memnotsafe.reporting.html_report import render_html  # noqa: E402
from memnotsafe.reporting.metrics import aggregate_metrics  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]

# «дробь (процент)» — единственная допустимая форма соседства процента
_FRAC_PCT = re.compile(r"(\d+)/(\d+)\s*\((\d+)%\)")
_ANY_PCT = re.compile(r"(\d+)%")


def _assert_pcts_own_their_fractions(line: str) -> None:
    """Каждый процент строки: (а) немедленно следует за дробью, (б) равен ей
    в том же округлении (:.0f), которым печать. Иначе — чужой знаменатель."""
    paired = _FRAC_PCT.findall(line)
    every = _ANY_PCT.findall(line)
    assert len(paired) == len(every), (
        f"процент без собственной дроби рядом: {line!r}"
    )
    for num, den, pct in paired:
        assert pct == f"{int(num) / int(den) * 100:.0f}", (
            f"процент {pct}% не сходится со своей дробью {num}/{den}: {line!r}"
        )


def _line(successful, independent, attempts, *, j=0, rt=0, both=0) -> str:
    prov = {
        "successful": successful,
        "independent": independent,
        "judge_raised_only": j,
        "retrieval_tolerated_only": rt,
        "judge_raised_and_retrieval_tolerated": both,
        "judge_raised_stages": {},
        "end_to_end_asr_independent": (
            independent / attempts if attempts else None
        ),
    }
    return asr_provenance_line({"attempts": attempts, "asr_provenance": prov})


# ------------------------------------------------------------------ PASS_IF 1

def test_no_foreign_denominator_adjacency():
    """Раскладки, где independent/successful != independent/attempts: в строке
    нет процента, стоящего рядом с чужой дробью, и обе величины видны."""
    layouts = [
        # (successful, independent, attempts, cells...)
        (4, 1, 5, dict(j=1, rt=1, both=1)),
        (2, 1, 10, dict(rt=1)),
    ]
    for successful, independent, attempts, cells in layouts:
        line = _line(successful, independent, attempts, **cells)
        _assert_pcts_own_their_fractions(line)
        # оба знаменателя явно присутствуют — раскладка не выродилась
        assert f"{independent}/{successful}" in line
        assert f"{independent}/{attempts}" in line


# ------------------------------------------------------------------ PASS_IF 2

def test_pcts_converge_across_four_layouts():
    """Не меньше четырёх раскладок, включая вырожденные: каждая строка
    непуста и каждый процент сходится со своей дробью."""
    layouts = [
        (4, 1, 5, dict(j=1, rt=1, both=1)),
        (10, 3, 12, dict(j=1, rt=1, both=5)),
        (5, 5, 5, dict()),          # все успехи независимы, successful==attempts
        (3, 3, 7, dict()),          # все независимы, НО successful<attempts
        (1, 0, 3, dict(j=1)),       # ноль независимых
        (0, 0, 0, dict()),          # успехов нет
    ]
    for successful, independent, attempts, cells in layouts:
        line = _line(successful, independent, attempts, **cells)
        assert line, (successful, independent, attempts)
        _assert_pcts_own_their_fractions(line)


# ------------------------------------------------------------------ PASS_IF 3

def test_independent_attempts_share_still_visible():
    """(4, 1, 5): доля от попыток не исчезла — видна и дробью, и процентом."""
    line = _line(4, 1, 5, j=1, rt=1, both=1)
    assert "1/5" in line
    assert "20%" in line


# ------------------------------------------------------------------ PASS_IF 4

def test_mechanisms_named_and_silent():
    """Смешанная раскладка называет все три сработавших механизма; раскладка
    с одним механизмом молчит о несработавших (поимённо, без подстрочных
    ложных срабатываний)."""
    mixed = _line(4, 1, 5, j=1, rt=1, both=1)
    assert "поднято судьёй" in mixed
    assert "на ненаблюдённом retrieval" in mixed
    assert "поднято судьёй при ненаблюдённом retrieval" in mixed

    rt_only = _line(2, 1, 2, rt=1)
    assert "судьёй" not in rt_only          # ни judge-, ни двойного механизма
    assert "ненаблюдённом retrieval" in rt_only

    j_only = _line(2, 1, 2, j=1)
    assert "ненаблюдённом" not in j_only    # retrieval-механизмы молчат


# ------------------------------------------------------------------ PASS_IF 5

def test_degenerate_cases_still_print():
    all_indep = _line(5, 5, 5)
    assert all_indep and "все успехи независимы" in all_indep
    _assert_pcts_own_their_fractions(all_indep)

    none = _line(0, 0, 0)
    assert none and "успехов нет" in none


# ------------------------------------------------------------------ PASS_IF 6

def test_console_and_html_captions_identical():
    """Консольная строка и подпись в сгенерированном HTML совпадают дословно
    (после html.escape/снятия экранирования)."""
    from test_asr_provenance import _Rep, _ok_stages, _result

    results = [
        _result(stages=_ok_stages()),
        _result(stages=_ok_stages(judge_stages=("retrieval",))),
        _result(stages=_ok_stages(retrieval=None)),
    ]
    m = aggregate_metrics(results)
    campaign = CampaignResult(
        run_id="RUN-R2", scenario_id="prov", attempts=3, results=results,
        aggregate_metrics=m,
    )
    rep = _Rep()
    render_campaign_summary(rep, campaign, html_path="x.html")
    console_line = next(l for l in rep.lines if "независимых" in l)

    page = render_html(campaign)
    m_p = re.search(r'class="summary-grid".*?</div>\s*<p>(.*?)</p>', page, re.S)
    assert m_p, "подпись после summary-grid не найдена"
    assert html.unescape(m_p.group(1)) == console_line
    # и вычислительный замок на живой строке от реальных метрик
    _assert_pcts_own_their_fractions(console_line)


# ------------------------------------------------------------------ PASS_IF 7

def test_no_private_cross_module_imports_in_src():
    """Греп по src/: ни одного импорта приватного (подчёркнутого) ИМЕНИ из
    модулей memnotsafe — приём объявлен публичным именем, не тихим исключением.
    Локальный алиас (`import public_name as _local`) — не нарушение: приватно
    должно быть имя в своём модуле, а не псевдоним у импортёра."""
    pattern = re.compile(r"from (memnotsafe[\w.]*) import ([^\n(#]+)")
    offenders = []
    for py in (_ROOT / "src").rglob("*.py"):
        for m in pattern.finditer(py.read_text(encoding="utf-8")):
            for piece in m.group(2).split(","):
                imported = piece.split(" as ")[0].strip()
                if imported.startswith("_"):
                    offenders.append(f"{py}: {m.group(0).strip()}")
    assert not offenders, offenders
