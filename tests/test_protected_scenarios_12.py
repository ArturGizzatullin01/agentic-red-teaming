"""tests/test_protected_scenarios_12.py — карточка E (ПАЧКА 2): protected-двойники
для 12 семей (первая половина W11).

Аудит ПАЧКИ 1 показал: protected-сценарий был только у 2 из 16 семей —
негативный контроль остальных существовал лишь как инвентаризация в тесте, а не
как запускаемый артефакт (нельзя дать оператору, положить в бенчмарк P14).
Здесь проверяются САМИ двойники, инвентаризацию семей делает
tests/test_protected_symmetry_audit.py (ветка пачки 1) и она тут не дублируется:

1. Структура: каждый двойник грузится штатным load_scenario (core/config.py),
   target.vulnerable is False, attack.family равен семье исходника, а построчный
   дифф с исходником меняет ТОЛЬКО комментарии (включая пустую строку-разделитель
   блока комментария), строку id и строку vulnerable — «то же самое, но
   protected».
2. Прогон: одна попытка на семью на моке (это проверка сценария, не измерение
   ASR) — composite success=False и external_effect=False. Ожидания — из
   измеренного аудита ПАЧКИ 1 (11 семей: adoption+external_effect; scope_escalation:
   только external_effect), они же записаны в комментарии каждого двойника.
3. Страж: у false_precedent protected-двойника НЕТ и быть не может — её
   protected-ветка измеримо слепа (PRECEDENT-ветка mock.py не проверяет
   auth_mode, находка W11 аудита ПАЧКИ 1): «негативный контроль», который
   ничего не контролирует, в репозиторий не кладём.
"""

from __future__ import annotations

import asyncio
import difflib
import sys
from pathlib import Path

import pytest
import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.core.campaign import Campaign  # noqa: E402
from memnotsafe.core.config import build_adapter, load_scenario  # noqa: E402

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"

# (двойник, исходник, семья) — все файлы существуют в scenarios/ на этой ветке.
TWINS: tuple[tuple[str, str, str], ...] = (
    ("consent-laundering-protected.yaml", "consent-laundering.yaml", "consent_laundering"),
    ("contact-supersede-protected.yaml", "contact-supersede.yaml", "contact_supersede"),
    ("cross-lingual-insertion-protected.yaml", "cross-lingual-insertion.yaml", "cross_lingual_insertion"),
    ("cross-topic-smuggle-protected.yaml", "cross-topic-smuggle.yaml", "cross_topic_smuggle"),
    ("direct_poisoning-protected.yaml", "direct_poisoning.yaml", "direct_poisoning"),
    ("document-regulation-graft-protected.yaml", "document-regulation-graft.yaml", "document_regulation_graft"),
    ("fake-shared-past-protected.yaml", "fake-shared-past.yaml", "fake_shared_past"),
    ("procedural-graft-protected.yaml", "procedural-graft.yaml", "procedural_graft"),
    ("recommendation-hijack-protected.yaml", "recommendation-hijack.yaml", "recommendation_hijack"),
    ("scope_escalation-protected.yaml", "scope_escalation.yaml", "scope_escalation"),
    ("system-log-impersonation-protected.yaml", "system-log-impersonation.yaml", "system_log_impersonation"),
    ("tool-error-echo-protected.yaml", "tool-error-echo.yaml", "tool_error_echo_poisoning"),
)

# НЕ имеют protected-двойников: cross_user_bac и tool_argument_hijack — уже есть
# (cross_user_bac_protected.yaml / tool_argument_hijack_protected.yaml);
# false_precedent — намеренно (W11, слепая protected-ветка, страж ниже);
# generated — корпусная семья с тремя вариантами, канонический выбор неоднозначен.


def _is_comment_or_blank(line: str) -> bool:
    s = line.strip()
    return s == "" or s.startswith("#")


def _is_id_line(line: str) -> bool:
    return line.startswith("id:")


def _is_vulnerable_line(line: str) -> bool:
    return line.strip().startswith("vulnerable:")


@pytest.mark.parametrize(
    "twin,src,family",
    TWINS,
    ids=[t[0][:-5] for t in TWINS],
)
def test_twin_structure(twin: str, src: str, family: str) -> None:
    # PASS_IF-2: штатная загрузка + уязвимость выключена + семья та же.
    twin_path = SCENARIOS / twin
    src_path = SCENARIOS / src
    scenario = load_scenario(twin_path)
    src_scenario = load_scenario(src_path)
    assert scenario.target.extra.get("vulnerable") is False, (
        f"{twin}: target.vulnerable должен быть False"
    )
    assert src_scenario.target.extra.get("vulnerable") is True, (
        f"{src}: исходник канонической пары обязан быть vulnerable (проверь, что "
        "двойник сравнивается с правильным файлом)"
    )
    assert scenario.attack_family == family == src_scenario.attack_family, (
        f"{twin}: attack.family разошёлся с исходником ({scenario.attack_family!r} "
        f"vs {src_scenario.attack_family!r})"
    )

    # Текстовый дифф: изменения только в комментариях/пустых разделителях,
    # строке id и строке vulnerable.
    a = src_path.read_text(encoding="utf-8").split("\n")
    b = twin_path.read_text(encoding="utf-8").split("\n")
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        for line in a[i1:i2] + b[j1:j2]:
            changed_kind = (
                "комментарий/пустая строка" if _is_comment_or_blank(line)
                else "id" if _is_id_line(line)
                else "vulnerable" if _is_vulnerable_line(line)
                else None
            )
            assert changed_kind is not None, (
                f"{twin}: дифф с {src} задел недопустимую строку {line!r} "
                f"(опкод {tag}); двойник обязан отличаться только комментариями, "
                "id и vulnerable"
            )


@pytest.mark.parametrize(
    "twin,family",
    [(t[0], t[2]) for t in TWINS],
    ids=[t[0][:-5] for t in TWINS],
)
def test_twin_protected_run(twin: str, family: str, tmp_path: Path) -> None:
    # PASS_IF-3: один прогон на семью — composite success=False,
    # external_effect=False. Защита мока «на использовании»: write/persistence/
    # (retrieval) остаются True, падает применение правила (и принятие — у всех,
    # кроме scope_escalation, где adoption от auth-режима не зависит).
    scenario = load_scenario(SCENARIOS / twin)
    target = build_adapter(scenario)  # MockTarget(vulnerable=False) из yaml
    out = tmp_path / family
    campaign = Campaign(scenario, target, out)
    result = asyncio.run(campaign.run(repetitions=1))
    assert len(result.results) == 1
    attempt = result.results[0]
    assert attempt.success is False, (
        f"{twin}: protected-прогон unexpectedly composite success — двойник "
        "перестал быть негативным контролем (ср. комментарий в самом сценарии)"
    )
    external = attempt.stage("external_effect")
    assert external is not None and external.success is False, (
        f"{twin}: external_effect обязан быть False в protected (защита «на "
        "использовании» блокирует именно применение)"
    )


def test_false_precedent_has_no_protected_twin() -> None:
    # PASS_IF-4: страж W11. PRECEDENT-ветка mock.py (лимит по approval #) не
    # проверяет auth_mode — protected-прогон false_precedent измеримо неотличим
    # от vulnerable (полный профиль, «PROTECTED-СЛЕП» в аудите ПАЧКИ 1).
    # Сценарий vulnerable:false для неё был бы «негативным контролем», который
    # ничего не контролирует. Если этот тест упал — сначала почини protected-
    # ветку семьи отдельной карточкой, затем снимай страж осознанно.
    blind: list[str] = []
    for path in sorted(SCENARIOS.glob("*.yaml")):
        try:
            cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(cfg, dict):
            continue
        family = (cfg.get("attack") or {}).get("family")
        if family == "false_precedent" and (cfg.get("target") or {}).get("vulnerable") is False:
            blind.append(path.name)
    assert not blind, (
        "у семьи false_precedent появился protected-сценарий "
        f"({', '.join(blind)}), но её protected-ветка слепа (W11: PRECEDENT в "
        "mock.py не проверяет auth_mode) — такой негативный контроль ничего не "
        "контролирует. Сначала почини ветку, потом добавляй двойник."
    )
