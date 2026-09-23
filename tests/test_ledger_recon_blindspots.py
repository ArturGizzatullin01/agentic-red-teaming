"""tests/test_ledger_recon_blindspots.py — P13-c-r2: два слепых места сверщика
(пост-аудит CLAUDE-AUDIT-POSTMERGE-2026-09-23, находки Ф-1/Ф-2; норматив —
CARD-P13-c-r2-ledger-recon-blindspots §2).

Ф-1: терминальный исход или evidence_error на attempt_no<1 раньше выпадал из
биекции молча (пропуск был чисто числовым, _ZERO_ATTEMPT_OUTCOMES в решении
не участвовало) — теперь находка terminal_outcome_at_zero_attempt; пять
легитимных видов@0 проходят мимо биекции по-прежнему (контроль регресса).

Ф-2: «attacker неактивен (offline-прогон)» раньше утверждалось без взгляда в
леджер — planned-списания при active=false дают честный unknown «артефакт
противоречив» (по прецеденту судьи, НЕ находка); при planned==0 сигнал прежний.

Фикстуры карточки §5.4: (а) completed_success@0 без target_call; (б)
evidence_error@0; (в) пять легитимных видов@0 — без находок; (г) active=false
+ planned>0 — unknown с противоречием, exit 0; (д) active=false + 0 planned —
прежний сигнал; (е) чистая пара прогонов — 0 расхождений.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from memnotsafe.reporting.ledger_recon import main, reconcile
from tests.test_ledger_recon import (
    _append_attempts,
    _attempt_row,
    _codes,
    _entry,
    _ledger_dicts,
    _offline_run,
    _online_run,
    _patch_campaign,
    _unknown_signals,
)


def _mk_inactive_attacker_dir(tmp_path: Path, name: str, *, planned: int) -> Path:
    """Рукодельный каталог: attacker active=false и N planned-списаний с
    РАЗНЫМИ ключами (одинаковые поймались бы сверкой 3 — маскировка)."""
    run_dir = tmp_path / name
    run_dir.mkdir()
    lines = [
        _entry("attacker_llm", "planned", case=f"case-{i}", cand=f"cand-{i}", attempt=1)
        for i in range(planned)
    ]
    (run_dir / "budget-ledger.jsonl").write_text(
        "".join(json.dumps(l, ensure_ascii=False) + "\n" for l in lines), encoding="utf-8")
    (run_dir / "attempts.jsonl").write_text("", encoding="utf-8")
    (run_dir / "campaign.json").write_text(json.dumps(
        {"run_id": name, "metadata": {"attacker": {"active": False}}},
        ensure_ascii=False), encoding="utf-8")
    return run_dir


def test_a_completed_success_at_zero_without_target_call(tmp_path) -> None:
    """(а) completed_success@0, target_call нет — находка Ф-1, только биекция;
    detail несёт case/candidate/attempt."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-zero-terminal"
    shutil.copytree(src, dst)
    _append_attempts(dst, _attempt_row(dst, outcome="completed_success", attempt_no=0))
    report = reconcile([dst])
    assert _codes(report, "bijection") == ["terminal_outcome_at_zero_attempt"]
    finding = report["runs"][0]["checks"]["bijection"]["findings"][0]
    assert "completed_success" in finding["detail"]
    assert "attempt_no=0" in finding["detail"] and "candidate=" in finding["detail"]
    for check in ("phases", "duplicates", "budgets"):
        assert _codes(report, check) == []
    assert report["summary"]["discrepancies"] == 1
    assert main([str(dst)]) == 1


def test_b_evidence_error_at_zero_attempt(tmp_path) -> None:
    """(б) evidence_error@0 — та же находка Ф-1: легитимна только ВТОРАЯ строка
    попытки с реальным attempt_no, не нулевая."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-zero-evidence"
    shutil.copytree(src, dst)
    _append_attempts(dst, _attempt_row(dst, outcome="evidence_error", attempt_no=0,
                                       error="пакет доказательств не записан: OSError"))
    report = reconcile([dst])
    assert _codes(report, "bijection") == ["terminal_outcome_at_zero_attempt"]
    assert "evidence_error" in report["runs"][0]["checks"]["bijection"]["findings"][0]["detail"]
    assert report["summary"]["discrepancies"] == 1
    assert main([str(dst)]) == 1


def test_c_five_legit_kinds_at_zero_stay_silent(tmp_path) -> None:
    """(в) Контроль регресса: все пять легитимных видов@0 (registered,
    budget_exhausted, aborted, rewrite_accepted, rewrite_rejected) — мимо
    биекции молча; замок, чтобы правка Ф-1 не зацепила легитимные строки."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-zero-legit"
    shutil.copytree(src, dst)
    _append_attempts(
        dst,
        _attempt_row(dst, outcome="registered", attempt_no=0),
        _attempt_row(dst, outcome="budget_exhausted", attempt_no=0),
        _attempt_row(dst, outcome="aborted", attempt_no=0, error="сбой атакующей LLM"),
        _attempt_row(dst, outcome="rewrite_accepted", attempt_no=0),
        _attempt_row(dst, outcome="rewrite_rejected", attempt_no=0),
    )
    report = reconcile([dst])
    assert report["summary"]["discrepancies"] == 0
    assert report["runs"][0]["checks"]["bijection"]["findings"] == []
    assert main([str(dst)]) == 0


def test_d_inactive_attacker_with_planned_is_contradiction_unknown(tmp_path) -> None:
    """(г) active=false + planned>0 — честный unknown «артефакт противоречив»,
    НЕ находка и НЕ «offline-прогон»: рукодельные 3 списания с разными
    ключами + реальный эскалационный прогон с отключённым active."""
    hand = _mk_inactive_attacker_dir(tmp_path, "run-contradiction", planned=3)
    report = reconcile([hand])
    assert report["summary"]["discrepancies"] == 0
    assert report["runs"][0]["checks"]["budgets"]["attacker"]["status"] == "unknown"
    signals = _unknown_signals(report)
    assert any("несёт 3 planned-списаний" in s and "артефакт противоречив" in s
               for s in signals)
    assert not any("offline-прогон" in s for s in signals)
    assert main([str(hand)]) == 0

    online = _online_run(tmp_path, "run-online-off")
    planned = sum(1 for l in _ledger_dicts(online)
                  if l["operation"] == "attacker_llm" and l["phase"] == "planned")
    assert planned >= 1

    def deactivate(data: dict) -> None:
        data["metadata"]["attacker"]["active"] = False

    _patch_campaign(online, deactivate)
    report2 = reconcile([online])
    assert report2["summary"]["discrepancies"] == 0
    assert any(f"несёт {planned} planned-списаний" in s for s in _unknown_signals(report2))
    assert main([str(online)]) == 0


def test_e_inactive_attacker_zero_planned_previous_signal(tmp_path) -> None:
    """(д) active=false + planned==0 — прежний сигнал «offline-прогон» без
    изменений (замок точности формулировки Ф-2)."""
    out = _offline_run(tmp_path, "run-offline")
    report = reconcile([out])
    signals = _unknown_signals(report)
    assert any("attacker неактивен (offline-прогон)" in s for s in signals)
    assert not any("противоречив" in s for s in signals)
    assert report["summary"]["discrepancies"] == 0
    assert main([str(out)]) == 0


def test_f_clean_pair_zero_discrepancies(tmp_path) -> None:
    """(е) Чистая пара прогонов — 0 расхождений, exit 0 (карточка §5.4(е))."""
    a = _offline_run(tmp_path, "run-a")
    b = _offline_run(tmp_path, "run-b")
    report = reconcile([a, b])
    assert report["summary"]["discrepancies"] == 0
    assert main([str(a), str(b)]) == 0
