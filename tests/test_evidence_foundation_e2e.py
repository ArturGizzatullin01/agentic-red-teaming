"""tests/test_evidence_foundation_e2e.py — Этап 7 (фича 007): интеграция и
replay. Доказывает матрицу миссии офлайн (mock/stub, без сети):

1) успешный сценарий; 2) честный отрицательный; 3) UNKNOWN из-за отсутствующей
телеметрии; 4) отклонённый rewrite; 5) исчерпанный бюджет; 6) транспортная
ошибка; 7) незавершённый пакет; 8) повреждение артефакта; 9) чтение
исторического run. Публичный CLI-контракт не меняется.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from memnotsafe import cli
from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.attempt import (
    OUTCOME_BUDGET_EXHAUSTED,
    OUTCOME_REWRITE_ACCEPTED,
    OUTCOME_REWRITE_REJECTED,
    OUTCOME_TRANSPORT_ERROR,
    OUTCOME_UNKNOWN,
    read_history,
)
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec
from memnotsafe.core.experiment import read_experiment
from memnotsafe.core.ledger import (
    OP_ATTACKER_LLM,
    OP_TARGET_CALL,
    PHASE_BLOCKED,
    PHASE_PLANNED,
    PHASE_UNKNOWN_OUTCOME,
    read_ledger,
)
from memnotsafe.evidence.bundle import (
    BundleError,
    STATUS_UNAVAILABLE,
    find_bundles,
    read_bundle,
    verify_run_bundles,
)

_SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
_SEED_CORPUS = Path("corpora/escalation-seed.yaml")


def _scenario(tmp_path: Path, *, corpus=None, family="cross_user_bac", vulnerable=True):
    return Scenario(
        id=family, path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock", extra={} if vulnerable else {"vulnerable": False}),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family=family, repetitions=1, corpus_path=corpus,
    )


# ------------------------------------------------- 1) успешный сценарий

def test_success_scenario_full_artifact_chain(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run"), "--json"])
    assert rc == 0
    capsys.readouterr()
    out = tmp_path / "run"
    assert read_experiment(out) is not None
    assert find_bundles(out)
    entries = read_history(out / "attempts.jsonl")
    assert any(e.outcome == "completed_success" for e in entries)
    # replay офлайн: верификация пакетов проходит, отчёт собирается
    assert verify_run_bundles(out) >= 1
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["findings_counts"] == {"SUCCESS": 1}


# ------------------------------------------------- 2) честный отрицательный

def test_honest_negative_full_chain(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac_protected.yaml"),
                   "--output", str(tmp_path / "run")])
    assert rc == 0  # непробитие атаки: exit 0, не ошибка
    capsys.readouterr()
    rc = cli.main(["report", "--input", str(tmp_path / "run"), "--output", str(tmp_path / "rep")])
    assert rc == 0
    findings = json.loads((tmp_path / "rep" / "findings.json").read_text(encoding="utf-8"))
    assert all(f["status"] == "NOT_EXPLOITABLE" for f in findings)


# ---------------------------------- 3) UNKNOWN из-за отсутствующей телеметрии

class _BlindMock(MockTarget):
    """Mock без телеметрии памяти: snapshot None — наблюдение невозможно."""

    async def snapshot(self):
        return None


def test_unknown_outcome_from_missing_telemetry(tmp_path) -> None:
    scenario = _scenario(tmp_path)
    out = tmp_path / "run"
    result = asyncio.run(Campaign(scenario, _BlindMock(vulnerable=True), out).run())
    assert result.results[0].success is False  # UNKNOWN не становится успехом
    entries = read_history(out / "attempts.jsonl")
    completed = [e for e in entries if e.attempt_no >= 1]
    assert completed and completed[-1].outcome == OUTCOME_UNKNOWN
    # в пакете слоты снимков честно unavailable (не absent, не «события нет»)
    bundle = read_bundle(next(iter(find_bundles(out).values())))
    assert bundle.slots["m1"].status == STATUS_UNAVAILABLE
    assert bundle.slots["m2"].status == STATUS_UNAVAILABLE


# ------------------------------------------------- 4) отклонённый rewrite

def test_rejected_rewrite_e2e(tmp_path) -> None:
    from memnotsafe.generation.config import AttackerConfig

    goal_change = json.dumps({
        "payload": "новый текст", "trigger": "новый вопрос",
        "expected_effect": {"type": "response_reflects_adoption", "markers": ["X"]},
        "signal_strength": "weak",
    }, ensure_ascii=False)
    cfg = AttackerConfig(provider="stub", scripted=[goal_change], budget=5)
    out = tmp_path / "run"
    asyncio.run(Campaign(_scenario(tmp_path, corpus=_SEED_CORPUS, family="generated"),
                         MockTarget(vulnerable=True), out,
                         attacker_config=cfg, online=True, online_attempts=3).run())
    entries = read_history(out / "attempts.jsonl")
    assert any(e.outcome == OUTCOME_REWRITE_REJECTED for e in entries)
    ledger = read_ledger(out / "budget-ledger.jsonl")
    planned = [e for e in ledger if e.operation == OP_ATTACKER_LLM and e.phase == PHASE_PLANNED]
    assert planned  # вызов атакующей LLM оплачен
    assert not any(e.candidate_id and e.candidate_id != entries[0].case_id
                   and e.attempt_no >= 1 for e in entries)  # до target не дошло


def test_accepted_rewrite_e2e_lineage(tmp_path) -> None:
    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.offline import escalation_stub_script

    cfg = AttackerConfig(
        provider="stub", scripted=[escalation_stub_script() for _ in range(4)], budget=10
    )
    out = tmp_path / "run"
    asyncio.run(Campaign(_scenario(tmp_path, corpus=_SEED_CORPUS, family="generated"),
                         MockTarget(vulnerable=True), out,
                         attacker_config=cfg, online=True, online_attempts=4).run())
    entries = read_history(out / "attempts.jsonl")
    accepted = [e for e in entries if e.outcome == OUTCOME_REWRITE_ACCEPTED]
    assert accepted and all(a.parent_candidate_id for a in accepted)


def test_multistep_escalation_bundles_match_history(tmp_path) -> None:
    """Многошаговый негативный E2E (фикс приёмки P1): reject → попытка 2 →
    попытка 3, каждая попытка со СВОИМ пакетом; attempt_no/parent пакетов
    согласованы с attempts.jsonl; леджер не дублирует списание."""
    from memnotsafe.generation.config import AttackerConfig

    goal_change = json.dumps({
        "payload": "новый текст", "trigger": "новый вопрос",
        "expected_effect": {"type": "response_reflects_adoption", "markers": ["X"]},
        "signal_strength": "weak",
    }, ensure_ascii=False)
    seed_effect = {"type": "cross_user_data_access", "tool": "portfolio_get_positions_valuation",
                   "attacker_user_id": "1001", "victim_user_id": "1002"}
    boring = json.dumps({
        "payload": "заметка без правил и маркеров", "trigger": "что в памяти?",
        "expected_effect": seed_effect, "signal_strength": "weak",
    }, ensure_ascii=False)
    cfg = AttackerConfig(
        provider="stub", scripted=[goal_change, boring, boring, boring], budget=10
    )
    out = tmp_path / "run"
    result = asyncio.run(Campaign(_scenario(tmp_path, corpus=_SEED_CORPUS, family="generated"),
                                  MockTarget(vulnerable=True), out,
                                  attacker_config=cfg, online=True, online_attempts=4).run())
    entries = read_history(out / "attempts.jsonl")
    bundles = find_bundles(out)
    # цепочка: registered → completed(1) → rejected → accepted(c2) → completed(2)
    #          → accepted(c3) → completed(3)
    accepted = [e for e in entries if e.outcome == OUTCOME_REWRITE_ACCEPTED]
    assert len(accepted) >= 2, "многошаговый прогон обязан иметь ≥2 принятых rewrite"
    completed = [e for e in entries if e.attempt_no >= 1 and e.outcome in
                 ("completed_success", "completed_failure", "unknown")]
    assert len(completed) == 3  # начальная + 2 переписанные попытки
    # каждая завершённая попытка имеет СВОЙ пакет с совпадающим lineage
    for rec in completed:
        bundle = read_bundle(out / "bundles" / rec.candidate_id)
        assert bundle.attempt_no == rec.attempt_no
        assert bundle.candidate_id == rec.candidate_id
        assert bundle.case_id == rec.case_id  # логический кейс один
    # родительская связь по хронологии: parent кандидата следующей завершённой
    # попытки = кандидат предыдущей (номера попыток — счётчик итераций
    # эскалации, отклонённый rewrite тоже тратит номер, поэтому 1,3,4…)
    ordered = sorted(completed, key=lambda r: r.attempt_no)
    for prev, cur in zip(ordered, ordered[1:]):
        cur_bundle = read_bundle(out / "bundles" / cur.candidate_id)
        assert cur_bundle.parent_candidate_id == prev.candidate_id
        assert cur_bundle.attempt_no == cur.attempt_no
    # финальный результат ссылается на свой пакет
    assert result.results[0].evidence["evidence_bundle"] == f"bundles/{result.results[0].case_id}"
    # replay цел (все пакеты завершены и верифицированы)
    assert verify_run_bundles(out) == len(bundles)


# ------------------------------------------------- 5) исчерпанный бюджет

def test_budget_exhausted_e2e(tmp_path) -> None:
    from memnotsafe.generation.config import AttackerConfig

    goal_change = json.dumps({
        "payload": "н", "trigger": "в",
        "expected_effect": {"type": "response_reflects_adoption", "markers": ["X"]},
        "signal_strength": "weak",
    }, ensure_ascii=False)
    cfg = AttackerConfig(provider="stub", scripted=[goal_change], budget=1)
    out = tmp_path / "run"
    asyncio.run(Campaign(_scenario(tmp_path, corpus=_SEED_CORPUS, family="generated"),
                         MockTarget(vulnerable=True), out,
                         attacker_config=cfg, online=True, online_attempts=4).run())
    assert any(e.outcome == OUTCOME_BUDGET_EXHAUSTED for e in read_history(out / "attempts.jsonl"))
    assert any(e.phase == PHASE_BLOCKED for e in read_ledger(out / "budget-ledger.jsonl"))


# ------------------------------------------------- 6) транспортная ошибка

def test_transport_error_e2e_cli_exit_1(tmp_path, capsys, monkeypatch) -> None:
    from memnotsafe.core.runner import RunnerError

    async def broken_run_attack(*args, **kwargs):
        raise RunnerError("стенд недоступен")

    monkeypatch.setattr("memnotsafe.core.campaign.run_attack", broken_run_attack)
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1  # runtime-ошибка: exit 1 (console-output.md)
    assert json.loads(captured.err)["outcome"] == "error"
    assert any(e.outcome == OUTCOME_TRANSPORT_ERROR
               for e in read_history(tmp_path / "run" / "attempts.jsonl"))
    assert any(e.operation == OP_TARGET_CALL and e.phase == PHASE_UNKNOWN_OUTCOME
               for e in read_ledger(tmp_path / "run" / "budget-ledger.jsonl"))


# ------------------------------------------------- 7) незавершённый пакет

def test_incomplete_bundle_is_not_mistaken_for_complete(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run")])
    assert rc == 0
    capsys.readouterr()  # буфер run не подмешивается к проверкам report
    out = tmp_path / "run"
    case_dir = next(iter(find_bundles(out).values()))
    case_dir.joinpath("manifest.json").unlink()  # сбой до атомарного replace
    # (а) читатель отказывается выдать незавершённый за завершённый
    with pytest.raises(BundleError, match="незавершён"):
        read_bundle(case_dir)
    # (b) find_bundles его не считает завершённым
    assert find_bundles(out) == {}
    # (c) replay НЕ прозевает незавершённый пакет: runtime-ошибка данных → exit 1
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert "незавершённый" in json.loads(captured.err)["data"]["message"]


def test_bundle_failure_before_mkdir_replay_exit_1(tmp_path, capsys, monkeypatch) -> None:
    """E2E (фикс приёмки P1-2, повтор): сбой записи пакета ДО создания каталога
    (OSError на mkdir) — evidence_error в истории, каталогов нет; replay обязан
    вернуть exit 1, а не «успешно ноль пакетов»."""
    from memnotsafe.evidence import bundle as bundle_mod

    def disk_full(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(bundle_mod, "write_bundle", disk_full)
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run")])
    captured = capsys.readouterr()
    assert rc == 0  # результаты сохранены штатно
    out = tmp_path / "run"
    assert find_bundles(out) == {}  # каталогов нет — прежняя проверка слепа
    assert any(e.outcome == "evidence_error"
               for e in read_history(out / "attempts.jsonl"))

    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1  # replay НЕ проходит с пустым stderr
    assert captured.out == ""
    assert "не записан" in json.loads(captured.err)["data"]["message"]


def test_completed_attempt_without_bundle_detected(tmp_path, capsys) -> None:
    """«Наличие ожидаемых пакетов»: завершённая попытка, чей пакет удалён,
    обнаруживается сверкой с attempts.jsonl → replay exit 1."""
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run")])
    assert rc == 0
    capsys.readouterr()
    out = tmp_path / "run"
    case_dir = next(iter(find_bundles(out).values()))
    shutil.rmtree(case_dir)
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "нет пакета доказательств" in json.loads(captured.err)["data"]["message"]


# ------------------------------------------------- 8) повреждение артефакта

def test_corrupted_artifact_detected_by_replay(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run")])
    assert rc == 0
    capsys.readouterr()
    out = tmp_path / "run"
    case_dir = next(iter(find_bundles(out).values()))
    artifact = next(case_dir.joinpath("artifacts").iterdir())
    original = artifact.read_bytes()
    artifact.write_bytes(b"X" * len(original))  # подмена ТОГО ЖЕ размера: ловит sha256, не размер

    # report --json: stdout пуст, JSON-ошибка в stderr, exit 1 (таблица контракта)
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert json.loads(captured.err)["outcome"] == "error"
    assert "повреждён" in json.loads(captured.err)["data"]["message"]


def test_corrupt_attempts_jsonl_replay_exit_1(tmp_path, capsys) -> None:
    """Повреждённый attempts.jsonl — runtime-ошибка данных: report exit 1 с
    понятным сообщением, не сырой traceback (фикс аудита)."""
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run")])
    assert rc == 0
    capsys.readouterr()
    out = tmp_path / "run"
    (out / "attempts.jsonl").write_text("{oops", encoding="utf-8")
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert "attempts.jsonl" in json.loads(captured.err)["data"]["message"]


def test_manifest_history_mismatch_detected(tmp_path, capsys) -> None:
    """Негативный E2E: манифест существует и цел, но НЕ согласован с историей
    (attempt_no подменён) — replay обязан это поймать, а не проверить «файл
    существует» (фикс аудита Этапа 3)."""
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run")])
    assert rc == 0
    capsys.readouterr()
    out = tmp_path / "run"
    case_dir = next(iter(find_bundles(out).values()))
    manifest_path = case_dir / "manifest.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["attempt_no"] = 7
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert "не согласован" in json.loads(captured.err)["data"]["message"]


# ------------------------------------------------- 9) исторический run

def test_historical_run_without_new_artifacts(tmp_path, capsys) -> None:
    """Run старого формата: только campaign.json из реального writer'а прошлого
    кода (симуляция — удаляем новые файлы). Replay работает, контракты читают
    «нет данных» без выдумывания полей."""
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / "cross_user_bac.yaml"),
                   "--output", str(tmp_path / "run")])
    assert rc == 0
    out = tmp_path / "run"
    capsys.readouterr()
    shutil.rmtree(out / "bundles")
    (out / "experiment.json").unlink()
    (out / "attempts.jsonl").unlink()
    (out / "budget-ledger.jsonl").unlink()

    assert read_experiment(out) is None
    assert read_history(out / "attempts.jsonl") == []
    assert read_ledger(out / "budget-ledger.jsonl") == []
    assert find_bundles(out) == {}
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "success"
