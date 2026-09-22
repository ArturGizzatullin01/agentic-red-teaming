"""tests/test_worker_orchestrate.py — CARD-P13-a: оркестратор N воркеров.

Замки (offline, mock-путь; Docker/стенд не поднимаются):

  1. сбор исходов ВСЕХ воркеров независимо: упавший/убитый (rc != 0)
     не блокирует остальных; rc оркестратора 0 только если все 0;
  2. env-скоуп воркера: MEMNOTSAFE_WORKER_INDEX (1..N) и
     MEMNOTSAFE_LEASE_DIR = <оркестратор>/locks;
  3. orchestrate_campaign: N=2 подпроцесса CLI-кампании на mock-сценарии —
     общий experiment_id в experiment.json обоих run-каталогов (детерминизм
     ExperimentSpec, докстринг worker.py), сводка
     <output>-orchestrator.json с составом/rc/путями;
  4. CLI-команда orchestrate: rc 0, human-сводка в stdout, существующие
     команды не тронуты.

Импорт воркер-модуля внутри тестов (прецедент P12): на чистой базе
карточки модуля нет — RED это падение конкретных тестов, а не collection
error.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

_SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
MOCK_SCENARIO = str(_SCENARIOS / "cross_user_bac.yaml")


def _rc_argv(code: str, *, sleep_s: float = 0.0) -> list[str]:
    body = f"import time{'' if not sleep_s else ''};"
    if sleep_s:
        body += f"time.sleep({sleep_s});"
    body += f"raise SystemExit({code})"
    return [sys.executable, "-c", body]


def test_orchestrate_collects_all_outcomes(tmp_path: Path) -> None:
    from memnotsafe.core.worker import orchestrate, orchestrator_rc
    import asyncio

    outcomes = asyncio.run(orchestrate(
        [_rc_argv("0"), _rc_argv("0", sleep_s=0.05)],
        run_dirs=[tmp_path / "w1", tmp_path / "w2"],
        orchestrator_dir=tmp_path / "orch",
    ))
    assert [o.returncode for o in outcomes] == [0, 0]
    assert [o.index for o in outcomes] == [1, 2]
    assert orchestrator_rc(outcomes) == 0


def test_crashed_worker_does_not_block_others(tmp_path: Path) -> None:
    from memnotsafe.core.worker import orchestrate, orchestrator_rc
    import asyncio

    outcomes = asyncio.run(orchestrate(
        [_rc_argv("4"), _rc_argv("0", sleep_s=0.05)],
        run_dirs=[tmp_path / "w1", tmp_path / "w2"],
        orchestrator_dir=tmp_path / "orch",
    ))
    # упавший воркер собран вместе с выжившим, ни один не потерян
    assert sorted(o.returncode for o in outcomes) == [0, 4]
    assert orchestrator_rc(outcomes) == 1


def test_worker_env_scope_index_and_lease_dir(tmp_path: Path) -> None:
    """Env-скоуп: каждому воркеру свой индекс и общий каталог замков
    оркестратора — воркер_dump фиксирует фактическое окружение процесса."""
    from memnotsafe.core.worker import orchestrate
    import asyncio

    dumps = [tmp_path / f"env{i}.txt" for i in (1, 2)]
    argvs = [
        [sys.executable, "-c",
         "import os, sys; open(sys.argv[1], 'w').write("
         "os.environ.get('MEMNOTSAFE_WORKER_INDEX', '') + '|' "
         "+ os.environ.get('MEMNOTSAFE_LEASE_DIR', ''))", str(dumps[i - 1])]
        for i in (1, 2)
    ]
    asyncio.run(orchestrate(argvs, run_dirs=[tmp_path / "w1", tmp_path / "w2"],
                            orchestrator_dir=tmp_path / "orch"))
    locks = (tmp_path / "orch" / "locks").resolve()
    for i in (1, 2):
        index, lease_dir = dumps[i - 1].read_text(encoding="utf-8").split("|")
        assert index == str(i), (i, index)
        assert Path(lease_dir).resolve() == locks, (i, lease_dir)


def test_orchestrate_campaign_two_mock_workers_share_experiment_id(tmp_path: Path) -> None:
    """Главный замок: 2 воркера CLI-кампании на mock-сценарии — оба run-каталога
    несут ОДИН experiment_id (digest спеки не включает run-каталог), сводка
    фиксирует общность и rc каждого."""
    from memnotsafe.core.worker import orchestrate_campaign, orchestrator_rc
    import asyncio

    out = tmp_path / "orch"
    outcomes, summary_path = asyncio.run(orchestrate_campaign(
        MOCK_SCENARIO, output=out, workers=2, iterations=1))
    assert [o.returncode for o in outcomes] == [0, 0], [(o.index, o.returncode) for o in outcomes]
    assert orchestrator_rc(outcomes) == 0

    ids = []
    for i in (1, 2):
        run_dir = Path(f"{out}-w{i}")
        spec = json.loads((run_dir / "experiment.json").read_text(encoding="utf-8"))
        assert spec["experiment_id"], i
        ids.append(spec["experiment_id"])
        assert (run_dir / "campaign.json").exists(), i
    assert ids[0] == ids[1], "experiment_id обязан быть общим у воркеров"

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["experiment_id_common"] is True
    assert summary["lease_dir"] == str(out / "locks")
    assert Path(summary["lease_dir"]).is_dir()
    assert [w["returncode"] for w in summary["workers"]] == [0, 0]
    assert summary["workers"][0]["run_dir"] == str(Path(f"{out}-w1"))


def test_cli_orchestrate_command(tmp_path: Path, capsys) -> None:
    """CLI-врезка: отдельная команда orchestrate — rc 0, human-сводка в
    stdout, сводный JSON рядом с run-каталогами воркеров."""
    from memnotsafe import cli

    out = tmp_path / "cli-orch"
    rc = cli.main(["orchestrate", "--scenario", MOCK_SCENARIO, "--output", str(out),
                   "--workers", "2", "--iterations", "1"])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "orchestrator" in printed.lower()
    summary = json.loads(Path(f"{out}-orchestrator.json").read_text(encoding="utf-8"))
    assert summary["experiment_id_common"] is True
    assert len(summary["workers"]) == 2


def test_cli_existing_commands_untouched(tmp_path: Path, capsys) -> None:
    """Контракт соседа: run-команда байт-в-байт прежнего поведения после
    врезки orchestrate (rc 0, прежние маркеры human-вывода)."""
    from memnotsafe import cli

    rc = cli.main(["run", "--scenario", MOCK_SCENARIO, "--output", str(tmp_path / "run")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AGENTIC MEMORY RED TEAMING" in out
    assert "Report:" in out


# ================================ CARD-P13-a-r2: честный сбор исходов + контракт


def test_spawn_failure_keeps_live_worker_outcome_and_summary(tmp_path: Path) -> None:
    """P13-a-r2 FINDING-2: исключение спауна одного воркера (бинарь не найден)
    НЕ теряет исходы остальных: у нестартовавшего — честный маркер
    (returncode=None + error), живой собран, сводка записана, rc != 0."""
    from memnotsafe.core.worker import (
        orchestrate,
        orchestrator_rc,
        write_orchestrator_summary,
    )
    import asyncio

    broken = [str(tmp_path / "no-such-binary"), "--run"]
    live = _rc_argv("0", sleep_s=0.05)
    outcomes = asyncio.run(orchestrate(
        [broken, live],
        run_dirs=[tmp_path / "w1", tmp_path / "w2"],
        orchestrator_dir=tmp_path / "orch",
    ))
    assert len(outcomes) == 2, "исход нестартовавшего воркера потерян целиком"
    w1, w2 = outcomes
    assert w1.returncode is None and w1.error, "нет честного маркера ошибки спауна"
    assert w2.returncode == 0, "исход живого воркера потерян из-за соседа"
    assert orchestrator_rc(outcomes) == 1

    summary_path = write_orchestrator_summary(
        tmp_path / "orch-summary.json", outcomes, lease_dir=tmp_path / "orch" / "locks"
    )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["workers"][0]["returncode"] is None
    assert summary["workers"][0]["error"] == w1.error
    assert summary["workers"][1]["returncode"] == 0
    # experiment_id у нестартовавшего — честный null (норма уже есть)
    assert summary["workers"][0]["experiment_id"] is None


def test_experiment_id_common_false_for_different_ids(tmp_path: Path) -> None:
    """FINDING-3 (замок против зашитого True): разные experiment_id у
    run-каталогов → experiment_id_common False; смешанный случай (id только
    у одного) — тоже False: общность требует ВСЕ воркеры с одним id."""
    from memnotsafe.core.worker import WorkerOutcome, write_orchestrator_summary

    for i, exp_id in ((1, "exp-aaa"), (2, "exp-bbb")):
        run_dir = tmp_path / f"w{i}"
        run_dir.mkdir()
        (run_dir / "experiment.json").write_text(
            json.dumps({"experiment_id": exp_id}), encoding="utf-8"
        )
    outcomes = [
        WorkerOutcome(index=i, argv=["x"], run_dir=tmp_path / f"w{i}", returncode=0)
        for i in (1, 2)
    ]
    summary = json.loads(write_orchestrator_summary(
        tmp_path / "s1.json", outcomes, lease_dir=tmp_path
    ).read_text(encoding="utf-8"))
    assert summary["experiment_id_common"] is False

    (tmp_path / "w2" / "experiment.json").unlink()  # незавершившийся воркер
    summary2 = json.loads(write_orchestrator_summary(
        tmp_path / "s2.json", outcomes, lease_dir=tmp_path
    ).read_text(encoding="utf-8"))
    assert summary2["experiment_id_common"] is False
    assert summary2["workers"][1]["experiment_id"] is None


def test_run_dirs_mismatch_raises_value_error(tmp_path: Path) -> None:
    """FINDING-3: run_dirs короче worker_argv — контрактный ValueError с
    сообщением (имя контракта в тексте), а не IndexError из задачи."""
    from memnotsafe.core.worker import orchestrate
    import asyncio

    with pytest.raises(ValueError, match="run_dirs"):
        asyncio.run(orchestrate(
            [_rc_argv("0")], run_dirs=[], orchestrator_dir=tmp_path / "orch"
        ))


def test_cli_orchestrate_invalid_workers_is_clean_error(tmp_path: Path, capsys) -> None:
    """CLI-слой: --workers 0 — управляемый отказ (сообщение + exit 1, БЕЗ
    трейсбека), паттерн соседних команд cli.py (reporter.emit_error)."""
    from memnotsafe import cli

    rc = cli.main(["orchestrate", "--scenario", MOCK_SCENARIO,
                   "--output", str(tmp_path / "orch"), "--workers", "0"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "workers" in (captured.err + captured.out)
    assert "Traceback" not in captured.err + captured.out
