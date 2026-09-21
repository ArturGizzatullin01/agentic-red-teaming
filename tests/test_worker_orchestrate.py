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
