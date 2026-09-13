"""tests/test_experiment_spec_p10b.py — P10b (фича 007): ExperimentSpec.

Проверяется: spec пишется кампанией ДО попыток и связан с пакетами
доказательств; experiment_id — digest содержимого (стабилен, чувствителен
к конфигурации, не зависит от летучих полей); неизвестные ревизии помечены
явно; секреты не попадают в spec; исторические runs читаются толерантно.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec
from memnotsafe.core.experiment import (
    ExperimentError,
    build_experiment_spec,
    read_experiment,
)
from memnotsafe.evidence.bundle import find_bundles, read_bundle


def _scenario(tmp_path: Path, *, family="cross_user_bac", reps=1, yaml_text=None) -> Scenario:
    yaml_path = tmp_path / f"{family}-{reps}.yaml"
    yaml_path.write_text(yaml_text or f"id: {family}\nattack:\n  family: {family}\n", encoding="utf-8")
    return Scenario(
        id=family, path=yaml_path,
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family=family, repetitions=reps,
    )


def _run(tmp_path: Path, scenario: Scenario, out_name="run"):
    out = tmp_path / out_name
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    return result, out


def test_experiment_json_written_before_attempts_and_linked_to_bundles(tmp_path) -> None:
    scenario = _scenario(tmp_path)
    _result, out = _run(tmp_path, scenario)
    spec = read_experiment(out)
    assert spec is not None
    assert spec.scenario_id == "cross_user_bac"
    # связь с пакетами доказательств: каждый bundle несёт experiment_id
    bundles = find_bundles(out)
    assert bundles
    for path in bundles.values():
        assert read_bundle(path).experiment_id == spec.experiment_id
    # spec самосогласован: id == digest содержимого
    from memnotsafe.core.goal_contract import sha256_hex

    assert spec.experiment_id == sha256_hex(spec.digest_source())


def test_experiment_id_stable_and_config_sensitive(tmp_path) -> None:
    scenario_a = _scenario(tmp_path, reps=1)
    a1 = build_experiment_spec(scenario_a)
    a2 = build_experiment_spec(scenario_a)
    assert a1.experiment_id == a2.experiment_id  # воспроизводимость

    scenario_b = _scenario(tmp_path, reps=3)
    assert build_experiment_spec(scenario_b).experiment_id != a1.experiment_id

    # содержимое сценария YAML входит в digest значимых файлов
    scenario_c = _scenario(tmp_path, yaml_text="id: cross_user_bac\n# другой комментарий\n")
    assert build_experiment_spec(scenario_c).experiment_id != a1.experiment_id


def test_volatile_fields_outside_digest(tmp_path) -> None:
    s = _scenario(tmp_path)
    spec1 = build_experiment_spec(s)
    spec2 = build_experiment_spec(s)  # created_at другой (микросекунды)
    assert spec1.volatile["created_at"] != spec2.volatile["created_at"]
    assert spec1.experiment_id == spec2.experiment_id
    assert "volatile" not in spec1.digest_source()


def test_unknown_revisions_are_explicit(tmp_path) -> None:
    spec = build_experiment_spec(_scenario(tmp_path))
    assert spec.target["model_name"] == "unknown"  # у mock модель не объявлена
    assert spec.attacker["chat_prompt_revision"] == "unknown"  # P09-full закроет
    assert spec.file_digests["scenario_yaml"] != "unknown"  # файл сценария существует


def test_no_secrets_only_env_names(tmp_path) -> None:
    spec = build_experiment_spec(_scenario(tmp_path))
    payload = json.dumps(spec.to_dict(), ensure_ascii=False)
    assert "OPENROUTER_API_KEY" in payload  # имя переменной — можно
    assert "sk-" not in payload  # значений ключей в spec нет в принципе
    assert "api_key" in json.dumps(spec.judge)  # секция судьи содержит только имя


def test_corpus_digest_present_for_generated(tmp_path) -> None:
    from tests.test_reporting_replay import _corpus

    corpus_path = _corpus(tmp_path)
    scenario = Scenario(
        id="generated_support", path=tmp_path / "gen.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="generated", repetitions=1, corpus_path=corpus_path,
    )
    spec = build_experiment_spec(scenario)
    assert spec.corpus is not None
    assert spec.corpus["path"] == str(corpus_path)
    assert spec.corpus["sha256"] == __import__("hashlib").sha256(
        corpus_path.read_bytes()
    ).hexdigest()


def test_read_experiment_tolerant_and_strict(tmp_path) -> None:
    # исторический run без experiment.json → None, ничего не выдумывается
    assert read_experiment(tmp_path) is None

    scenario = _scenario(tmp_path)
    _result, out = _run(tmp_path, scenario, out_name="run2")
    spec = read_experiment(out)
    assert spec is not None

    # подмена experiment_id обнаруживается при чтении
    raw = json.loads((out / "experiment.json").read_text(encoding="utf-8"))
    raw["experiment_id"] = "0" * 64
    (out / "experiment.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ExperimentError, match="подменена"):
        read_experiment(out)


def test_writer_prompt_revision_is_real_digest(tmp_path) -> None:
    """Ревизия writer-промпта — sha256 реального исходника, не заглушка:
    изменение промпта создаёт новый эксперимент (требование миссии)."""
    import hashlib

    import memnotsafe.generation.prompts as prompts_module

    spec = build_experiment_spec(_scenario(tmp_path))
    expected = hashlib.sha256(Path(prompts_module.__file__).read_bytes()).hexdigest()
    assert spec.attacker["writer_prompt_sha256"] == expected
