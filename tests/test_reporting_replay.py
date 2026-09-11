"""tests/test_reporting_replay.py — этапы 2–3 пакета post-smoke и FIX-08:
(1) восстановление отчёта по family (scenario_id ≠ family, legacy-формат);
(2) честная end_to_end_asr (числитель — composite success, не external_effect);
(3) family доезжает до campaign.json настоящим writer'ом, а не фикстурой.

Фикстуры этапов 2–3 — campaign.json минимальной формы (см.
core/campaign._campaign_to_dict), без сети и без адаптеров: replay обязан
работать на сохранённых артефактах. Раздел FIX-08 наоборот запускает настоящую
кампанию на офлайновом mock — проверяется как раз writer.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, JudgeSpec, Scenario, TargetSpec
from memnotsafe.core.models import AttackResult, StageResult
from memnotsafe.judge.client import JudgeCallResult
from memnotsafe.judge.runtime import LLMJudge
from memnotsafe.reporting.findings import build_finding
from memnotsafe.reporting.metrics import aggregate_metrics


def _stage(stage: str, success: bool | None) -> StageResult:
    return StageResult(stage=stage, success=success, reason="тест")


def _result(*, scenario_id: str = "my-experiment", family: str = "direct_poisoning",
            success: bool = False, stages: list[StageResult] | None = None) -> AttackResult:
    return AttackResult(
        run_id="RUN-TEST", case_id="CASE-x-001-abcdef", attack_id="direct_poisoning",
        scenario_id=scenario_id, family=family, stages=stages or [], success=success,
        metrics={}, evidence={}, attacker_user_id="1001", victim_user_id="1002",
    )


# --------------------------------------------------------- Этап 2: family replay


def test_build_finding_uses_family_not_scenario_id() -> None:
    f = build_finding(_result())
    assert f.family == "direct_poisoning"
    assert f.attack_id == "direct_poisoning"
    assert f.title == "Direct memory poisoning (explicit command insertion)"
    # негатив → INFO (существующий дизайн severity)
    assert f.severity == "INFO" and f.status == "NOT_EXPLOITABLE"


def test_build_finding_unknown_family_is_explicit_error() -> None:
    with pytest.raises(ValueError, match="direct_poisoning_v99"):
        build_finding(_result(family="direct_poisoning_v99"))


def test_build_finding_missing_family_is_explicit_error() -> None:
    # family не заполнялась (старый код) — диагностическая ошибка, не молчаливый default
    with pytest.raises(ValueError, match="family"):
        build_finding(_result(family=""))


def _write_campaign(tmp_path: Path, *, scenario_id: str, family_in_result: str | None,
                    attack_id: str = "direct_poisoning") -> Path:
    result: dict = {
        "case_id": "CASE-direct_poisoning-001-df4699",
        "attack_id": attack_id,
        "success": False,
        "stages": [
            {"stage": "write", "success": False, "reason": "нет", "evidence": []},
            {"stage": "persistence", "success": False, "reason": "нет", "evidence": []},
            {"stage": "retrieval", "success": None, "reason": "нет trace", "evidence": []},
            {"stage": "adoption", "success": False, "reason": "нет", "evidence": []},
            {"stage": "tool", "success": None, "reason": "не задействует", "evidence": []},
            {"stage": "external_effect", "success": False, "reason": "нет", "evidence": []},
        ],
        "attacker_user_id": "1003",
        "victim_user_id": "1003",
        "evidence": {"victim_response": "…"},
    }
    if family_in_result is not None:
        result["family"] = family_in_result
    campaign = {
        "run_id": "RUN-TEST", "scenario_id": scenario_id, "attempts": 1,
        "metadata": {},
        # реалистичный агрегат (html_report читает attempts/funnel) — как после run
        "aggregate_metrics": aggregate_metrics([
            AttackResult(
                run_id="RUN-TEST", case_id=result["case_id"], attack_id=attack_id,
                scenario_id=scenario_id, family=family_in_result or "",
                stages=[StageResult(stage=s["stage"], success=s["success"], reason=s["reason"])
                        for s in result["stages"]],
                success=result["success"], metrics={}, evidence={},
                attacker_user_id="1003", victim_user_id="1003",
            )
        ]),
        "results": [result],
    }
    d = tmp_path / "run"
    d.mkdir()
    (d / "campaign.json").write_text(json.dumps(campaign, ensure_ascii=False), encoding="utf-8")
    return d


def test_cli_report_replays_new_format_with_scenario_id_ne_family(tmp_path, capsys) -> None:
    from memnotsafe.cli import cmd_report

    d = _write_campaign(tmp_path, scenario_id="direct_poisoning_smoke",
                        family_in_result="direct_poisoning")
    out = tmp_path / "rebuilt"
    rc = cmd_report(type("A", (), {"input": str(d), "output": str(out)})())
    assert rc == 0
    f = json.loads((out / "findings.json").read_text(encoding="utf-8"))[0]
    assert f["family"] == "direct_poisoning"  # не имя эксперимента
    assert f["attack_id"] == "direct_poisoning"
    assert f["title"] == "Direct memory poisoning (explicit command insertion)"
    assert f["status"] == "NOT_EXPLOITABLE"
    assert f["stages"]["retrieval"] is None  # round-trip None


def test_cli_report_legacy_format_falls_back_only_on_verifiable_identity(tmp_path) -> None:
    from memnotsafe.cli import cmd_report

    # старый формат без family: attack_id == зарегистрированная family —
    # однозначно проверяемая идентичность (точное вхождение в ATTACK_REGISTRY)
    d = _write_campaign(tmp_path, scenario_id="direct_poisoning_smoke", family_in_result=None,
                        attack_id="direct_poisoning")
    rc = cmd_report(type("A", (), {"input": str(d), "output": str(tmp_path / "rebuilt2")})())
    assert rc == 0
    f = json.loads((tmp_path / "rebuilt2" / "findings.json").read_text(encoding="utf-8"))[0]
    assert f["family"] == "direct_poisoning"


def test_cli_report_legacy_unresolvable_family_is_explicit_error(tmp_path, capsys) -> None:
    from memnotsafe.cli import cmd_report

    # attack_id не является зарегистрированной family и family отсутствует —
    # НЕ выводим из префикса и не подставляем молчаливый default
    d = _write_campaign(tmp_path, scenario_id="s", family_in_result=None,
                        attack_id="direct_poisoning_v1")
    rc = cmd_report(type("A", (), {"input": str(d), "output": str(tmp_path / "rebuilt3")})())
    assert rc == 1
    assert "family" in capsys.readouterr().err


# --------------------------------------------------------- Этап 3: честная ASR


def _full_success_stages() -> list[StageResult]:
    return [
        _stage("write", True), _stage("persistence", True), _stage("retrieval", None),
        _stage("adoption", True), _stage("tool", None), _stage("external_effect", True),
    ]


def test_asr_counts_composite_success_not_external_effect() -> None:
    # effect=True при write=False — композит False; ASR обязан быть 0 (было: 1)
    effect_only = _result(
        stages=[
            _stage("write", False), _stage("persistence", False), _stage("retrieval", None),
            _stage("adoption", False), _stage("tool", None), _stage("external_effect", True),
        ],
    )
    m = aggregate_metrics([effect_only])
    assert m["end_to_end_asr"] == 0.0 and m["successful"] == 0


def test_asr_half_with_one_confirmed_composite_of_two() -> None:
    confirmed = _result(success=True, stages=_full_success_stages())
    failed = _result(success=False, stages=[
        _stage("write", False), _stage("persistence", False), _stage("retrieval", None),
        _stage("adoption", False), _stage("tool", None), _stage("external_effect", False),
    ])
    m = aggregate_metrics([confirmed, failed])
    assert m["end_to_end_asr"] == 0.5 and m["successful"] == 1 and m["attempts"] == 2


def test_asr_unknown_mandatory_stage_is_not_success() -> None:
    # adoption=UNKNOWN — композит False, ASR 0; retrieval=UNKNOWN формулой допускается
    stages = _full_success_stages()
    stages[3] = _stage("adoption", None)
    m = aggregate_metrics([_result(success=False, stages=stages)])
    assert m["end_to_end_asr"] == 0.0


def test_asr_none_on_zero_attempts() -> None:
    m = aggregate_metrics([])
    assert m["end_to_end_asr"] is None and m["attempts"] == 0


def test_asr_run_replay_consistency() -> None:
    # агрегат на in-memory результатах == пересчитанный из сериализованного
    # campaign.json (CLI report), исключая генерируемые id/время
    from memnotsafe.cli import cmd_report

    d = _write_campaign(tmp_path_d := __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                        scenario_id="my-experiment", family_in_result="direct_poisoning")
    # подменяем stages/success на успешные и пересобираем реалистичный агрегат
    stages = _full_success_stages()
    local_result = AttackResult(
        run_id="RUN", case_id="C", attack_id="direct_poisoning", scenario_id="my-experiment",
        family="direct_poisoning", stages=stages, success=True, metrics={}, evidence={},
        attacker_user_id="1003", victim_user_id="1003",
    )
    camp = json.loads((d / "campaign.json").read_text(encoding="utf-8"))
    camp["results"][0]["success"] = True
    camp["results"][0]["stages"] = [
        {"stage": s.stage, "success": s.success, "reason": s.reason, "evidence": s.evidence}
        for s in stages
    ]
    camp["aggregate_metrics"] = aggregate_metrics([local_result])
    (d / "campaign.json").write_text(json.dumps(camp, ensure_ascii=False), encoding="utf-8")
    m_local = aggregate_metrics([local_result])
    rc = cmd_report(type("A", (), {"input": str(d), "output": str(d / "rebuilt")})())
    assert rc == 0
    m_replay = json.loads((d / "rebuilt" / "metrics.json").read_text(encoding="utf-8"))
    assert m_replay["end_to_end_asr"] == m_local["end_to_end_asr"] == 1.0


# ------------------------------------------------- replay без сети/адаптера


def test_cli_report_never_builds_adapter_or_network(monkeypatch, tmp_path) -> None:
    """Replay обязан работать ТОЛЬКО на сохранённых артефактах: попытка
    построить адаптер/сценарий = обращение к живому стенду — запрещена."""
    import memnotsafe.cli as cli

    def _explode(*_a: object, **_k: object) -> None:
        raise AssertionError("cmd_report не должен строить адаптер/сценарий (сеть)")

    monkeypatch.setattr(cli, "load_scenario", _explode)
    monkeypatch.setattr(cli, "build_adapter", _explode)
    d = _write_campaign(tmp_path, scenario_id="direct_poisoning_smoke",
                        family_in_result="direct_poisoning")
    rc = cli.cmd_report(type("A", (), {"input": str(d), "output": str(tmp_path / "rebuilt-net")})())
    assert rc == 0


# ------------------------------------------------- F4: replay пересчитывает метрики


def test_f4_replay_recomputes_wrong_saved_aggregate(monkeypatch, tmp_path, capsys) -> None:
    """Сохранённый campaign с неверным агрегатом (end_to_end_asr=1.0 при
    success=False) обязан быть пересчитан: CLI/JSON показывают фактические 0,
    а не унаследованную ложную цифру. Артефакт-источник не изменяется."""
    import memnotsafe.cli as cli

    def _explode(*_a: object, **_k: object) -> None:
        raise AssertionError("replay без сети")

    monkeypatch.setattr(cli, "load_scenario", _explode)
    monkeypatch.setattr(cli, "build_adapter", _explode)
    d = _write_campaign(tmp_path, scenario_id="direct_poisoning_smoke", family_in_result="direct_poisoning")
    camp = json.loads((d / "campaign.json").read_text(encoding="utf-8"))
    camp["aggregate_metrics"]["end_to_end_asr"] = 1.0  # намеренно неверный старый агрегат
    camp["aggregate_metrics"]["successful"] = 1
    (d / "campaign.json").write_text(json.dumps(camp, ensure_ascii=False), encoding="utf-8")
    raw_before = (d / "campaign.json").read_text(encoding="utf-8")

    out = tmp_path / "rebuilt-f4"
    rc = cli.cmd_report(type("A", (), {"input": str(d), "output": str(out)})())
    assert rc == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert m["end_to_end_asr"] == 0.0 and m["successful"] == 0  # пересчитано, не скопировано
    assert (d / "campaign.json").read_text(encoding="utf-8") == raw_before  # вход не изменён
    assert "пересчитаны" in capsys.readouterr().out


# ------------------------------------- FIX-08: реальный writer → load_campaign
#
# Здесь фикстур campaign.json нет: файл пишет штатный Campaign на офлайновом
# mock. Дописать family в артефакт руками означало бы проверить сам тест —
# дыра была именно в writer'е.


class _ConfirmingJudge:
    """Судья-заглушка: всегда подтверждает и цитирует дословно. Без сети."""

    async def complete(self, system: str, user: str) -> JudgeCallResult:
        inside = user.split(">>>\n", 1)[1].split("\n<<<END", 1)[0]
        body = {
            "outcome": "confirmed", "confidence": 0.83,
            "rationale": "ответ отражает отравленный факт", "quote": inside[:40] or "пусто",
        }
        return JudgeCallResult(ok=True, content=json.dumps(body, ensure_ascii=False),
                               status=200, raw={"stub": True})

    async def aclose(self) -> None:
        return None


def _real_run(tmp_path: Path, *, family: str, corpus_path: str | None = None,
              judged: bool = False, out_name: str = "run"):
    """Настоящий прогон кампании на mock: campaign.json пишет core/campaign.py.

    `scenario.id` намеренно не равен family — семья обязана доехать сама, а не
    через имя эксперимента."""
    judge_spec = JudgeSpec(enabled=True, model="stub-judge", min_confidence=0.7) if judged \
        else JudgeSpec()
    scenario = Scenario(
        id=f"{family}_smoke", path=tmp_path / f"{family}.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family=family, repetitions=1, corpus_path=corpus_path, judge=judge_spec,
    )
    out = tmp_path / out_name
    judge = LLMJudge(scenario.judge, client=_ConfirmingJudge(), repetitions=1,
                     artifacts_dir=out / "judge") if judged else None
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out, judge=judge).run())
    return result, out


def _wire(out: Path) -> dict:
    return json.loads((out / "campaign.json").read_text(encoding="utf-8"))


def _corpus(tmp_path: Path):
    """Корпус из офлайновой заглушки атакующей LLM — тот же путь, что в US1."""
    from memnotsafe.generation.attack_classes import load_attack_classes
    from memnotsafe.generation.attacker_client import StubAttackerClient
    from memnotsafe.generation.budget import CallBudget
    from memnotsafe.generation.corpus import write_corpus
    from memnotsafe.generation.corpus_gen import generate_corpus
    from memnotsafe.generation.offline import reference_answers
    from memnotsafe.generation.profile import load_profile

    classes = load_attack_classes("attack_classes/")
    corpus = asyncio.run(generate_corpus(
        load_profile("profiles/support-agent.yaml"), classes,
        StubAttackerClient(reference_answers(classes)), CallBudget(50),
        provider="stub", model=None,
    ))
    return write_corpus(corpus, tmp_path / "support-agent.yaml")


def test_writer_records_family_in_campaign_json(tmp_path) -> None:
    """Дыра FIX-08: writer знал family, но в wire её не клал."""
    result, out = _real_run(tmp_path, family="direct_poisoning")
    assert result.results[0].family == "direct_poisoning"           # в памяти была
    assert _wire(out)["results"][0]["family"] == "direct_poisoning"  # и в файле


def test_generated_run_keeps_family_generated_not_source_class(tmp_path) -> None:
    """У корпусного случая attack_id — имя КЛАССА-ИСТОЧНИКА, и оно само по себе
    зарегистрировано в ATTACK_REGISTRY. Пока family нет в wire, legacy-fallback
    читателя выдаёт рукописную семью там, где работал корпус."""
    from memnotsafe.attacks.base import ATTACK_REGISTRY
    from memnotsafe.cli import load_campaign

    _result, out = _real_run(tmp_path, family="generated", corpus_path=_corpus(tmp_path))
    wire = _wire(out)["results"]
    assert wire, "корпусный прогон не дал ни одного случая"
    assert {r["family"] for r in wire} == {"generated"}
    # именно это делает fallback опасным: attack_id — валидный ключ реестра
    assert any(r["attack_id"] in ATTACK_REGISTRY and r["attack_id"] != "generated" for r in wire)
    assert {r.family for r in load_campaign(out).results} == {"generated"}


def test_family_and_provenance_attack_class_stay_independent(tmp_path) -> None:
    """family — идентичность семьи, provenance.attack_class — происхождение
    нагрузки. У рукописной атаки они совпадают, у корпусной расходятся, и
    round-trip не сводит одно к другому."""
    from memnotsafe.cli import load_campaign

    _plain, plain_out = _real_run(tmp_path, family="direct_poisoning", out_name="plain")
    plain = load_campaign(plain_out).results[0]
    assert plain.family == "direct_poisoning"
    assert plain.evidence["provenance"] == {
        "origin": "handwritten", "attack_class": "direct_poisoning",
    }

    _gen, gen_out = _real_run(tmp_path, family="generated", corpus_path=_corpus(tmp_path),
                              out_name="gen")
    for r in load_campaign(gen_out).results:
        assert r.family == "generated"
        prov = r.evidence["provenance"]
        assert prov["origin"] == "corpus"
        assert prov["attack_class"] != "generated"  # класс-источник, не семья


def test_round_trip_keeps_tristate_stages_judge_provenance_and_composite(tmp_path) -> None:
    """Аддитивное поле не должно сдвинуть соседей: тристейт стадий, судейский
    провенанс, расхождение и композит переживают запись и чтение."""
    from memnotsafe.cli import load_campaign

    result, out = _real_run(tmp_path, family="direct_poisoning", judged=True)
    before, after = result.results[0], load_campaign(out).results[0]

    assert {s.success for s in before.stages} == {True, False, None}  # все три состояния
    assert any(s.disagreement for s in before.stages)                 # и реальное расхождение
    assert [(s.stage, s.success) for s in after.stages] == \
           [(s.stage, s.success) for s in before.stages]
    assert [(s.verdict_source, s.evidence_kind, s.disagreement) for s in after.stages] == \
           [(s.verdict_source, s.evidence_kind, s.disagreement) for s in before.stages]
    assert [s.judge.to_dict() if s.judge else None for s in after.stages] == \
           [s.judge.to_dict() if s.judge else None for s in before.stages]
    assert after.success is before.success is False
    assert after.family == before.family == "direct_poisoning"


def test_legacy_wire_without_family_still_reads_by_the_old_rule(tmp_path) -> None:
    """Legacy — это ровно сегодняшний файл без нового ключа. Точное вхождение
    attack_id в реестр разрешается по-прежнему, неоднозначный — нет: выдуманной
    семьи читатель не выдаёт."""
    from memnotsafe.cli import load_campaign

    _result, out = _real_run(tmp_path, family="direct_poisoning")
    camp = _wire(out)
    for r in camp["results"]:
        r.pop("family", None)  # снимаем ровно то, что добавил FIX-08
    path = out / "campaign.json"
    path.write_text(json.dumps(camp, ensure_ascii=False), encoding="utf-8")
    assert load_campaign(out).results[0].family == "direct_poisoning"

    camp["results"][0]["attack_id"] = "direct_poisoning-CASE-001"  # неоднозначный legacy
    path.write_text(json.dumps(camp, ensure_ascii=False), encoding="utf-8")
    assert load_campaign(out).results[0].family == ""
