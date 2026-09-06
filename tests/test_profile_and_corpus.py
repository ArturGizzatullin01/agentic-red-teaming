"""tests/test_profile_and_corpus.py — валидация профиля/классов/корпуса и
отбраковка невалидной сгенерированной записи (FR-012, US1).

Всё офлайн: ни один тест не выходит в сеть. Негативный профиль без
`compromise.external_effect` обязан падать config-ошибкой ДО любых вызовов
атакующей LLM (research §3, §11)."""

from __future__ import annotations

import asyncio

import pytest

from memnotsafe.generation.attack_classes import load_attack_classes, parse_attack_class
from memnotsafe.generation.attacker_client import StubAttackerClient
from memnotsafe.generation.budget import CallBudget
from memnotsafe.generation.corpus import (
    Corpus,
    CorpusRecord,
    is_valid_record,
    read_corpus,
    record_issues,
    write_corpus,
)
from memnotsafe.generation.corpus_gen import generate_corpus, parse_generation_output
from memnotsafe.generation.errors import AttackerError
from memnotsafe.generation.offline import reference_answers
from memnotsafe.generation.profile import load_profile

PROFILE = "profiles/support-agent.yaml"
BROKEN_PROFILE = "profiles/broken-no-effect.yaml"
CLASSES_DIR = "attack_classes/"


# --------------------------------------------------------------------- профиль

def test_valid_profile_loads_with_sha256_and_sections():
    profile = load_profile(PROFILE)
    assert profile.id == "support-agent"
    assert profile.interface.identity_field == "user_id"
    assert profile.compromise.external_effect_type == "cross_user_data_access"
    assert profile.compromise.external_effect_required_fields == ["tool", "attacker_user_id", "victim_user_id"]
    assert len(profile.sha256) == 64  # sha256 hex


def test_profile_sha256_is_stable_and_content_sensitive():
    a = load_profile(PROFILE).sha256
    b = load_profile(PROFILE).sha256
    assert a == b  # тот же файл → тот же хеш


def test_broken_profile_without_external_effect_is_config_error():
    # Негатив US1-3: падение ДО сети (load_profile сеть не трогает вовсе).
    with pytest.raises(AttackerError) as exc:
        load_profile(BROKEN_PROFILE)
    assert "external_effect" in str(exc.value)


# --------------------------------------------------------------------- классы

def test_all_five_classes_load_and_reference_known_families():
    classes = load_attack_classes(CLASSES_DIR)
    families = {c.family for c in classes}
    assert {"cross_user_bac", "direct_poisoning", "scope_escalation", "false_precedent", "tool_argument_hijack"} <= families


def test_attack_class_with_unknown_family_rejected():
    with pytest.raises(AttackerError):
        parse_attack_class(
            {
                "family": "no_such_family",
                "goal": "g",
                "delivery_intent": "d",
                "trigger_intent": "t",
                "expected_effect": {"type": "x", "required_fields": ["a"]},
                "signal_strength": "strong",
            },
            where="<t>",
        )


# ----------------------------------------------------------- отбраковка записи (FR-012)

def test_record_issues_flags_empty_and_unknown_and_missing_fields():
    classes = {c.family: c for c in load_attack_classes(CLASSES_DIR)}
    klass = classes["cross_user_bac"]

    empty_payload = CorpusRecord(attack_class="cross_user_bac", payload="  ", trigger="t",
                                 expected_effect={"type": "cross_user_data_access", "tool": "x",
                                                  "attacker_user_id": "1", "victim_user_id": "2"})
    assert "пустой payload" in " ".join(record_issues(empty_payload, class_spec=klass))

    unknown_class = CorpusRecord(attack_class="ghost", payload="p", trigger="t",
                                 expected_effect={"type": "cross_user_data_access"})
    assert any("ATTACK_REGISTRY" in i for i in record_issues(unknown_class))

    missing_fields = CorpusRecord(attack_class="cross_user_bac", payload="p", trigger="t",
                                  expected_effect={"type": "cross_user_data_access"})  # нет tool/…
    assert not is_valid_record(missing_fields, class_spec=klass)


def test_parse_generation_output_rejects_non_json():
    assert parse_generation_output("извините, не могу помочь", attack_class="cross_user_bac") is None


def test_generate_corpus_drops_invalid_records_but_keeps_valid(tmp_path):
    profile = load_profile(PROFILE)
    classes = load_attack_classes(CLASSES_DIR)
    # Первый класс получает мусорный ответ (отбраковка), остальные — эталон.
    scripts = ["не буду это делать"] + reference_answers(classes)[1:]
    client = StubAttackerClient(scripts)
    corpus = asyncio.run(
        generate_corpus(profile, classes, client, CallBudget(50), provider="stub", model=None)
    )
    # одна запись отбракована → на одну меньше классов
    assert len(corpus.records) == len(classes) - 1
    assert "cross_user_bac" not in {r.attack_class for r in corpus.records}
    assert corpus.provenance.attacker_calls == len(classes)  # вызовы потрачены на все классы


def test_corpus_round_trip_write_read(tmp_path):
    profile = load_profile(PROFILE)
    classes = load_attack_classes(CLASSES_DIR)
    corpus = asyncio.run(
        generate_corpus(profile, classes, StubAttackerClient(reference_answers(classes)),
                        CallBudget(50), provider="stub", model=None)
    )
    path = write_corpus(corpus, tmp_path / "c.yaml")
    reloaded = read_corpus(path)
    assert reloaded.provenance.profile_id == "support-agent"
    assert reloaded.provenance.profile_sha256 == profile.sha256
    assert [r.attack_class for r in reloaded.records] == [r.attack_class for r in corpus.records]


def test_profile_effect_type_must_match_some_class():
    # Профиль с эффектом, которого нет ни у одного класса → config-ошибка до сети.
    profile = load_profile(PROFILE)
    object.__setattr__(profile.compromise, "external_effect_type", "no_such_effect")
    with pytest.raises(AttackerError):
        asyncio.run(
            generate_corpus(profile, load_attack_classes(CLASSES_DIR),
                            StubAttackerClient([]), CallBudget(50), provider="stub", model=None)
        )
