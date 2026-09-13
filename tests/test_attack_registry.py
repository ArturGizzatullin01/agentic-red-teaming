"""K2/P02: защита реестра атак от тихой перезаписи family.

Дефект (base.py __init_subclass__): второй класс с той же metadata.family
МОЛЧА перезаписывал ATTACK_REGISTRY[family] — collisions в списках атак
превращались в тихую подмену семантики. Контракт: коллизия family →
понятный exception ДО присваивания в реестр; первый класс остаётся.
Fixture восстанавливает реестр после каждого теста — никаких утечек
глобального состояния между тестами.
"""

from __future__ import annotations

import pytest

from memnotsafe.attacks.base import ATTACK_REGISTRY, AttackBase, AttackMetadata


@pytest.fixture
def registry_guard():
    """Снимок ATTACK_REGISTRY до теста и точное восстановление после —
    временные классы не утекают в остальные тесты."""
    saved = dict(ATTACK_REGISTRY)
    yield ATTACK_REGISTRY
    ATTACK_REGISTRY.clear()
    ATTACK_REGISTRY.update(saved)


def _make_class(name: str, family: str) -> type[AttackBase]:
    # type() создаёт класс с ФИНАЛЬНЫМ именем до __init_subclass__ — иначе
    # сообщение о коллизии показывает техническое <locals>._TempAttack
    def _gen(self, ctx):
        raise NotImplementedError

    def _ds(self, candidate, ctx):
        raise NotImplementedError

    def _ts(self, candidate, ctx):
        raise NotImplementedError

    def _ee(self, ctx):
        raise NotImplementedError

    return type(name, (AttackBase,), {
        "metadata": AttackMetadata(
            id=name, name=name, description="temp", family=family,
            mpbench_class="test", signal_strength="weak",
        ),
        "generate": _gen,
        "delivery_steps": _ds,
        "trigger_steps": _ts,
        "expected_effect": _ee,
    })


def test_first_registration_works(registry_guard):
    first = _make_class("RegFirst", "k2-dupe-family")
    assert ATTACK_REGISTRY["k2-dupe-family"] is first


def test_duplicate_family_registration_is_rejected_not_overwritten(registry_guard):
    first = _make_class("RegFirstDup", "k2-dupe-family")
    assert ATTACK_REGISTRY["k2-dupe-family"] is first

    # второй класс с той же family: ДО дефекта — тихая перезапись; по контракту —
    # понятный exception ДО присваивания, первый класс остаётся в реестре
    with pytest.raises(ValueError, match="k2-dupe-family") as excinfo:
        _make_class("RegSecondDup", "k2-dupe-family")
    # сообщение называет оба класса — иначе «понятный» не выполнено
    assert "RegFirstDup" in str(excinfo.value) and "RegSecondDup" in str(excinfo.value)
    assert ATTACK_REGISTRY["k2-dupe-family"] is first


def test_registry_guard_fixture_restores_state(registry_guard):
    saved_keys = set(registry_guard)
    _make_class("RegTransient", "k2-transient-family")
    assert "k2-transient-family" in ATTACK_REGISTRY
    # fixture очистит; здесь только фиксируем добавление
    assert set(ATTACK_REGISTRY) - saved_keys == {"k2-transient-family"}


def test_no_leak_between_tests():
    # порядок pytest непредсказуем: этот тест подтверждает, что временная
    # семья предыдущих тестов не дожила до соседа
    assert "k2-dupe-family" not in ATTACK_REGISTRY
    assert "k2-transient-family" not in ATTACK_REGISTRY
