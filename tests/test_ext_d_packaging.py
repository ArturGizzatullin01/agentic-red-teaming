"""tests/test_ext_d_packaging.py — CARD-EXT-D задача 1: аудит и добивка P19.

Аудит P19 (сценарии стартового пака едут в wheel как package-data пакета
`memnotsafe.pilot_scenarios`) делом показал ДВА разрыва при голом `pip install`
без каталога репозитория и из произвольного cwd:

  1) `memnotsafe run --scenario <имя>` — `load_scenario` резолвил только путь
     файловой системы; упакованный сценарий по ИМЕНИ не находился
     (FileNotFoundError, а из-за непойманного исключения — сырой traceback);
  2) `memnotsafe go` без --scenario — интерактивный каталог строился из
     `./scenarios` в cwd (`build_catalog("scenarios")`); из голого install этот
     каталог пуст.

Оба закрыты как «добивка P19 по факту разрыва» (ALLOWLIST): резолв голого имени
из package resources в `load_scenario` и fallback каталога `go` на упакованный
набор, когда `./scenarios` в cwd нет. Резолвинг-помощники живут в самом пакете
`memnotsafe.pilot_scenarios` (он и владеет знанием о своих ресурсах).

`pilot --init` и `pilot --config` из голого install работают уже сейчас (не
разрыв) — их держат тесты в tests/test_pilot_pack.py; здесь не дублируем прогон.

Плюс офлайн-замок упаковки: сценарии пака РЕАЛЬНО едут в wheel — проверка
содержимого архива + importlib.resources, без сети и без установки.
"""

from __future__ import annotations

import importlib.resources as _resources
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from memnotsafe.core.config import load_scenario
from memnotsafe.pilot_pack import STARTER_PACK

PILOT_SCENARIOS_PKG = "memnotsafe.pilot_scenarios"
REPO = Path(__file__).resolve().parents[1]


def _starter_basenames() -> set[str]:
    """Имена файлов сценариев стартового пака (атаки + контроль) — единый источник,
    не хардкодим список (карта STARTER_PACK)."""
    names: set[str] = set()
    for e in STARTER_PACK:
        names.add(Path(e.scenario).name)
        if e.control:
            names.add(Path(e.control).name)
    return names


# ------------------------------------------- разрыв 1: run --scenario <имя>
def test_load_scenario_resolves_bundled_name_from_foreign_cwd(tmp_path, monkeypatch):
    """РАЗРЫВ 1 (RED→GREEN): из чужого cwd без ./scenarios `run --scenario <имя>`
    обязан находить упакованный сценарий по ИМЕНИ (P19 добивка). До фикса
    load_scenario резолвил только путь ФС → FileNotFoundError."""
    monkeypatch.chdir(tmp_path)  # пустой каталог, ./scenarios здесь нет
    for name in _starter_basenames():
        sc = load_scenario(name)  # голое имя, файла в cwd нет — только пакет
        assert sc.id, f"{name}: сценарий не загрузился по имени из пакета"


def test_load_scenario_bundled_name_matches_repo_original(tmp_path, monkeypatch):
    """Резолв по имени даёт ТОТ ЖЕ сценарий, что и репозиторный scenarios/<name>
    (id/family/adapter совпадают) → семантика и experiment_id не дрейфуют."""
    monkeypatch.chdir(tmp_path)
    for name in _starter_basenames():
        from_name = load_scenario(name)
        from_repo = load_scenario(REPO / "scenarios" / name)
        assert from_name.id == from_repo.id, f"{name}: id разошёлся"
        assert from_name.attack_family == from_repo.attack_family, f"{name}: family разошёлся"
        assert from_name.target.adapter == from_repo.target.adapter, f"{name}: adapter разошёлся"


def test_load_scenario_unknown_name_still_raises(tmp_path, monkeypatch):
    """Регресс-страховка: неизвестное имя (нет ни на диске, ни в пакете) по-прежнему
    даёт FileNotFoundError — fallback не маскирует реальную опечатку оператора."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError):
        load_scenario("no_such_scenario_xyz.yaml")


def test_load_scenario_explicit_missing_path_not_shadowed(tmp_path, monkeypatch):
    """Регресс-страховка: ЯВНЫЙ путь с каталогом (sub/<имя>) НЕ подменяется
    упакованной копией — из пакета резолвится только голое имя файла."""
    monkeypatch.chdir(tmp_path)
    name = sorted(_starter_basenames())[0]
    with pytest.raises(FileNotFoundError):
        load_scenario(f"nonexistent_dir/{name}")


# ------------------------------------------------- разрыв 2: каталог `go`
def test_go_catalog_dir_uses_local_scenarios_in_tree(monkeypatch):
    """В дереве разработчика (есть ./scenarios) каталог `go` берётся из репозитория —
    поведение НЕ меняется (байт-в-байт как было: build_catalog('scenarios'))."""
    import memnotsafe.selfserve as ss

    monkeypatch.chdir(REPO)  # ./scenarios существует в дереве
    assert Path("scenarios").is_dir(), "предпосылка теста: ./scenarios есть в дереве"
    assert Path(ss._go_catalog_dir()) == Path("scenarios")


def test_go_catalog_falls_back_to_packaged_scenarios(tmp_path, monkeypatch):
    """РАЗРЫВ 2 (RED→GREEN): из чужого cwd без ./scenarios каталог `go` обязан
    заполниться УПАКОВАННЫМ стартовым набором (P19 добивка), а не быть пустым."""
    import memnotsafe.selfserve as ss

    monkeypatch.chdir(tmp_path)  # ./scenarios здесь нет
    catalog = ss.build_catalog(ss._go_catalog_dir())
    got = {Path(e.path).name for e in catalog}
    assert _starter_basenames() <= got, f"каталог `go` не нашёл упакованные сценарии: {sorted(got)}"


# ------------------------------------------------- офлайн-замок упаковки
def test_pyproject_declares_pilot_scenarios_as_package_data():
    """ЗАМОК упаковки (без сети, без установки): pyproject ОБЪЯВЛЯЕТ сценарии пака
    как package-data пакета memnotsafe.pilot_scenarios и находит сам пакет из src/ —
    иначе они не уедут в wheel."""
    import tomllib  # stdlib 3.11+

    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    pkg_data = data["tool"]["setuptools"]["package-data"]
    assert "*.yaml" in pkg_data.get(PILOT_SCENARIOS_PKG, []), (
        f"pyproject: {PILOT_SCENARIOS_PKG} *.yaml не в [tool.setuptools.package-data]"
    )
    find = data["tool"]["setuptools"]["packages"]["find"]
    assert find.get("where") == ["src"], "packages.find.where должен быть ['src']"
    assert any("memnotsafe" in inc for inc in find.get("include", [])), (
        "packages.find.include должен покрывать memnotsafe*"
    )


def test_pilot_scenarios_present_as_package_resource():
    """ЗАМОК (importlib.resources, без сети/установки): каждый сценарий пака виден
    ресурсом пакета — значит уедет в wheel и найдётся из голого install."""
    root = _resources.files(PILOT_SCENARIOS_PKG)
    for name in _starter_basenames():
        assert root.joinpath(name).is_file(), f"сценарий пака не упакован: {name}"


def _try_build_wheel(out_dir: Path):
    """Собирает wheel БЕЗ сети (без build-isolation) toolchain'ом окружения.
    Возвращает путь .whl или None, если toolchain собрать не может (нет `build`,
    битый setuptools) — тогда вызывающий SKIP-ает, не FAIL-ит."""
    attempts = [
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(out_dir), str(REPO)],
        [sys.executable, "-m", "pip", "wheel", ".", "--no-build-isolation", "--no-deps", "-w", str(out_dir)],
    ]
    for argv in attempts:
        try:
            proc = subprocess.run(argv, cwd=str(REPO), capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.SubprocessError):
            continue
        whls = sorted(out_dir.glob("*.whl"))
        if proc.returncode == 0 and whls:
            return whls[-1]
    return None


def test_built_wheel_contains_pilot_scenarios(tmp_path):
    """ЗАМОК (проверка содержимого АРХИВА, без сети): собранный wheel РЕАЛЬНО
    содержит memnotsafe/pilot_scenarios/<name>.yaml и НЕ тащит репозиторный
    scenarios/. Сборка — toolchain'ом окружения без изоляции; toolchain недоступен
    (нет `build`/битый setuptools) → SKIP (не FAIL), чтобы suite был зелёным везде."""
    whl = _try_build_wheel(tmp_path)
    if whl is None:
        pytest.skip("нет доступного build-toolchain без сети — архивный замок пропущен")
    with zipfile.ZipFile(whl) as z:
        names = z.namelist()
    for base in _starter_basenames():
        assert any(n.endswith(f"memnotsafe/pilot_scenarios/{base}") for n in names), (
            f"{base} отсутствует в собранном wheel"
        )
    leaked = [n for n in names if n.startswith("scenarios/")]
    assert not leaked, f"репозиторный scenarios/ не должен попадать в wheel: {leaked}"
