"""src/memnotsafe/pilot_scenarios/ — P19 (часть 2): стартовый набор сценариев
пилота, упакованный в wheel как package data.

Единственная УПАКОВАННАЯ копия сценариев стартового пака (`pilot_pack.STARTER_PACK`):
из голого `pip install` каталог репозитория `scenarios/` недоступен, поэтому
`memnotsafe pilot` разрешает сценарии через `importlib.resources` этого пакета
(fallback на repo-путь — поведение разработчика). Файлы БАЙТ-В-БАЙТ совпадают с
каноническими `scenarios/<name>.yaml` — расхождение ловит тест
`test_packaged_pilot_scenarios_match_repo_originals` (единый источник истины,
дрейфа быть не должно). Сами сценарии здесь не редактируются.

EXT-D (добивка P19): пакет владеет знанием о своих ресурсах и отдаёт его наружу
двумя тонкими помощниками поверх `importlib.resources` — тем же приёмом, что и
`pilot_pack._packaged_scenario_path`. Ими пользуются `core.config.load_scenario`
(резолв сценария пака по ИМЕНИ для `run`/`go --scenario`) и `selfserve`
(fallback интерактивного каталога `go`), чтобы упакованные сценарии находились из
голого `pip install` без каталога репозитория. Секретов и логики атак здесь нет.
"""

from __future__ import annotations

import importlib.resources as _resources
from pathlib import Path

__all__ = ["packaged_scenario_path", "packaged_scenarios_dir"]

_PKG = __name__  # "memnotsafe.pilot_scenarios"


def packaged_scenario_path(name: str) -> str | None:
    """Путь к упакованному сценарию стартового пака по голому ИМЕНИ файла
    (`importlib.resources` этого пакета — работает из установленного wheel без
    каталога репозитория). None — ресурса нет (пакет/файл отсутствует), тогда
    вызывающий уходит в свой обычный путь (ошибка «не найдено» / repo-fallback)."""
    try:
        res = _resources.files(_PKG).joinpath(name)
    except (ModuleNotFoundError, ImportError):
        return None
    try:
        if res.is_file():
            return str(res)
    except (OSError, AttributeError):
        return None
    return None


def packaged_scenarios_dir() -> str | None:
    """Путь к каталогу упакованных сценариев пака (для листинга каталога `go` из
    голого install). None — если пакет не распакован в обычный каталог (например,
    zip-import): вызывающий тогда сохраняет прежнее поведение."""
    try:
        base = _resources.files(_PKG)
    except (ModuleNotFoundError, ImportError):
        return None
    try:
        directory = Path(str(base))
        if directory.is_dir():
            return str(directory)
    except (OSError, AttributeError, TypeError, ValueError):
        return None
    return None
