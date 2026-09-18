"""tests/test_adapter_contract_conformance.py — карточка T: контракт адаптера
не имеет права расходиться с кодом, в обе стороны.

Три замка:
1. обязательная часть контракта выполнена каждым адаптером (наличие +
   async/sync-природа совпадает с базой);
2. опциональные расширения, если есть, объявлены с документированной природой;
3. множество имён расширений в документе == множеству имён, которые ядро
   читает через hasattr/getattr в core/campaign.py — расхождение в ЛЮБУЮ
   сторону ловится с сообщением о направлении.

Всё вычисляется, а не перечисляется: адаптеры находятся обходом модулей пакета
memnotsafe.adapters (четвёртый адаптер попадает под проверку сам), обязательные
методы берутся из самого ABC, имена расширений — из нумерованного списка
раздела «Опциональные расширения контракта» и из узких якорей
`hasattr(self.target, "...")` / `getattr(self.target, "...",` по campaign.py
(одна и та же имя читается второй формой и в двух местах — поэтому множество).
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from memnotsafe.adapters.base import TargetAdapter  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]
_CAMPAIGN_PY = _REPO / "src" / "memnotsafe" / "core" / "campaign.py"
_CONTRACT_MD = (
    _REPO / "specs" / "001-live-target-reproduction" / "contracts" / "adapter-contract.md"
)
_DOC_SECTION_TITLE = "## Опциональные расширения контракта"


def _nature(func) -> str:
    return "async" if inspect.iscoroutinefunction(func) else "sync"


def discover_adapters() -> list[type]:
    """Механический обход: все подклассы TargetAdapter во всех модулях пакета
    adapters. ABC исключается; литеральных имён адаптеров здесь нет и быть не
    может — источник правды сам пакет."""
    import memnotsafe.adapters as pkg

    found = []
    for mod_info in pkgutil.iter_modules(pkg.__path__):
        module = importlib.import_module(f"memnotsafe.adapters.{mod_info.name}")
        for obj in vars(module).values():
            if (
                inspect.isclass(obj)
                and issubclass(obj, TargetAdapter)
                and obj is not TargetAdapter
                and obj.__module__ == module.__name__  # определён здесь, не импорт
            ):
                found.append(obj)
    return found


def _base_contract() -> dict[str, str]:
    """Обязательные методы — из самого ABC (публичные функции класса): источник
    правды база, а не список в тесте."""
    return {
        name: _nature(obj)
        for name, obj in vars(TargetAdapter).items()
        if inspect.isfunction(obj) and not name.startswith("_")
    }


def _doc_extensions() -> dict[str, str]:
    """Имена и природа расширений — из нумерованного списка раздела документа.
    Природа: маркер «(async)» в строке пункта; его отсутствие — синхронное."""
    text = _CONTRACT_MD.read_text(encoding="utf-8")
    start = text.index(_DOC_SECTION_TITLE)
    rest = text[start:]
    nxt = rest.find("\n## ", 1)
    section = rest if nxt == -1 else rest[:nxt]
    extensions: dict[str, str] = {}
    for m in re.finditer(r'^\d+\.\s+\*\*`([a-z_][a-z0-9_]*)\(', section, re.M):
        line_end = section.find("\n", m.start())
        line = section[m.start():line_end if line_end != -1 else None]
        extensions[m.group(1)] = "async" if "(async)" in line else "sync"
    assert extensions, "разбор документа ничего не нашёл — якорь рассыпался"
    return extensions


def _core_extensions() -> set[str]:
    """Имена, которые ядро читает duck-typed. Якорь узкий и стабильный: только
    hasattr(self.target, "...") и getattr(self.target, "...", — обе формы
    (context_tool_evidence читается второй и в двух местах)."""
    src = _CAMPAIGN_PY.read_text(encoding="utf-8")
    names: set[str] = set()
    for m in re.finditer(r'hasattr\(self\.target,\s*"([a-z_][a-z0-9_]*)"\)', src):
        names.add(m.group(1))
    for m in re.finditer(r'getattr\(self\.target,\s*"([a-z_][a-z0-9_]*)",', src):
        names.add(m.group(1))
    return names


# ------------------------------------------------------------- PASS_IF 1 и 2

def test_discovery_is_mechanical_and_finds_the_adapters():
    """Обход находит все реализации; «нашли хоть что-то» обязано быть явным,
    иначе пустой обход выглядел бы зелёным замком."""
    adapters = discover_adapters()
    names = {cls.__name__ for cls in adapters}
    assert len(adapters) >= 3, f"обход нашёл меньше трёх реализаций: {sorted(names)}"
    assert "MockTarget" in names, sorted(names)
    assert "InvestmentStandAdapter" in names, sorted(names)


def test_discovery_does_not_enumerate_adapter_names():
    """В самом обходе нет литеральных имён модулей адаптеров — источник правды
    обход пакета, а не повтор цепочки build_adapter (самопроверка источника;
    имена для сверки живут здесь же, но не в discover_adapters)."""
    src = inspect.getsource(discover_adapters)
    for forbidden in ("mock", "openai", "investment_stand"):
        assert forbidden not in src, f"литеральное имя адаптера в обходе: {forbidden}"


# ------------------------------------------------ obligatory part (замок 1)

def test_mandatory_contract_held_by_every_adapter():
    base = _base_contract()
    assert base, "пустой контракт базы — якорь рассыпался"
    for cls in discover_adapters():
        for name, base_nature in base.items():
            func = inspect.getattr_static(cls, name, None)
            assert func is not None, (
                f"{cls.__name__}: обязательный метод {name} отсутствует"
            )
            actual = _nature(inspect.getattr_static(cls, name))
            assert actual == base_nature, (
                f"{cls.__name__}.{name}: природа {actual}, у базы {base_nature}"
            )


# ------------------------------------------------ optional part (замок 2)

def test_optional_extensions_nature_matches_doc():
    doc = _doc_extensions()
    for cls in discover_adapters():
        for name, doc_nature in doc.items():
            if not hasattr(cls, name):
                continue  # отсутствие — штатный случай, см. тест ниже
            actual = _nature(getattr(cls, name))
            assert actual == doc_nature, (
                f"{cls.__name__}.{name}: природа {actual}, в документе {doc_nature}"
            )


def test_absent_extensions_are_licensed():
    """Отсутствие расширения — не провал. По букве карточки «ни одного из
    трёх», но MockTarget ИМЕЕТ context_tool_evidence (с P09-full, df97672/
    6a404f4 — predates база карточки): отсутствие действительно штатно на двух
    остальных, что и запирается здесь. Отступление от PASS_IF 6 выделено в
    хендофе; природу имеющегося у MockTarget расширения проверяет тест выше."""
    doc = _doc_extensions()
    adapter = next(cls for cls in discover_adapters() if cls.__name__ == "MockTarget")
    absent = [name for name in doc if not hasattr(adapter, name)]
    assert "run_metadata" in absent and "acollect_run_observations" in absent, absent
    assert hasattr(adapter, "context_tool_evidence")  # и это допустимо тоже


# ------------------------------------------- doc <-> code sync (замок 3)

def test_doc_names_equal_core_names_both_directions():
    doc, core = set(_doc_extensions()), _core_extensions()
    silent_in_code = core - doc
    promised_not_read = doc - core
    assert not silent_in_code and not promised_not_read, (
        "контракт адаптера разошёлся с кодом: "
        + (f"в коде, нет в документе (завели молча): {sorted(silent_in_code)}; "
           if silent_in_code else "")
        + (f"в документе, нет в коде (документ обещает то, чего нет): "
           f"{sorted(promised_not_read)}" if promised_not_read else "")
    )


def test_core_reads_both_forms_and_core_names_are_duck_typed():
    """Обе формы чтения реально встречаются в campaign.py (иначе замок слеп к
    одной из них), и ни одно duck-typed имя не является методом базы —
    расширение обязано быть расширением, а не обязательной частью."""
    src = _CAMPAIGN_PY.read_text(encoding="utf-8")
    assert re.search(r'hasattr\(self\.target,\s*"[a-z_]+"', src), "форма hasattr не найдена"
    assert re.search(r'getattr\(self\.target,\s*"[a-z_]+",', src), "форма getattr не найдена"
    base = _base_contract()
    for name in _core_extensions():
        assert name not in base, f"{name} — метод базы, а не расширение"
