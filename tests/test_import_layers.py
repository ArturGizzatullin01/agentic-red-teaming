"""tests/test_import_layers.py — ARC-1: слои импортов core ↔ generation.

Правило слоёв: ядро (`core/*`) не зависит от периферии (`generation/*`,
`attacks/generated`) — ни top-level, ни в функциях, ни под TYPE_CHECKING;
обратное разрешено. В графе импортов пакета нет компонент сильной связности
больше одного модуля (SCC>1): ядро не держится на ленивых импортах периферии.

Граф строится AST-обходом (не импортом): ребро `A → B` — любой `import`/`from
... import` в модуле A на модуль B пакета, на любом уровне вложенности.
`from pkg import name` даёт ребро на подмодуль `pkg.name`, если такой есть,
иначе на сам `pkg`.

Остаточные ленивые рёбра композиции core → периферия ВНЕ цикла (campaign —
точка сборки прогона, experiment — sha промптов) заморожены таблицей
RESIDUAL_LAZY_EDGES: она сверяется ТОЧНО, поэтому набор может только
сужаться (расщепление campaign — отдельная карта), а новое ребро
core → периферия падает здесь.

RED на базе c833250: SCC {core.escalation, generation.corpus_gen,
generation.prompts, generation.rewrite}; core.escalation импортирует
generation.attacker_client/budget/corpus/rewrite и attacks.generated;
core.goal_contract — generation.corpus.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
PKG = "memnotsafe"
PKG_ROOT = SRC / PKG

PERIPHERY_PREFIX = f"{PKG}.generation"
PERIPHERY_MODULES = frozenset({f"{PKG}.attacks.generated"})

# Модули ядра, замкнутые циклом ARC-1: после карты — ноль рёбер на периферию.
ARC1_CORE_MODULES = (
    f"{PKG}.core.escalation",
    f"{PKG}.core.escalation_feedback",
    f"{PKG}.core.goal_contract",
)

# Остаточные ленивые рёбра композиции (вне SCC). Сверяются точно.
RESIDUAL_LAZY_EDGES: dict[str, frozenset[str]] = {
    f"{PKG}.core.campaign": frozenset({
        f"{PKG}.attacks.generated",
        f"{PKG}.generation.attacker_client",
        f"{PKG}.generation.budget",
        f"{PKG}.generation.config",
        f"{PKG}.generation.corpus",
        f"{PKG}.generation.errors",
    }),
    f"{PKG}.core.experiment": frozenset({f"{PKG}.generation.prompts"}),
}


def _is_periphery(module: str) -> bool:
    return module.startswith(PERIPHERY_PREFIX + ".") or module == PERIPHERY_PREFIX or module in PERIPHERY_MODULES


def _module_name(path: Path) -> str:
    rel = path.relative_to(SRC).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _package_modules() -> dict[str, Path]:
    return {_module_name(p): p for p in PKG_ROOT.rglob("*.py")}


def _resolve_from(module: str, node: ast.ImportFrom) -> str:
    if node.level:
        base = module.rsplit(".", node.level - 1)[0] if node.level > 1 else module
        # для обычного модуля `from . import x` относится к его пакету
        base = base.rsplit(".", 1)[0] if not (PKG_ROOT / Path(*base.split(".")[1:]) / "__init__.py").exists() else base
        return f"{base}.{node.module}" if node.module else base
    return node.module or ""


def import_graph() -> dict[str, set[str]]:
    """Модуль → множество модулей пакета, которые он импортирует (на любом уровне)."""
    modules = _package_modules()
    graph: dict[str, set[str]] = {}
    for module, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        deps: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in modules:
                        deps.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                target = _resolve_from(module, node)
                if not target.startswith(PKG):
                    continue
                for alias in node.names:
                    sub = f"{target}.{alias.name}"
                    if sub in modules:
                        deps.add(sub)
                    elif target in modules:
                        deps.add(target)
        deps.discard(module)
        graph[module] = deps
    return graph


def strongly_connected_components(graph: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan; возвращаются только компоненты из >1 модуля."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0

    def visit(v: str) -> None:
        nonlocal counter
        index[v] = low[v] = counter
        counter += 1
        stack.append(v)
        on_stack.add(v)
        for w in graph.get(v, ()):
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            component: list[str] = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                component.append(w)
                if w == v:
                    break
            if len(component) > 1:
                result.append(sorted(component))

    for v in sorted(graph):
        if v not in index:
            visit(v)
    return sorted(result)


def _periphery_edges(graph: dict[str, set[str]]) -> dict[str, set[str]]:
    return {
        m: {d for d in deps if _is_periphery(d)}
        for m, deps in graph.items()
        if m.startswith(f"{PKG}.core") and any(_is_periphery(d) for d in deps)
    }


def test_arc1_core_modules_do_not_import_periphery():
    graph = import_graph()
    for module in ARC1_CORE_MODULES:
        assert module in graph, f"{module}: модуль отсутствует в src/"
        bad = sorted(d for d in graph[module] if _is_periphery(d))
        assert not bad, f"{module} импортирует периферию: {bad}"


def test_core_periphery_edges_match_frozen_residual_table():
    actual = {m: frozenset(d) for m, d in _periphery_edges(import_graph()).items()}
    assert actual == RESIDUAL_LAZY_EDGES, (
        "рёбра core → generation/attacks.generated отличаются от замороженной таблицы: "
        f"лишние={ {m: sorted(d - RESIDUAL_LAZY_EDGES.get(m, frozenset())) for m, d in actual.items() if d - RESIDUAL_LAZY_EDGES.get(m, frozenset())} } "
        f"исчезли={ {m: sorted(d - actual.get(m, frozenset())) for m, d in RESIDUAL_LAZY_EDGES.items() if d - actual.get(m, frozenset())} }"
    )


def test_package_import_graph_has_no_cycles():
    sccs = strongly_connected_components(import_graph())
    assert sccs == [], f"циклы импортов (SCC>1): {sccs}"


def test_runtime_layering_in_fresh_interpreter():
    """Динамическая сторона правила: листовой контракт ядра импортируется без
    периферии (backend не связан → RuntimeError), импорт ЛЮБОГО модуля
    generation связывает backend эскалации. (core/escalation.py сам тянет
    generation транзитивно через attacks/__init__ → attacks.generated →
    generation.corpus — допустимое ребро периферии, не ядра.)"""
    code = (
        "import sys\n"
        "from memnotsafe.core.escalation_feedback import escalation_backend\n"
        "loaded = sorted(m for m in sys.modules if m.startswith('memnotsafe.generation') or m == 'memnotsafe.attacks.generated')\n"
        "assert not loaded, loaded\n"
        "try:\n"
        "    escalation_backend()\n"
        "except RuntimeError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError('backend связан без импорта generation')\n"
        "import memnotsafe.generation.budget\n"
        "backend = escalation_backend()\n"
        "assert backend.rewrite.__module__ == 'memnotsafe.generation.rewrite', backend\n"
        "import memnotsafe.core.escalation as esc\n"
        "assert esc.EscalationFeedback.__module__ == 'memnotsafe.core.escalation_feedback'\n"
        "print('OK')\n"
    )
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert proc.returncode == 0 and proc.stdout.strip() == "OK", proc.stdout + proc.stderr
