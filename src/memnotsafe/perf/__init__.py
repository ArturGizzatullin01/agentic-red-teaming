"""src/memnotsafe/perf/__init__.py — измерение производительности оснастки (B0).

B0 — замороженный набор (perf/b0/spec.yaml): измеряет mock-путь offline,
живые сценарии не входят. Подробнее: memnotsafe.perf.baseline.
"""

from memnotsafe.perf.baseline import STAGE_METRICS

__all__ = ["STAGE_METRICS"]
