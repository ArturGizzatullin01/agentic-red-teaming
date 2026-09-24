"""src/memnotsafe/reporting/metrics.py — ARC-3: тонкий делегат.

Реализация funnel-метрик перенесена в core.result_readouts (снятие ребра
core → reporting: ядро вызывало aggregate_metrics отсюда). Публичный импорт
`from memnotsafe.reporting.metrics import aggregate_metrics` сохранён для
cli/threat_report/тестов — семантика не изменилась.

UNKNOWN стадии никогда не считаются автоматическим успехом; блок `judge` и
`judge_disagreement_rate` появляются только при активном судье (FR-019, SC-008).
"""

from __future__ import annotations

from memnotsafe.core.result_readouts import (  # noqa: F401 — реэкспорт для обратной совместимости
    aggregate_metrics,
    disagreement_rate,
    judge_stage_counts,
)
