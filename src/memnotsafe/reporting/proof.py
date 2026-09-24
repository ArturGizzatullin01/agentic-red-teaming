"""src/memnotsafe/reporting/proof.py — ARC-3: тонкий делегат.

Сборка proof-артефакта перенесена в core.result_readouts (снятие ребра
core → reporting: core/campaign_persistence вызывал build_proof отсюда).
Публичный импорт `from memnotsafe.reporting.proof import build_proof` сохранён
для threat_report/тестов — семантика не изменилась.
"""

from __future__ import annotations

from memnotsafe.core.result_readouts import build_proof  # noqa: F401 — реэкспорт для обратной совместимости
