"""tests/test_timing_regress_encoding.py — CARD-P14-fix-stdout: текстовый
вывод CLI timing_regress не зависит от кодовой страницы консоли.

Замок: подпроцесс `python -m memnotsafe.reporting.timing_regress` на
минимальном валидном входе (хелперы test_timing_regress, засев k=1 ⇒ PASS)
с PYTHONIOENCODING, под которым non-ASCII рендера (′ U+2032, R̂, русские
строки) не кодируется, обязан завершиться кодом контракта 0/1/2 с вердиктом
в stdout и БЕЗ UnicodeEncodeError. cp1251 — находка среды второго A0
(cmd/PowerShell на русской Windows), ascii — предельный случай. Сам вердикт
(PASS для k=1) здесь не запирается — это замок `test_k1_pass_exit0`.
Регресс существующих 27 тестов файла — их собственным файлом, без правок.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_timing_regress import REPO, SRC, _prereg, _std_blocks


@pytest.mark.parametrize("console_encoding", ["cp1251", "ascii"])
def test_cli_text_output_does_not_depend_on_console_codepage(
    tmp_path: Path, console_encoding: str
) -> None:
    prereg = _prereg(tmp_path)
    a, b, a2 = _std_blocks(tmp_path, factor_b=1.0)
    argv = [sys.executable, "-m", "memnotsafe.reporting.timing_regress",
            "--prereg", str(prereg), str(a), str(b), str(a2)]
    proc = subprocess.run(
        argv, cwd=str(REPO), capture_output=True,
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONIOENCODING": console_encoding},
    )
    stderr = proc.stderr.decode("utf-8", errors="replace")
    stdout = proc.stdout.decode("utf-8", errors="replace")
    assert "UnicodeEncodeError" not in stderr, (
        f"[{console_encoding}] вывод CLI зависит от кодовой страницы консоли:\n{stderr[-1500:]}"
    )
    assert "Traceback" not in stderr, stderr[-1500:]
    assert proc.returncode in (0, 1, 2), (proc.returncode, stderr[-1500:])
    assert "G3.5/timing verdict=" in stdout, (
        f"[{console_encoding}] вердикт не напечатан:\n{stdout[-800:]}\n{stderr[-800:]}"
    )
