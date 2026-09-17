"""tests/test_demo_launcher.py — карточка F (ПАЧКА 2): дешёвый тест на разрыв
ссылки demo.cmd -> скрипт.

История поломки: demo.cmd запускал %~dp0.agent-work\\demo\\demo-run.ps1, а
/.agent-work/ лежит в .gitignore — скрипта никогда не было в репозитории, на
любом свежем клоне демо было сломано. Этот тест ловит ровно этот класс дефекта:
лаунчер обязан ссылаться на существующий ОТСЛЕЖИВАЕМЫЙ файл вне .agent-work.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_demo_cmd_references_existing_tracked_script() -> None:
    text = (REPO / "demo.cmd").read_text(encoding="utf-8", errors="replace")
    m = re.search(r'-File\s+"([^"]+)"', text)
    assert m, "demo.cmd должен запускать powershell -File \"<скрипт>\""
    rel = m.group(1)
    assert ".agent-work" not in rel, (
        f"demo.cmd ссылается в .agent-work ({rel}) — каталог в .gitignore, "
        "на свежем клоне демо сломано (исходная поломка этой карточки)"
    )
    assert rel.lower().startswith("%~dp0"), (
        f"путь скрипта в demo.cmd должен быть привязан к корню репозитория через %~dp0, получено {rel!r}"
    )
    target = REPO / rel[len("%~dp0"):]
    assert target.is_file(), f"demo.cmd ссылается на несуществующий файл: {target}"
    rel_posix = target.relative_to(REPO).as_posix()
    out = subprocess.run(
        ["git", "ls-files", "--", rel_posix],
        cwd=REPO, capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == rel_posix, (
        f"{rel_posix} не отслеживается git — на свежем клоне его не будет, и демо "
        "сломается так же, как со старым .agent-work"
    )
