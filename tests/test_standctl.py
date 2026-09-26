"""tests/test_standctl.py — CARD-CLI-MEGA-UX §1: `memnotsafe stand up|down|status|keys`.

Всё офлайн: реальный docker и сеть не трогаем — команды гоняются с ПОДСТАВНЫМИ
runner/healthz/issuer (карта §Рамки: «unit с подставным compose-runner»). Замки:
- docker CLI ищется в PATH и в %LOCALAPPDATA%\\...\\DockerDesktop\\resources\\bin;
- каталог стенда — из env MEMNOTSAFE_STACK2_DIR / pilot.yaml, НЕ хардкод;
- нет docker / недостижимый healthz → человеческое сообщение (exit 2/1), не traceback;
- compose вызывается СПИСКОМ аргументов (без shell=True);
- keys: .env пишется с бэкапом .env.bak, значения ключей НИКОГДА не печатаются.
"""

from __future__ import annotations

import io

from rich.console import Console

from memnotsafe import standctl


class _Proc:
    """Подставной результат запуска процесса (как subprocess.CompletedProcess)."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, force_terminal=False, no_color=True, width=200), buf


def _stack(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return {"MEMNOTSAFE_STACK2_DIR": str(tmp_path)}


# --------------------------------------------------------------- find_docker
def test_find_docker_prefers_path():
    assert standctl.find_docker({}, which=lambda name: "/usr/bin/docker") == "/usr/bin/docker"


def test_find_docker_localappdata_fallback(tmp_path):
    binp = tmp_path / "Programs" / "DockerDesktop" / "resources" / "bin"
    binp.mkdir(parents=True)
    (binp / "docker.exe").write_text("", encoding="utf-8")
    found = standctl.find_docker({"LOCALAPPDATA": str(tmp_path)}, which=lambda name: None)
    assert found == str(binp / "docker.exe")


def test_find_docker_absent(tmp_path):
    assert standctl.find_docker({"LOCALAPPDATA": str(tmp_path)}, which=lambda name: None) is None


# ------------------------------------------------------------ resolve_stack_dir
def test_resolve_stack_dir_from_env(tmp_path):
    assert standctl.resolve_stack_dir({"MEMNOTSAFE_STACK2_DIR": str(tmp_path)}) == tmp_path


def test_resolve_stack_dir_from_config(tmp_path):
    cfg = tmp_path / "pilot.yaml"
    cfg.write_text("stand:\n  stack2_dir: /opt/stack2\n", encoding="utf-8")
    assert standctl.resolve_stack_dir({}, config_path=cfg).as_posix().endswith("stack2")


def test_resolve_stack_dir_missing_raises():
    import pytest

    with pytest.raises(standctl.StandError):
        standctl.resolve_stack_dir({}, config_path="does-not-exist.yaml")


# ------------------------------------------------------------------ up
def test_stand_up_success(monkeypatch, tmp_path):
    monkeypatch.setattr(standctl, "find_docker", lambda *a, **k: "docker")
    calls: list = []
    console, buf = _console()
    rc = standctl.stand_up(
        environ=_stack(tmp_path),
        runner=lambda cmd: calls.append(cmd) or _Proc(0),
        healthz=lambda url: 200,
        sleep=lambda s: None, timeout_s=10, poll_interval_s=1, console=console,
    )
    assert rc == 0
    assert len(calls) == 1
    cmd = calls[0]
    assert isinstance(cmd, list)  # список, не shell-строка
    assert "compose" in cmd and "up" in cmd and "-d" in cmd
    assert "200" in buf.getvalue()


def test_stand_up_docker_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(standctl, "find_docker", lambda *a, **k: None)
    calls: list = []
    console, buf = _console()
    rc = standctl.stand_up(environ=_stack(tmp_path), runner=lambda cmd: calls.append(cmd) or _Proc(0),
                           healthz=lambda url: 200, sleep=lambda s: None, console=console)
    assert rc == 2
    assert calls == []  # compose не запускался
    assert "docker" in buf.getvalue().lower() and "Traceback" not in buf.getvalue()


def test_stand_up_healthz_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(standctl, "find_docker", lambda *a, **k: "docker")
    console, buf = _console()
    rc = standctl.stand_up(environ=_stack(tmp_path), runner=lambda cmd: _Proc(0),
                           healthz=lambda url: None, sleep=lambda s: None,
                           timeout_s=3, poll_interval_s=1, console=console)
    assert rc == 1
    assert "не ответил 200" in buf.getvalue() and "Traceback" not in buf.getvalue()


def test_stand_up_compose_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(standctl, "find_docker", lambda *a, **k: "docker")
    console, buf = _console()
    rc = standctl.stand_up(environ=_stack(tmp_path),
                           runner=lambda cmd: _Proc(1, stderr="boom"),
                           healthz=lambda url: 200, sleep=lambda s: None, console=console)
    assert rc == 1
    assert "Traceback" not in buf.getvalue()


def test_default_runner_no_shell(monkeypatch):
    import subprocess

    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"], captured["kwargs"] = cmd, kwargs
        return _Proc(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    standctl._default_runner(["docker", "compose", "ps"])
    assert captured["cmd"] == ["docker", "compose", "ps"]
    assert not captured["kwargs"].get("shell", False)  # без shell=True


# ------------------------------------------------------------ status / down
def test_stand_status_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(standctl, "find_docker", lambda *a, **k: "docker")
    console, buf = _console()
    rc = standctl.stand_status(environ=_stack(tmp_path),
                               runner=lambda cmd: _Proc(0, stdout="NAME  STATE\napi   Up"),
                               healthz=lambda url: 200, console=console)
    assert rc == 0
    assert "200" in buf.getvalue() and "api" in buf.getvalue()


def test_stand_status_not_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(standctl, "find_docker", lambda *a, **k: "docker")
    console, _ = _console()
    rc = standctl.stand_status(environ=_stack(tmp_path), runner=lambda cmd: _Proc(0, stdout=""),
                               healthz=lambda url: None, console=console)
    assert rc == 1


def test_stand_down(monkeypatch, tmp_path):
    monkeypatch.setattr(standctl, "find_docker", lambda *a, **k: "docker")
    calls: list = []
    console, _ = _console()
    rc = standctl.stand_down(environ=_stack(tmp_path), runner=lambda cmd: calls.append(cmd) or _Proc(0),
                             console=console)
    assert rc == 0
    assert "down" in calls[0]


# ------------------------------------------------------------------ keys
def test_stand_keys_writes_env_with_backup_and_no_values(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("KEEP_ME=1\nSK_GENAI_1001=old_secret\n", encoding="utf-8")
    console, buf = _console()
    secret_values = {cid: f"NEWKEY-{cid}-SECRET" for cid in standctl.CLIENT_IDS}
    rc = standctl.stand_keys(
        environ={}, issue_key=lambda cid: secret_values[cid],
        env_path=env_path, console=console,
    )
    assert rc == 0
    text = env_path.read_text(encoding="utf-8")
    # все имена записаны, прежняя не-ключевая строка сохранена
    for cid in standctl.CLIENT_IDS:
        assert f"SK_GENAI_{cid}={secret_values[cid]}" in text
    assert "KEEP_ME=1" in text
    # бэкап .env.bak с прежним содержимым
    backup = tmp_path / ".env.bak"
    assert backup.exists() and "old_secret" in backup.read_text(encoding="utf-8")
    # СЕКРЕТ-ГИГИЕНА: значения ключей в консоль не попали, только имена
    out = buf.getvalue()
    for val in secret_values.values():
        assert val not in out
    assert "SK_GENAI_1001" in out


def test_stand_keys_default_issuer_needs_secret_no_network(tmp_path):
    """Дефолтный issuer без UI_CLIENT_SECRET падает StandError ДО любой сети →
    exit 2, человеческое сообщение (не traceback)."""
    env_path = tmp_path / ".env"
    console, buf = _console()
    rc = standctl.stand_keys(environ={}, env_path=env_path, console=console)  # issue_key=None → дефолт
    assert rc == 2
    assert "UI_CLIENT_SECRET" in buf.getvalue() and "Traceback" not in buf.getvalue()
