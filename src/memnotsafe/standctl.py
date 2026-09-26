"""src/memnotsafe/standctl.py — CARD-CLI-MEGA-UX §1: управление Docker-стендом из CLI.

`memnotsafe stand up|down|status|keys` — тонкая оболочка над `docker compose`
стенда stack2 и headless-перевыпуском ключей клиентов. Ни движка, ни атак, ни
оракулов не трогает: это инфраструктурная команда рядом с `go`/`pilot`.

Границы (карта):
- путь к compose НЕ хардкодится в пакете: берётся из env `MEMNOTSAFE_STACK2_DIR`
  или из `pilot.yaml`/конфига (ключ `stand.stack2_dir`);
- docker CLI ищется в PATH и в `%LOCALAPPDATA%\\Programs\\DockerDesktop\\resources\\bin`
  (2026-09-26 его не было в PATH — стенд не стартовал);
- мёртвый Docker / недостижимый healthz → человеческое сообщение, не трейсбек;
  GUI Docker Desktop не поднимаем (решение владельца; NOTICED);
- секретов ноль: значения ключей НИКОГДА не печатаются; `.env` перезаписывается с
  бэкапом `.env.bak`; compose и внешние вызовы — без `shell=True` (список
  аргументов, не строка).

Все точки внешнего мира (запуск процессов, healthz, выпуск ключей, сон) —
инъектируемые слоты: юнит-тесты гоняют команды с подставными runner/healthz/
issuer БЕЗ реального docker и без сети (карта: «unit с подставным compose-runner»).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Callable

import yaml
from rich.console import Console

# Стенд stack2 (карта §1; preflight.KNOWN_DEPLOYMENTS «основной стек»): API 9600.
HEALTHZ_URL = "http://localhost:9600/healthz"
COMPOSE_FILENAME = "docker-compose.yml"
# Клиенты стенда (SK_GENAI_1001..1005) — карта §1.
CLIENT_IDS: tuple[str, ...] = ("1001", "1002", "1003", "1004", "1005")
ENV_KEY_TEMPLATE = "SK_GENAI_{cid}"

# Ключи выпускаются приёмом bootstrap_api_keys.sh (карта §1): Keycloak 9443 →
# POST /keys на 9600. Точный контракт скрипта живёт ВНЕ репозитория (isolated-
# live-test/, открывать нельзя по CLAUDE.md) — дефолтный issuer ниже реализует
# описанный в карте поток best-effort и вынесен в инъектируемый слот; боевой
# путь сверяет A0 ручным приёмом (NOTICED в хендофе).
KEYCLOAK_URL = "https://localhost:9443"
KEY_ISSUE_URL = "http://localhost:9600/keys"

_HTTP_TIMEOUT_S = 5.0
_UP_TIMEOUT_S = 90.0
_POLL_INTERVAL_S = 3.0

# Тип запускателя процессов: список аргументов (без shell), объект с .returncode/
# .stdout/.stderr (как subprocess.CompletedProcess).
Runner = Callable[[list[str]], "object"]
Healthz = Callable[[str], "int | None"]
KeyIssuer = Callable[[str], str]


class StandError(Exception):
    """Человекочитаемый отказ управления стендом — стоп с инструкцией, не traceback."""


# --------------------------------------------------------------- поиск docker
def find_docker(environ: dict[str, str] | None = None, *, which: Callable[[str], str | None] | None = None) -> str | None:
    """Путь к docker CLI: сперва PATH (shutil.which), затем фолбэк Docker Desktop
    `%LOCALAPPDATA%\\Programs\\DockerDesktop\\resources\\bin\\docker.exe` (карта §1:
    2026-09-26 docker не было в PATH). None — не найден нигде."""
    environ = os.environ if environ is None else environ
    which = which or shutil.which
    found = which("docker")
    if found:
        return found
    localapp = (environ.get("LOCALAPPDATA") or "").strip()
    if localapp:
        cand = Path(localapp) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
        if cand.exists():
            return str(cand)
    return None


# ------------------------------------------------------------ каталог стенда
def resolve_stack_dir(environ: dict[str, str] | None = None, *, config_path: str | Path | None = None) -> Path:
    """Каталог стенда stack2 (с docker-compose.yml). Приоритет: env
    `MEMNOTSAFE_STACK2_DIR` → `pilot.yaml`/конфиг (`stand.stack2_dir` или
    `stack2_dir`). Хардкода пути в пакете нет (карта §1). Не задан → StandError."""
    environ = os.environ if environ is None else environ
    raw = (environ.get("MEMNOTSAFE_STACK2_DIR") or "").strip()
    if raw:
        return Path(raw)
    cfg = Path(config_path) if config_path else Path("pilot.yaml")
    if cfg.exists():
        try:
            data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            data = {}
        if isinstance(data, dict):
            d = ((data.get("stand") or {}) if isinstance(data.get("stand"), dict) else {}).get("stack2_dir")
            d = d or data.get("stack2_dir")
            if d:
                return Path(str(d))
    raise StandError(
        "каталог стенда stack2 не задан: укажите переменную окружения "
        "MEMNOTSAFE_STACK2_DIR=<каталог с docker-compose.yml> или ключ "
        "stand.stack2_dir в pilot.yaml (путь к стенду в пакете не хардкодится)."
    )


def _compose_file(stack_dir: Path) -> Path:
    f = stack_dir / COMPOSE_FILENAME
    if not f.exists():
        raise StandError(
            f"{f} не найден — проверьте каталог стенда (MEMNOTSAFE_STACK2_DIR / "
            f"pilot.yaml): ожидается каталог с {COMPOSE_FILENAME}."
        )
    return f


# --------------------------------------------------------- внешние слоты
def _default_runner(cmd: list[str]):
    """Живой запуск процесса. shell=False (список аргументов) — карта: без shell=True."""
    import subprocess

    return subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603 — список, не shell


def _default_healthz(url: str) -> int | None:
    """Живой GET healthz (в тестах подменяется). Транспортный отказ → None."""
    import httpx

    try:
        return httpx.get(url, timeout=_HTTP_TIMEOUT_S).status_code
    except Exception:  # noqa: BLE001 — недоступность стенда — тоже ответ (None)
        return None


def _tail(text: str | None, limit: int = 400) -> str:
    text = (text or "").strip()
    return text[-limit:] if len(text) > limit else text


def _reconfigure_stdout_utf8() -> None:
    """UTF-8 вывод в точке входа (прецедент CARD-P14-fix-stdout)."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _resolve_compose(environ, console: Console) -> tuple[str, Path] | None:
    """docker + compose-файл или None (уже напечатав человеческую причину)."""
    docker = find_docker(environ)
    if not docker:
        console.print(
            "[red]docker CLI не найден: ни в PATH, ни в "
            "%LOCALAPPDATA%\\Programs\\DockerDesktop\\resources\\bin. "
            "Запустите Docker Desktop и повторите (GUI из CLI не поднимаем).[/red]"
        )
        return None
    try:
        compose = _compose_file(resolve_stack_dir(environ))
    except StandError as exc:
        console.print(f"[red]{exc}[/red]")
        return None
    return docker, compose


def _await_healthz(healthz: Healthz, url: str, timeout_s: float, interval_s: float,
                   sleep: Callable[[float], None]) -> bool:
    deadline_tries = max(1, int(timeout_s // max(interval_s, 0.001)) + 1)
    for i in range(deadline_tries):
        if healthz(url) == 200:
            return True
        if i < deadline_tries - 1:
            sleep(interval_s)
    return False


# ------------------------------------------------------------------ up/down/status
def stand_up(*, environ: dict[str, str] | None = None, runner: Runner | None = None,
             healthz: Healthz | None = None, healthz_url: str = HEALTHZ_URL,
             timeout_s: float = _UP_TIMEOUT_S, poll_interval_s: float = _POLL_INTERVAL_S,
             sleep: Callable[[float], None] = time.sleep, console: Console | None = None) -> int:
    """`docker compose -f <stack2>/docker-compose.yml up -d` + ожидание healthz
    9600 → 200. Коды: 0 готов; 1 compose/healthz не удались; 2 нет docker/каталога."""
    console = console or Console()
    environ = os.environ if environ is None else environ
    resolved = _resolve_compose(environ, console)
    if resolved is None:
        return 2
    docker, compose = resolved
    runner = runner or _default_runner
    console.print(f"[dim]$ docker compose -f {compose} up -d[/dim]")
    proc = runner([docker, "compose", "-f", str(compose), "up", "-d"])
    if getattr(proc, "returncode", 1) != 0:
        detail = _tail(getattr(proc, "stderr", "")) or _tail(getattr(proc, "stdout", "")) or "нет вывода"
        console.print(
            f"[red]docker compose up вернул код {getattr(proc, 'returncode', '?')}. "
            f"Docker Desktop запущен и здоров? Подробности: {detail}[/red]"
        )
        return 1
    healthz = healthz or _default_healthz
    if not _await_healthz(healthz, healthz_url, timeout_s, poll_interval_s, sleep):
        console.print(
            f"[red]стенд поднят, но {healthz_url} не ответил 200 за ~{timeout_s:.0f}s — "
            "проверьте контейнеры (memnotsafe stand status) и логи.[/red]"
        )
        return 1
    console.print(f"[green]стенд поднят и готов: {healthz_url} → 200.[/green]")
    return 0


def stand_down(*, environ: dict[str, str] | None = None, runner: Runner | None = None,
               console: Console | None = None) -> int:
    """`docker compose -f <stack2>/docker-compose.yml down`."""
    console = console or Console()
    environ = os.environ if environ is None else environ
    resolved = _resolve_compose(environ, console)
    if resolved is None:
        return 2
    docker, compose = resolved
    runner = runner or _default_runner
    console.print(f"[dim]$ docker compose -f {compose} down[/dim]")
    proc = runner([docker, "compose", "-f", str(compose), "down"])
    if getattr(proc, "returncode", 1) != 0:
        detail = _tail(getattr(proc, "stderr", "")) or _tail(getattr(proc, "stdout", "")) or "нет вывода"
        console.print(f"[red]docker compose down вернул код {getattr(proc, 'returncode', '?')}: {detail}[/red]")
        return 1
    console.print("[green]стенд остановлен (compose down).[/green]")
    return 0


def stand_status(*, environ: dict[str, str] | None = None, runner: Runner | None = None,
                 healthz: Healthz | None = None, healthz_url: str = HEALTHZ_URL,
                 console: Console | None = None) -> int:
    """healthz 9600 + таблица контейнеров (`docker compose ps`). Код 0, если
    healthz=200, иначе 1 (стенд не готов); 2 — нет docker/каталога."""
    console = console or Console()
    environ = os.environ if environ is None else environ
    resolved = _resolve_compose(environ, console)
    if resolved is None:
        return 2
    docker, compose = resolved
    runner = runner or _default_runner
    healthz = healthz or _default_healthz
    code = healthz(healthz_url)
    if code == 200:
        console.print(f"[green]healthz: {healthz_url} → 200 (стенд готов).[/green]")
    elif code is None:
        console.print(f"[yellow]healthz: {healthz_url} недостижим (стенд не поднят?).[/yellow]")
    else:
        console.print(f"[yellow]healthz: {healthz_url} → HTTP {code} (стенд отвечает, но не готов).[/yellow]")
    proc = runner([docker, "compose", "-f", str(compose), "ps"])
    table = _tail(getattr(proc, "stdout", ""), limit=4000)
    console.print("[bold]контейнеры (docker compose ps):[/bold]")
    console.print(table or "  (нет вывода)")
    return 0 if code == 200 else 1


# --------------------------------------------------------------------- keys
def _default_issue_key(client_id: str, *, environ: dict[str, str],
                       keycloak_url: str = KEYCLOAK_URL, key_url: str = KEY_ISSUE_URL) -> str:
    """Boot-strap приём (карта §1: Keycloak 9443 → POST /keys 9600). UI_CLIENT_SECRET
    берётся из окружения/запроса, не из кода; значение наружу не печатается.

    ВНИМАНИЕ (NOTICED): точный контракт bootstrap_api_keys.sh лежит вне репозитория
    (isolated-live-test/, открывать нельзя) — этот дефолт реализует описанный в
    карте поток best-effort; A0 сверяет его ручным приёмом. Юнит-замки гоняют
    stand_keys с ПОДСТАВНЫМ issuer (без сети) — .env/бэкап/секрет-гигиена под
    замком независимо от боевого HTTP."""
    import httpx

    secret = (environ.get("UI_CLIENT_SECRET") or "").strip()
    if not secret:
        raise StandError(
            "UI_CLIENT_SECRET не задан в окружении — headless-перевыпуск ключей "
            "невозможен (значение берётся из env/запроса, не из кода)."
        )
    try:
        token_resp = httpx.post(
            f"{keycloak_url}/realms/master/protocol/openid-connect/token",
            data={"grant_type": "client_credentials", "client_id": "admin-cli", "client_secret": secret},
            timeout=_HTTP_TIMEOUT_S, verify=False,
        )
        token = (token_resp.json() or {}).get("access_token")
        if not token:
            raise StandError(f"Keycloak не выдал токен (HTTP {token_resp.status_code}) — перевыпуск {client_id} прерван.")
        key_resp = httpx.post(
            key_url, headers={"Authorization": f"Bearer {token}"},
            json={"client_id": client_id}, timeout=_HTTP_TIMEOUT_S,
        )
        new_key = (key_resp.json() or {}).get("api_key")
        if not new_key:
            raise StandError(f"POST /keys не вернул ключ для {client_id} (HTTP {key_resp.status_code}).")
        return str(new_key)
    except httpx.HTTPError as exc:
        raise StandError(f"перевыпуск ключа {client_id} не удался: {type(exc).__name__} (стенд/Keycloak доступны?).") from exc


def _write_env_keys(path: Path, values: dict[str, str]) -> None:
    """Перезапись/добавление KEY=VALUE в .env, прочие строки сохранены. Значения
    в консоль не идут (пишутся только в файл)."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(values)
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        key = None
        if "=" in stripped and not stripped.startswith("#"):
            candidate = stripped.split("=", 1)[0].strip()
            candidate = candidate[len("export "):].strip() if candidate.startswith("export ") else candidate
            if candidate in remaining:
                key = candidate
        if key is not None:
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    for key, val in remaining.items():
        out.append(f"{key}={val}")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def stand_keys(*, environ: dict[str, str] | None = None, issue_key: KeyIssuer | None = None,
               env_path: str | Path = ".env", client_ids: tuple[str, ...] = CLIENT_IDS,
               console: Console | None = None) -> int:
    """Headless-перевыпуск SK_GENAI_<cid> (карта §1) с бэкапом .env.bak. Значения
    ключей НИКОГДА не печатаются. Коды: 0 успех; 2 конфиг/секрет/сеть."""
    console = console or Console()
    environ = os.environ if environ is None else environ
    if issue_key is None:
        def issue_key(cid: str, _env=environ) -> str:  # noqa: ANN001
            return _default_issue_key(cid, environ=_env)
    env_path = Path(env_path)
    if env_path.exists():
        backup = Path(str(env_path) + ".bak")
        backup.write_text(env_path.read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"[dim]бэкап прежнего .env: {backup}[/dim]")
    new: dict[str, str] = {}
    try:
        for cid in client_ids:
            new[ENV_KEY_TEMPLATE.format(cid=cid)] = issue_key(cid)
    except StandError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    _write_env_keys(env_path, new)
    console.print("[green]ключи перевыпущены и записаны в .env (только ИМЕНА): "
                  + ", ".join(sorted(new)) + "[/green]")
    return 0


# --------------------------------------------------------------- точка входа CLI
def run_stand(args: argparse.Namespace) -> int:
    """Диспетчер `memnotsafe stand <up|down|status|keys>`."""
    _reconfigure_stdout_utf8()
    console = Console(no_color=getattr(args, "no_color", False))
    cmd = getattr(args, "stand_cmd", None)
    if cmd == "up":
        return stand_up(console=console)
    if cmd == "down":
        return stand_down(console=console)
    if cmd == "status":
        return stand_status(console=console)
    if cmd == "keys":
        return stand_keys(console=console)
    console.print("[red]нужна подкоманда: memnotsafe stand up|down|status|keys[/red]")
    return 2
