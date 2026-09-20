"""tests/test_langfuse_sink.py — карточка P11-3: реальный приёмник Langfuse + врезка.

Часть 1 — LangfuseTraceSink (PASS_IF 3a): фейковый http.server получает batch
правильной формы (ingestion API v3: тело {"batch": [{"type": "trace-create"|
"event-create", "id", "timestamp", "body": {...}}]}, Basic auth pk:sk, путь
/api/public/ingestion); HTTP 4xx/5xx и сетевой отказ → исключение из send()
(контракт P11-1: отказ приёмника; ретраев ВНУТРИ send нет — иначе двойная
доставка, ретрай — забота экспортёра); отсутствие обязательного env →
ValueError при создании, не при send.

Часть 2 — врезка за флагом (PASS_IF 3d): с флагом MEMNOTSAFE_TRACE_EXPORT=1
события mock-кампании доезжают до sink (trace по run_id), локальный events.jsonl
при этом побайтово тот же, что без флага; без флага артефакты прогона побайтово
равны базовым — базовый campaign.py загружается из git-объекта BASE_SHA,
случайность (uuid/время/идентификаторы) заморожена, деревья артефактов
сравниваются рекурсивно. После P12 (VERDICT-P12-2026-09-20, вариант (b))
attempts.jsonl и campaign.json сравниваются канонически (sort_keys) после
рекурсивного удаления всех ключей `timing` — живые perf_counter-длительности
недетерминированы между прогонами, побайтовая идентичность этих двух файлов
структурно недостижима; остальные артефакты — по-прежнему побайтово.
"""

from __future__ import annotations

import asyncio
import base64
import http.server
import importlib.util
import json
import socket
import subprocess
import sys
import threading
import types
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "3a4ea58"  # карточка P11-3: база = main 3a4ea58 (сверен до старта)

FLAG_VAR = "MEMNOTSAFE_TRACE_EXPORT"
HOST_VAR = "LANGFUSE_HOST"
PUBLIC_KEY_VAR = "LANGFUSE_PUBLIC_KEY"
SECRET_KEY_VAR = "LANGFUSE_SECRET_KEY"
PUBLIC_KEY = "pk-lf-TESTPLACEHOLDER"
SECRET_KEY = "sk-lf-TESTPLACEHOLDER"


# -- фейковый ingestion-сервер -------------------------------------------------

class _SinkState:
    def __init__(self, status: int) -> None:
        self.status = status
        self.requests: list[dict] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 — имя метода протокола http.server
        state: _SinkState = self.server.sink_state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        state.requests.append(
            {
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
                "body": json.loads(raw.decode("utf-8")) if raw else None,
            }
        )
        self.send_response(state.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:  # тише в выводе pytest
        return


@contextmanager
def _ingestion_server(status: int = 200):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.sink_state = _SinkState(status)  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", server.sink_state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _closed_port() -> int:
    """Порт, на котором гарантированно никто не слушает (bind-close)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _event(n: int, run: str = "RUN-X") -> dict:
    return {
        "event_id": f"evt-{n:04d}",
        "run_id": run,
        "case_id": "CASE-1",
        "session_id": "sess-1",
        "actor": "system",
        "timestamp": f"2026-09-20T00:00:{n:02d}.000000+00:00",
        "event": "state_change",
        "detail": {"step": n},
    }


# -- часть 1: sink -------------------------------------------------------------

def test_send_posts_wellformed_ingestion_batch() -> None:
    from memnotsafe.tracing.langfuse_sink import LangfuseTraceSink

    with _ingestion_server() as (url, state):
        sink = LangfuseTraceSink(host=url, public_key=PUBLIC_KEY, secret_key=SECRET_KEY)
        sink.send([_event(1), _event(2), _event(3, run="RUN-Y")])

    assert len(state.requests) == 1
    req = state.requests[0]
    assert req["path"] == "/api/public/ingestion"
    expected_auth = "Basic " + base64.b64encode(
        f"{PUBLIC_KEY}:{SECRET_KEY}".encode()
    ).decode()
    assert req["auth"] == expected_auth
    assert req["content_type"] == "application/json"

    batch = req["body"]["batch"]
    traces = [item for item in batch if item["type"] == "trace-create"]
    events = [item for item in batch if item["type"] == "event-create"]
    assert sorted(t["body"]["id"] for t in traces) == ["RUN-X", "RUN-Y"]
    assert len(events) == 3
    for item, n, run in zip(events, [1, 2, 3], ["RUN-X", "RUN-X", "RUN-Y"]):
        body = item["body"]
        assert body["id"] == f"evt-{n:04d}"
        assert body["traceId"] == run
        assert body["name"] == "state_change"
        assert body["startTime"] == f"2026-09-20T00:00:{n:02d}.000000+00:00"
        assert body["metadata"]["detail"] == {"step": n}
    for item in batch:
        assert item["id"] and item["timestamp"]


@pytest.mark.parametrize("status", [401, 500])
def test_send_raises_on_http_error(status: int) -> None:
    from memnotsafe.tracing.langfuse_sink import LangfuseTraceSink

    with _ingestion_server(status=status) as (url, state):
        sink = LangfuseTraceSink(host=url, public_key=PUBLIC_KEY, secret_key=SECRET_KEY)
        with pytest.raises(Exception):
            sink.send([_event(1)])
    assert len(state.requests) == 1  # один POST, без ретраев внутри send


def test_send_raises_on_network_error() -> None:
    from memnotsafe.tracing.langfuse_sink import LangfuseTraceSink

    port = _closed_port()
    sink = LangfuseTraceSink(
        host=f"http://127.0.0.1:{port}", public_key=PUBLIC_KEY, secret_key=SECRET_KEY,
        timeout_s=2.0,
    )
    with pytest.raises(Exception):
        sink.send([_event(1)])


def test_missing_env_raises_value_error_at_creation() -> None:
    from memnotsafe.tracing.langfuse_sink import LangfuseTraceSink

    with pytest.raises(ValueError) as full_empty:
        LangfuseTraceSink(env={})
    message = str(full_empty.value)
    for var in (HOST_VAR, PUBLIC_KEY_VAR, SECRET_KEY_VAR):
        assert var in message
    with pytest.raises(ValueError) as partial:
        LangfuseTraceSink(env={HOST_VAR: "http://127.0.0.1:1"})
    assert PUBLIC_KEY_VAR in str(partial.value) and SECRET_KEY_VAR in str(partial.value)


def test_build_langfuse_exporter_respects_flag() -> None:
    from memnotsafe.tracing.langfuse_sink import build_langfuse_exporter

    assert build_langfuse_exporter(Path("whatever-spool"), env={}) is None
    assert (
        build_langfuse_exporter(
            Path("whatever-spool"), env={FLAG_VAR: "0", HOST_VAR: "http://x",
                                         PUBLIC_KEY_VAR: PUBLIC_KEY, SECRET_KEY_VAR: SECRET_KEY}
        )
        is None
    )
    # флаг есть, ключей нет — громкий отказ конфигурации при создании, не молчание
    with pytest.raises(ValueError):
        build_langfuse_exporter(Path("whatever-spool"), env={FLAG_VAR: "1"})


# -- часть 2: врезка за флагом ---------------------------------------------------

def _scenario(tmp_path: Path, family: str = "cross_user_bac") -> Scenario:
    return Scenario(
        id=family,
        path=tmp_path / f"{family}.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"),
        victim=ActorConfig(user_id="1002"),
        attack_family=family,
        repetitions=2,
    )


def test_flag_on_events_reach_sink_and_local_jsonl_intact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(FLAG_VAR, "1")
    out_off = tmp_path / "run-off"
    out_on = tmp_path / "run-on"

    # прогон без флага: эталон локального evidence
    monkeypatch.delenv(FLAG_VAR, raising=False)
    result_off = asyncio.run(Campaign(_scenario(tmp_path), MockTarget(True), out_off).run())

    with _ingestion_server() as (url, state):
        monkeypatch.setenv(FLAG_VAR, "1")
        monkeypatch.setenv(HOST_VAR, url)
        monkeypatch.setenv(PUBLIC_KEY_VAR, PUBLIC_KEY)
        monkeypatch.setenv(SECRET_KEY_VAR, SECRET_KEY)
        result_on = asyncio.run(Campaign(_scenario(tmp_path), MockTarget(True), out_on).run())

    # (1) доставка: sink получил ingestion-пакеты, все события кампании доехали
    assert state.requests, "экспортёр не отправил ничего"
    event_ids_sent: set[str] = set()
    trace_ids_sent: set[str] = set()
    for req in state.requests:
        assert req["auth"] == "Basic " + base64.b64encode(
            f"{PUBLIC_KEY}:{SECRET_KEY}".encode()
        ).decode()
        for item in req["body"]["batch"]:
            if item["type"] == "event-create":
                event_ids_sent.add(item["body"]["id"])
                trace_ids_sent.add(item["body"]["traceId"])
            else:
                trace_ids_sent.add(item["body"]["id"])
    rows = [
        json.loads(line)
        for line in (out_on / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows, "events.jsonl пуст"
    assert {row["event_id"] for row in rows} <= event_ids_sent
    assert result_on.run_id in trace_ids_sent

    # (2) спул пуст (всё доставлено), каталог экспорта создан только у флаг-он
    assert not list((out_on / "trace-export-spool").glob("batch-*.json"))
    assert not (out_off / "trace-export-spool").exists()
    assert result_off.run_id != result_on.run_id  # два независимых прогона


# -- заморозка случайности + база из git ------------------------------------------

class _Freeze:
    """Детерминизм mock-кампании: uuid4, таймстемпы, run/case-идентификаторы,
    счётчик event_id (глобальный itertools.count в events) и created_at
    эксперимента (inline datetime.now в experiment.py)."""

    def __init__(self) -> None:
        self._extra_resets: list = []
        self.reset()

    def reset(self) -> None:
        self._n = 0
        self._t = 0
        self._run = 0
        self._case = 0
        for extra in self._extra_resets:
            extra()

    def uuid4(self) -> object:
        self._n += 1
        return types.SimpleNamespace(hex=f"{self._n:032x}")

    def now_iso(self) -> str:
        self._t += 1
        return f"2026-09-20T00:{self._t // 60:02d}:{self._t % 60:02d}.000000+00:00"

    def run_id(self) -> str:
        self._run += 1
        return f"RUN-FROZEN-{self._run:03d}"

    def case_id(self, attack_id: str, attempt: int) -> str:
        self._case += 1
        return f"CASE-FROZEN-{self._case:03d}"


def _load_base_campaign(tmp_path: Path):
    proc = subprocess.run(
        ["git", "show", f"{BASE_SHA}:src/memnotsafe/core/campaign.py"],
        capture_output=True, cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, f"git show {BASE_SHA} не удался: {proc.stderr[:200]!r}"
    path = tmp_path / "campaign_base_under_test.py"
    path.write_bytes(proc.stdout)
    spec = importlib.util.spec_from_file_location("campaign_base_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _freeze_everything(monkeypatch, tmp_path: Path):
    import itertools

    import memnotsafe.adapters.mock as mock_mod
    import memnotsafe.core.campaign as campaign_mod
    import memnotsafe.core.experiment as experiment_mod
    import memnotsafe.core.runner as runner_mod
    import memnotsafe.tracing.events as events_mod

    freeze = _Freeze()
    monkeypatch.setattr(uuid, "uuid4", freeze.uuid4)
    monkeypatch.setattr(mock_mod, "_utc_now", freeze.now_iso)
    monkeypatch.setattr(events_mod, "_utc_now_iso", freeze.now_iso)
    monkeypatch.setattr(runner_mod, "new_run_id", freeze.run_id)
    monkeypatch.setattr(runner_mod, "new_case_id", freeze.case_id)
    monkeypatch.setattr(campaign_mod, "new_run_id", freeze.run_id)
    monkeypatch.setattr(campaign_mod, "new_case_id", freeze.case_id)

    # event_id: new_event_id читает глобальный счётчик events._counter —
    # каждый прогон обязан начинать с чистого счётчика.
    freeze._extra_resets.append(
        lambda: setattr(events_mod, "_counter", itertools.count(1))
    )

    # timestamp у TraceEvent — default_factory с прямой ссылкой на функцию:
    # патчим конструктор, который использует mock-адаптер (единственный
    # производитель событий в этом тесте).
    real_trace_event = events_mod.TraceEvent

    def _trace_event_frozen_ts(*args: object, **kwargs: object):
        if not args and "timestamp" not in kwargs:
            kwargs["timestamp"] = freeze.now_iso()
        return real_trace_event(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(mock_mod, "TraceEvent", _trace_event_frozen_ts)

    # created_at эксперимента: inline datetime.now(timezone.utc).isoformat().
    class _FrozenDateTime:
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001 — сигнатура протокола datetime
            return types.SimpleNamespace(isoformat=lambda: freeze.now_iso())

    monkeypatch.setattr(experiment_mod, "datetime", _FrozenDateTime)

    base_module = _load_base_campaign(tmp_path)
    monkeypatch.setattr(base_module, "new_run_id", freeze.run_id)
    monkeypatch.setattr(base_module, "new_case_id", freeze.case_id)
    return freeze, base_module


def _tree(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(root)).replace("\\", "/")] = path.read_bytes()
    return out


# -- P12: нормализация «минус timing» (VERDICT-P12-2026-09-20, вариант (b)) -----
#
# После P12 длительности фаз попытки — живые perf_counter-значения: attempts.jsonl
# несёт их аддитивным полем строки исхода, campaign.json — через evidence-embed.
# Они недетерминированы между любыми двумя прогонами, поэтому побайтовая
# идентичность этих двух файлов структурно недостижима. Замки ниже сравнивают
# их канонически (sort_keys) после рекурсивного удаления ВСЕХ ключей `timing`:
# равенство после удаления эквивалентно утверждению «отличаются только
# timing-значения». Все остальные артефакты сравниваются побайтово без
# изменений; шире ключа `timing` сравнение не ослабляется (вердикт, п.3).


def _strip_timing(obj: object) -> object:
    if isinstance(obj, dict):
        return {k: _strip_timing(v) for k, v in obj.items() if k != "timing"}
    if isinstance(obj, list):
        return [_strip_timing(v) for v in obj]
    return obj


def _jsonl_parse(blob: bytes) -> list:
    return [json.loads(line) for line in blob.decode("utf-8").splitlines() if line.strip()]


def _normalize_tree(tree: dict[str, bytes]) -> dict[str, bytes]:
    """attempts.jsonl/campaign.json → канонический JSON без ключей `timing`;
    остальные файлы — нетронутые байты."""
    out: dict[str, bytes] = {}
    for name, blob in tree.items():
        if name == "attempts.jsonl":
            rows = [_strip_timing(row) for row in _jsonl_parse(blob)]
            out[name] = "\n".join(
                json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows
            ).encode("utf-8")
        elif name == "campaign.json":
            out[name] = json.dumps(
                _strip_timing(json.loads(blob.decode("utf-8"))),
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        else:
            out[name] = blob
    return out


def _has_timing(obj: object) -> bool:
    if isinstance(obj, dict):
        return "timing" in obj or any(_has_timing(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_timing(v) for v in obj)
    return False


def _clear_export_env(monkeypatch) -> None:
    for var in (FLAG_VAR, HOST_VAR, PUBLIC_KEY_VAR, SECRET_KEY_VAR):
        monkeypatch.delenv(var, raising=False)


def test_flag_off_artifacts_byte_identical_to_base(tmp_path: Path, monkeypatch) -> None:
    """PASS_IF 3d: без флага — ноль изменений поведения.

    Базовый campaign.py (git-объект BASE_SHA) и текущий прогонятся на одном
    замороженном генераторе случайности; деревья артефактов обязаны совпасть
    (весь набор файлов, включая events.jsonl/cases.jsonl/campaign.json/
    experiment.json/attempts/ledger/traces/evidence). После P12 — по
    VERDICT-P12-2026-09-20 (вариант (b)): attempts.jsonl/campaign.json
    сравниваются канонически после удаления ключей `timing` (живые таймеры
    недетерминированы), остальные файлы — побайтово.
    """
    freeze, base_module = _freeze_everything(monkeypatch, tmp_path)
    _clear_export_env(monkeypatch)
    scenario = _scenario(tmp_path)

    freeze.reset()
    asyncio.run(base_module.Campaign(scenario, MockTarget(True), tmp_path / "out-base").run())
    freeze.reset()
    asyncio.run(Campaign(scenario, MockTarget(True), tmp_path / "out-branch").run())

    base_tree = _tree(tmp_path / "out-base")
    branch_tree = _tree(tmp_path / "out-branch")
    assert base_tree, "артефакты базового прогона не появились"
    assert set(base_tree) == set(branch_tree), (
        f"набор файлов разошёлся: только-в-базе={sorted(set(base_tree) - set(branch_tree))} "
        f"только-в-ветке={sorted(set(branch_tree) - set(base_tree))}"
    )
    # VERDICT-P12-2026-09-20, вариант (b): campaign.json несёт evidence.timing
    # ОБОИХ прогонов (базовый campaign.py исполняется текущим раннером), и эти
    # живые значения недетерминированы между прогонами. Нормализация минус
    # `timing` = доказательство «отличаются только timing-значения»; всё
    # остальное дерево — побайтово.
    norm_base = _normalize_tree(base_tree)
    norm_branch = _normalize_tree(branch_tree)
    differing = [name for name, blob in norm_base.items() if blob != norm_branch[name]]
    assert not differing, f"артефакты отличаются (после удаления timing): {differing}"

    # Вердикт п.2 — нормализация не маскирует отсутствие P12-поля. campaign.json:
    # timing обязан присутствовать в ОБОИХ армах (evidence обоих прогонов).
    for arm, tree in (("base", base_tree), ("branch", branch_tree)):
        assert _has_timing(json.loads(tree["campaign.json"])), (
            f"campaign.json[{arm}] не содержит timing — P12-поле исчезло"
        )
    # attempts.jsonl: асимметрия ожидаема и заперта явно — текущий код пишет
    # timing в строку исхода, базовый campaign.py (BASE_SHA=3a4ea58, pre-P12)
    # поле в history.record не передаёт.
    assert any(_has_timing(r) for r in _jsonl_parse(branch_tree["attempts.jsonl"])), (
        "attempts.jsonl[branch] не содержит timing — P12-поле исчезло"
    )
    assert not any(_has_timing(r) for r in _jsonl_parse(base_tree["attempts.jsonl"])), (
        "attempts.jsonl[base] неожиданно содержит timing"
    )
    assert not (tmp_path / "out-branch" / "trace-export-spool").exists()


def test_flag_on_local_evidence_byte_identical_to_flag_off(
    tmp_path: Path, monkeypatch
) -> None:
    """Флаг меняет только экспорт: локальный evidence (events.jsonl и всё
    дерево, кроме каталога экспорта) побайтово тот же, что без флага — после
    P12 с нормализацией минус `timing` по VERDICT-P12-2026-09-20 (вариант (b))."""
    freeze, _ = _freeze_everything(monkeypatch, tmp_path)
    out_off = tmp_path / "run-off"
    out_on = tmp_path / "run-on"
    scenario = _scenario(tmp_path)

    _clear_export_env(monkeypatch)
    freeze.reset()
    asyncio.run(Campaign(scenario, MockTarget(True), out_off).run())

    with _ingestion_server() as (url, state):
        monkeypatch.setenv(FLAG_VAR, "1")
        monkeypatch.setenv(HOST_VAR, url)
        monkeypatch.setenv(PUBLIC_KEY_VAR, PUBLIC_KEY)
        monkeypatch.setenv(SECRET_KEY_VAR, SECRET_KEY)
        freeze.reset()
        asyncio.run(Campaign(scenario, MockTarget(True), out_on).run())

    assert state.requests, "с флагом ничего не отправлено"
    off_tree = _tree(out_off)
    on_tree = {
        name: blob
        for name, blob in _tree(out_on).items()
        if not name.startswith("trace-export-spool/")
    }
    assert set(off_tree) == set(on_tree), (
        f"набор файлов разошёлся: только-без-флага={sorted(set(off_tree) - set(on_tree))} "
        f"только-с-флагом={sorted(set(on_tree) - set(off_tree))}"
    )
    # VERDICT-P12-2026-09-20, вариант (b): оба прогона — текущий код, timing
    # пишется в оба арма (attempts.jsonl строкой исхода, campaign.json через
    # evidence-embed), живые значения недетерминированы между прогонами.
    # Замок = «флаг меняет только экспорт»: всё, кроме timing-значений,
    # побайтово идентично.
    norm_off = _normalize_tree(off_tree)
    norm_on = _normalize_tree(on_tree)
    differing = [name for name, blob in norm_off.items() if blob != norm_on[name]]
    assert not differing, f"локальный evidence изменился от флага (после удаления timing): {differing}"

    # Вердикт п.2: timing присутствует в ОБОИХ армах и в ОБОИХ файлах-носителях
    # — нормализация не маскирует отсутствие P12-поля.
    for arm, tree in (("off", off_tree), ("on", on_tree)):
        assert _has_timing(json.loads(tree["campaign.json"])), (
            f"campaign.json[{arm}] не содержит timing — P12-поле исчезло"
        )
        assert any(_has_timing(r) for r in _jsonl_parse(tree["attempts.jsonl"])), (
            f"attempts.jsonl[{arm}] не содержит timing — P12-поле исчезло"
        )
