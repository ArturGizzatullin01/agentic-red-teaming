"""tests/test_pilot_pack.py — CARD-P17: пилот одной командой.

Всё офлайн: e2e гоняется против ЛОКАЛЬНОГО fake-сервера (OpenAI-совместимый
эхо-эндпоинт на 127.0.0.1), ни одного живого обращения. Замки: --init валидный
шаблон; нет env-ключа → инструкция rc≠0 без traceback; конфиг→probe→preflight→
run→threat-report.html со штампом; retest: UNKNOWN ≠ FIXED.
"""

from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml
from rich.console import Console

from memnotsafe.cli import build_parser, load_campaign
from memnotsafe.pilot_pack import (
    DEFAULT_API_KEY_ENV,
    PilotConfigError,
    _tristate_from_verdict,
    classify_retest,
    init_template,
    load_pilot_config,
    run_pilot,
)

KEY_ENV = DEFAULT_API_KEY_ENV
_REPLY = {"choices": [{"message": {"role": "assistant", "content": "ok, noted."}}]}


class _FakeHandler(BaseHTTPRequestHandler):
    def _send(self, code=200):
        body = json.dumps(_REPLY).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self._send(200)

    def do_GET(self):  # preflight healthz/sampling — отвечаем 200
        self._send(200)

    def log_message(self, *a):
        pass


class _FakeServer:
    def __init__(self):
        self._srv = HTTPServer(("127.0.0.1", 0), _FakeHandler)
        self.base_url = f"http://127.0.0.1:{self._srv.server_address[1]}"

    def __enter__(self):
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *a):
        self._srv.shutdown()


def _console():
    buf = io.StringIO()
    return Console(file=buf, force_terminal=False, no_color=True, width=200), buf


def _write_config(tmp_path: Path, base_url: str, *, budget_cap=20, iterations=1) -> Path:
    doc = {
        "version": 1,
        "target": {"adapter": "http_endpoint", "base_url": base_url,
                   "model": "fake", "api_key_env": KEY_ENV},
        "budget_cap": budget_cap, "iterations": iterations,
    }
    p = tmp_path / "pilot.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


# ------------------------------------------------------------------ --init
def test_init_writes_valid_template(tmp_path):
    dest = tmp_path / "pilot.yaml"
    path, hint = init_template(dest)
    assert path == dest and dest.exists()
    assert KEY_ENV in dest.read_text(encoding="utf-8")
    assert "http_endpoint" in dest.read_text(encoding="utf-8")
    # шаблон валиден только после заполнения base_url — но грузибельность формы:
    cfg = load_pilot_config(dest)  # base_url в шаблоне не пуст (placeholder URL)
    assert cfg.adapter == "http_endpoint" and cfg.budget_cap >= 1
    assert cfg.api_key_env == KEY_ENV


def test_init_refuses_overwrite(tmp_path):
    dest = tmp_path / "pilot.yaml"
    init_template(dest)
    with pytest.raises(PilotConfigError, match="уже существует"):
        init_template(dest)


# ------------------------------------------------------------------ конфиг
def test_config_validation_errors(tmp_path):
    with pytest.raises(PilotConfigError, match="не найден"):
        load_pilot_config(tmp_path / "nope.yaml")

    def _cfg(**target_over):
        base = {"adapter": "http_endpoint", "base_url": "http://x/v1", "model": "m", "api_key_env": KEY_ENV}
        base.update(target_over)
        return {"version": 1, "target": base, "budget_cap": 5, "iterations": 1}

    def _write(doc):
        p = tmp_path / "c.yaml"
        p.write_text(yaml.safe_dump(doc), encoding="utf-8")
        return p

    with pytest.raises(PilotConfigError, match="base_url"):
        load_pilot_config(_write(_cfg(base_url="")))
    with pytest.raises(PilotConfigError, match="adapter"):
        load_pilot_config(_write(_cfg(adapter="mock")))
    doc = _cfg()
    del doc["budget_cap"]
    with pytest.raises(PilotConfigError, match="budget_cap"):
        load_pilot_config(_write(doc))
    doc2 = _cfg()
    doc2["iterations"] = 0
    with pytest.raises(PilotConfigError, match="iterations"):
        load_pilot_config(_write(doc2))


# ------------------------------------------------------ retest (ЗАМОК)
def test_classify_retest_unknown_is_never_fixed():
    # ЗАМОК: новый UNKNOWN → UNKNOWN, НЕ FIXED (даже если раньше было пробито)
    assert classify_retest(True, None) == "UNKNOWN"
    assert classify_retest(None, None) == "UNKNOWN"
    # остальные переходы
    assert classify_retest(True, False) == "FIXED"
    assert classify_retest(True, True) == "STILL VULNERABLE"
    assert classify_retest(False, True) == "NEW"
    assert classify_retest(None, True) == "NEW"
    assert classify_retest(False, False) == "NOT VULNERABLE"


def test_tristate_from_verdict():
    assert _tristate_from_verdict("PROVEN") is True
    assert _tristate_from_verdict("NOT PROVEN") is False
    assert _tristate_from_verdict("INCONCLUSIVE") is None
    assert _tristate_from_verdict("") is None


# ------------------------------------------------------ нет ключа → инструкция
def test_missing_key_gives_instruction_no_traceback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(KEY_ENV, raising=False)
    cfg_path = _write_config(tmp_path, "http://127.0.0.1:1/v1")
    console, buf = _console()
    rc = run_pilot(cfg_path, tmp_path / "out", load_campaign=load_campaign, console=console)
    text = buf.getvalue()
    assert rc == 2
    assert KEY_ENV in text                 # инструкция называет переменную
    assert "Traceback" not in text          # не traceback


# ------------------------------------------------------ e2e против fake-сервера
def test_pilot_e2e_against_localhost_fake(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(KEY_ENV, "fake-local-key")
    with _FakeServer() as srv:
        cfg_path = _write_config(tmp_path, srv.base_url)
        out = tmp_path / "runs" / "pilot-run"
        console, buf = _console()
        rc = run_pilot(cfg_path, out, load_campaign=load_campaign, console=console)
    text = buf.getvalue()
    assert rc == 0, text
    for marker in ("PROBE", "PREFLIGHT", "ИТОГ ПИЛОТА", "threat-report"):
        assert marker in text
    assert (out / "threat-report.html").exists()
    assert (out / "campaign.json").exists()
    assert (out / "pilot-cases.json").exists()
    # штамп присутствует в сводке (tier-1 → INCONCLUSIVE честно)
    assert "вердикт:" in text
    cases = json.loads((out / "pilot-cases.json").read_text(encoding="utf-8"))
    assert cases, "стартовый пак дал кейсы"
    # эхо-сервер ничего не сливает → НИ ОДНОГО ложного PROVEN (vulnerable True);
    # честно только None (UNKNOWN, ненаблюдаемо) или False (детерминированно опровергнуто)
    assert not any(c["vulnerable"] is True for c in cases)
    assert all(c["vulnerable"] in (None, False) for c in cases)
    assert any(c["vulnerable"] is None for c in cases)  # tier-1 даёт хотя бы один честный UNKNOWN


def test_pilot_retest_unknown_not_fixed_e2e(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(KEY_ENV, "fake-local-key")
    with _FakeServer() as srv:
        cfg_path = _write_config(tmp_path, srv.base_url)
        base = tmp_path / "runs" / "pilot-base"
        new = tmp_path / "runs" / "pilot-new"
        console, _ = _console()
        assert run_pilot(cfg_path, base, load_campaign=load_campaign, console=console) == 0
        console2, buf2 = _console()
        assert run_pilot(cfg_path, new, load_campaign=load_campaign, console=console2, baseline=base) == 0
    text = buf2.getvalue()
    assert "RETEST" in text
    retest = json.loads((new / "retest.json").read_text(encoding="utf-8"))
    assert retest
    # ЗАМОК: ни одного ложного FIXED — против ненаблюдаемой/недоказанной цели
    # «исправлено» не выносим. Ненаблюдённые кейсы (baseline None → new None) →
    # UNKNOWN; детерминированно опровергнутые (False→False) → NOT VULNERABLE.
    assert not any(row["status"] == "FIXED" for row in retest)
    assert any(row["status"] == "UNKNOWN" for row in retest)
    assert all(row["status"] in ("UNKNOWN", "NOT VULNERABLE", "STILL VULNERABLE", "NEW", "NEW CASE")
               for row in retest)


# ------------------------------------------------------ cli routing
def test_cli_pilot_arg_parsing():
    parser = build_parser()
    a = parser.parse_args(["pilot", "--init"])
    assert a.init is True and a.config is None
    b = parser.parse_args(["pilot", "--config", "pilot.yaml", "--output", "runs/p", "--baseline", "runs/prev"])
    assert b.config == "pilot.yaml" and b.output == "runs/p" and b.baseline == "runs/prev"


def test_cli_pilot_needs_config_or_init(capsys):
    parser = build_parser()
    args = parser.parse_args(["pilot"])
    rc = args.func(args)
    assert rc == 2
    err = capsys.readouterr().err
    assert "--init" in err or "--config" in err
