"""tests/test_preflight.py — карточка S: сказать ДО живого прогона, что будет
измерено, и не дать измерить подделку.

Всё офлайн (Принцип VI): ни стенда, ни сети, ни docker — HTTP и Mongo
подменяются фейками через слоты run_preflight, pymongo-ветка проверяется
подменой sys.modules. Главный замок — B2: одинаковые ключи принципалов =
ложный кросс-юзер успех. Значение ключа не имеет права появиться нигде —
игла sk-genai-PREFLIGHT-NEEDLE-4C1D проверяется по полному выводу CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from memnotsafe.preflight import (  # noqa: E402
    BLOCKER,
    OK,
    SKIP,
    WARNING,
    MongoProbe,
    _default_mongo,
    run_preflight,
)

_REPO = Path(__file__).resolve().parents[1]
NEEDLE = "sk-genai-PREFLIGHT-NEEDLE-4C1D"

_LIVE_YAML = """
id: preflight_live_probe
target:
  adapter: investment_stand
  base_url: "http://localhost:9600"
  auth_mode: vulnerable
  identities:
    "1001": SK_GENAI_1001
    "1002": SK_GENAI_1002
  mongo_uri: "mongodb://localhost:28017"
  mongo_db: agent_memory
actors:
  attacker: {user_id: "1001"}
  victim: {user_id: "1002"}
attack:
  family: cross_user_bac
"""


def _write(tmp_path, text=_LIVE_YAML) -> Path:
    p = tmp_path / "scenario.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def _fake_http(healthz=200, sampling=200):
    """Транспорт-заглушка: ответы по путям, остальное — 404."""
    table = {"/healthz": healthz, "/debug/sampling": sampling}

    async def http_get(url):
        for path, code in table.items():
            if url.endswith(path):
                from memnotsafe.preflight import HttpReply

                return HttpReply(status_code=code if code is not None else None,
                                 error="ConnectError" if code is None else None)
        raise AssertionError(f"неожидаемый путь {url}")

    return http_get


def _fake_mongo(state):
    def probe(uri, db_name):
        from memnotsafe.preflight import MongoProbe

        return MongoProbe(state=state)

    return probe


def _run(tmp_path, *, env, healthz=200, sampling=200, mongo="ok", text=_LIVE_YAML):
    return run_preflight(
        _write(tmp_path, text),
        http_get=_fake_http(healthz, sampling),
        mongo_probe=_default_mongo if mongo is None else _fake_mongo(mongo),
        environ=env,
    )


def _by_id(result, check_id):
    return next(c for c in result.checks if c.check_id == check_id)


# ------------------------------------------------------------------ PASS_IF 1

def test_b2_catches_forgery(tmp_path, monkeypatch):
    """Одинаковые значения принципалов — блокер, ненулевой код, названы оба
    user_id и оба имени переменных (значение — никогда)."""
    monkeypatch.setenv("SK_GENAI_1001", "sk-genai-same-value")
    monkeypatch.setenv("SK_GENAI_1002", "sk-genai-same-value")
    result = _run(tmp_path, env=None)
    b2 = _by_id(result, "B2")
    assert b2.status == BLOCKER
    assert result.exit_code == 1
    rendered = result.render()
    assert "1001" in rendered and "1002" in rendered
    assert "SK_GENAI_1001" in rendered and "SK_GENAI_1002" in rendered
    assert "sk-genai-same-value" not in rendered


# ------------------------------------------------------------------ PASS_IF 2

def test_needle_never_leaks(tmp_path, monkeypatch, capsys):
    """Игла в значении ключа не появляется ни в полном stdout+stderr, ни в
    сообщениях исключений — в раскладках B1, B2 и на успешном пути. Полный
    путь CLI: cli.main(['preflight', ...]) с подменёнными дефолтами (офлайн)."""
    import memnotsafe.preflight as pf
    from memnotsafe.cli import main as cli_main

    monkeypatch.setattr(pf, "_default_http_get", _fake_http())
    monkeypatch.setattr(pf, "_default_mongo", _fake_mongo("ok"))
    layouts = {
        "b1": {"SK_GENAI_1001": NEEDLE},  # 1002 не задана
        "b2": {"SK_GENAI_1001": NEEDLE, "SK_GENAI_1002": NEEDLE},
        "healthy": {"SK_GENAI_1001": NEEDLE, "SK_GENAI_1002": "another-value"},
    }
    for name, env in layouts.items():
        for var in ("SK_GENAI_1001", "SK_GENAI_1002"):
            monkeypatch.delenv(var, raising=False)
        for var, val in env.items():
            monkeypatch.setenv(var, val)
        # не падает — исключений с иглой в сообщении нет вовсе
        code = cli_main(["preflight", "--scenario", str(_write(tmp_path))])
        captured = capsys.readouterr()
        assert NEEDLE not in captured.out, name
        assert NEEDLE not in captured.err, name
        assert code in (0, 1), name
    # и в render() поверхностного результата — тот же текст
    monkeypatch.setenv("SK_GENAI_1001", NEEDLE)
    monkeypatch.setenv("SK_GENAI_1002", NEEDLE)
    assert NEEDLE not in _run(tmp_path, env=None).render()


# ------------------------------------------------------------------ PASS_IF 3

def test_b1_differs_from_b2(tmp_path, monkeypatch):
    monkeypatch.delenv("SK_GENAI_1001", raising=False)
    monkeypatch.setenv("SK_GENAI_1002", "value-two")
    result = _run(tmp_path, env=None)
    b1, b2 = _by_id(result, "B1"), _by_id(result, "B2")
    assert b1.status == BLOCKER and "SK_GENAI_1001" in b1.text
    assert b2.status == SKIP  # карточка B2-partial: непустых < 2 — сравнения не было
    assert "меньше двух" in b2.text

    monkeypatch.setenv("SK_GENAI_1001", "value-one")
    result = _run(tmp_path, env=None)
    assert result.blockers == 0
    assert result.exit_code == 0


# ------------------------------------------------------------------ PASS_IF 4

def test_three_principals_pairwise(tmp_path, monkeypatch):
    text = _LIVE_YAML.replace(
        '    "1002": SK_GENAI_1002\n',
        '    "1002": SK_GENAI_1002\n    "1003": SK_GENAI_1003\n',
    ).replace('  victim: {user_id: "1002"}', '  victim: {user_id: "1003"}')
    monkeypatch.setenv("SK_GENAI_1001", "dup")
    monkeypatch.setenv("SK_GENAI_1002", "dup")
    monkeypatch.setenv("SK_GENAI_1003", "unique-three")
    result = _run(tmp_path, env=None, text=text)
    b2 = _by_id(result, "B2")
    assert b2.status == BLOCKER
    # названа именно совпавшая пара; третий принципал в блокер не попал
    assert "1001" in b2.text and "1002" in b2.text and "SK_GENAI_1002" in b2.text
    assert "1003" not in b2.text and "SK_GENAI_1003" not in b2.text


# ------------------------------------------------------------------ PASS_IF 5

def test_w2_distinguishes_404_from_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    not_found = _run(tmp_path, env=None, sampling=404)
    w2 = _by_id(not_found, "W2")
    assert w2.status == WARNING
    assert "старее карточки P" in w2.text
    assert "unavailable" in w2.text

    transport_down = _run(tmp_path, env=None, healthz=None)
    w1 = _by_id(transport_down, "W1")
    assert w1.status == WARNING
    assert "недостижим" in w1.text
    assert _by_id(transport_down, "W2").status == SKIP
    assert w1.text != w2.text  # различимы по тексту


# ------------------------------------------------------------------ PASS_IF 6

def test_w6_both_reasons_and_no_overclaim(tmp_path, monkeypatch):
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    fresh_or_old = _run(tmp_path, env=None, mongo="no-collection")
    w6 = _by_id(fresh_or_old, "W6")
    assert w6.status == WARNING
    # ОБЕ причины названы, выбор между ними не сделан
    assert "свежий" in w6.text and "сессий ещё не было" in w6.text
    assert "старее карточки I" in w6.text and "retrieval останется UNKNOWN" in w6.text
    assert "НЕ различает" in w6.text
    assert "сломан" not in w6.text

    present = _run(tmp_path, env=None, mongo="ok")
    w6 = _by_id(present, "W6")
    assert w6.status == OK
    assert "писал" in w6.text and "карточки I" in w6.text
    assert "свежий" not in w6.text and "старее" not in w6.text


# ------------------------------------------------------------------ PASS_IF 7

def test_w5_is_unknown_not_unreachable(tmp_path, monkeypatch):
    """pymongo нет (подменён импорт) — «проверить нельзя», а не «недоступен»;
    preflight не падает. Проверяется РЕАЛЬНАЯ ветка импорта _default_mongo."""
    monkeypatch.setitem(sys.modules, "pymongo", None)  # import pymongo -> ImportError
    probe = _default_mongo("mongodb://localhost:28017", "agent_memory")
    assert probe.state == "pymongo-missing"

    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    result = _run(tmp_path, env=None, mongo=None)  # None -> дефолтный щуп
    w5 = _by_id(result, "W5")
    assert w5.status == WARNING
    assert "проверить нельзя" in w5.text
    assert "это UNKNOWN" in w5.text  # дизамбигуатор: не «Mongo недоступен»
    assert _by_id(result, "W4").status == SKIP
    assert _by_id(result, "W6").status == SKIP
    assert result.exit_code == 0  # предупреждение, не блокер


# ------------------------------------------------------------------ PASS_IF 8

def test_contract_wording_verbatim(tmp_path, monkeypatch):
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    exact = "write/persistence UNKNOWN → композит недостижим"
    # W3: mongo_uri не задан (не этот сценарий — отдельный YAML без uri)
    no_uri = _LIVE_YAML.replace('  mongo_uri: "mongodb://localhost:28017"\n', "")
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    w3 = _by_id(_run(tmp_path, env=None, text=no_uri), "W3")
    assert w3.status == WARNING and exact in w3.text
    # W4: задан, но недоступен
    w4 = _by_id(_run(tmp_path, env=None, mongo="unreachable"), "W4")
    assert w4.status == WARNING and exact in w4.text
    # обе строки рядом — для хендофа
    print(f"\nW3: {w3.text}\nW4: {w4.text}")


# ------------------------------------------------------------------ PASS_IF 9

def test_http_get_only_and_paths(tmp_path, monkeypatch):
    """Перехват на СЛОЕ httpx: подменяется httpx.AsyncClient — recorder пишет
    метод и URL каждого запроса; POST/PUT/DELETE/PATCH падают сразу."""

    class _Resp:
        def __init__(self, code):
            self.status_code = code

    class Recorder:
        calls: list[tuple[str, str]] = []

        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, **kwargs):
            Recorder.calls.append(("GET", url))
            return _Resp(200)

        async def _forbidden(self, method, url, **kwargs):
            Recorder.calls.append((method, url))
            raise AssertionError(f"preflight сделал {method} {url}")

        async def post(self, url, **kw):
            return await self._forbidden("POST", url, **kw)

        async def put(self, url, **kw):
            return await self._forbidden("PUT", url, **kw)

        async def delete(self, url, **kw):
            return await self._forbidden("DELETE", url, **kw)

        async def patch(self, url, **kw):
            return await self._forbidden("PATCH", url, **kw)

    import memnotsafe.preflight as pf

    monkeypatch.setattr(pf.httpx, "AsyncClient", Recorder)
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    result = run_preflight(
        _write(tmp_path), mongo_probe=_fake_mongo("ok"), environ=None
    )
    assert result.exit_code == 0
    assert Recorder.calls == [
        ("GET", "http://localhost:9600/healthz"),
        ("GET", "http://localhost:9600/debug/sampling"),
    ], Recorder.calls
    assert all(method == "GET" for method, _ in Recorder.calls)


# ------------------------------------------------------------------ PASS_IF 10

def test_healthy_layout_prints_every_check(tmp_path, monkeypatch):
    monkeypatch.setenv("SK_GENAI_1001", "healthy-one")
    monkeypatch.setenv("SK_GENAI_1002", "healthy-two")
    result = _run(tmp_path, env=None)
    rendered = result.render()
    for check_id in ("B1", "B2", "W1", "W2", "W3", "W4", "W5", "W6", "W7"):
        assert f"[{check_id}]" in rendered, check_id
        assert _by_id(result, check_id).status == OK, check_id
    assert result.blockers == 0 and result.warnings == 0
    assert result.exit_code == 0


def test_no_identities_block_is_skip_not_silence(tmp_path):
    """Сценарий без identities (mock): строки B1/B2 печатаются как SKIP —
    отсутствие строки читалось бы как «не проверяли»."""
    text = _LIVE_YAML.replace(
        """  identities:
    "1001": SK_GENAI_1001
    "1002": SK_GENAI_1002
""",
        "",
    )
    result = _run(tmp_path, env={}, text=text)
    assert _by_id(result, "B1").status == SKIP
    assert _by_id(result, "B2").status == SKIP


def test_w7_names_known_deployments(tmp_path, monkeypatch):
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    unknown = _run(tmp_path, env=None, mongo="ok")
    # 9600/28017 — известная пара: W7 зелёный
    assert _by_id(unknown, "W7").status == OK

    odd = _LIVE_YAML.replace("localhost:9600", "localhost:9601")
    result = _run(tmp_path, env=None, text=odd)
    w7 = _by_id(result, "W7")
    assert w7.status == WARNING
    assert "9601" in w7.text
    assert "9600" in w7.text and "28017" in w7.text  # известные пары названы
    assert "9702" in w7.text and "28182" in w7.text

    batch = _LIVE_YAML.replace("localhost:9600", "localhost:9702").replace(
        "localhost:28017", "localhost:28182")
    assert _by_id(_run(tmp_path, env=None, text=batch), "W7").status == OK


# ------------------------------------------------------------------ PASS_IF 11

def test_real_live_scenario_offline(tmp_path, monkeypatch, capsys):
    """Реальный scenarios/cross_user_bac_live.yaml: подменённый транспорт,
    недоступный Mongo (стенд не поднимаем). Ожидаем предупреждения, не падение;
    правильное предупреждение про Mongo — W4 «задан, но недоступен», НЕ W3."""
    monkeypatch.setenv("SK_GENAI_1001", "live-fake-one")
    monkeypatch.setenv("SK_GENAI_1002", "live-fake-two")
    result = run_preflight(
        _REPO / "scenarios" / "cross_user_bac_live.yaml",
        http_get=_fake_http(healthz=None),  # транспортный отказ
        mongo_probe=_fake_mongo("unreachable"),
        environ=None,
    )
    rendered = result.render()
    print("\n" + rendered)
    w3, w4 = _by_id(result, "W3"), _by_id(result, "W4")
    assert w3.status == OK, "mongo_uri в этом сценарии ЗАДАН — W3 быть не должно"
    assert w4.status == WARNING
    assert "задан, но недоступен" in w4.text
    assert result.blockers == 0
    assert result.exit_code == 0  # предупреждения, не блокеры
    assert "live-fake-one" not in rendered and "live-fake-two" not in rendered
    captured = capsys.readouterr()
    assert "live-fake-one" not in captured.out + captured.err


# ================================================================== карточка S-2
# Возврат карточки S: сила замка. Раскладка обязана РАСХОДИТЬСЯ на верном и
# типичном неверном поведении; нестроковые ключи — блокер, а не KeyError;
# mongo_db без сценария — та же база, что у адаптера; SKIP, когда сравнения
# не было.

NEEDLE2 = "sk-genai-S2-NEEDLE-77F3"

_IDENT_BLOCK = '  identities:\n    "1001": SK_GENAI_1001\n    "1002": SK_GENAI_1002\n'


def test_b2_colliding_pair_is_not_first_two_by_any_order(tmp_path, monkeypatch):
    """PASS_IF 1–2 (S-2): раскладка расходящаяся. Совпавшая пара — (1003,
    1004): она НЕ первые два ни по порядку словаря (вставка 1001, 1002
    раньше), ни по сортировке user_id (1001 < 1002 < 1003 < 1004), ни по
    алфавиту имён переменных (SK_FIRST_A/SK_FIRST_B < SK_LATE_C/SK_LATE_D).
    Под мутацией «сравнивать только первых двух» B2 здесь даёт OK — и этот
    тест краснеет (проверено прогоном мутации, не рассуждением)."""
    text = _LIVE_YAML.replace(
        _IDENT_BLOCK,
        '  identities:\n    "1001": SK_FIRST_A\n    "1002": SK_FIRST_B\n'
        '    "1003": SK_LATE_C\n    "1004": SK_LATE_D\n',
    )
    monkeypatch.setenv("SK_FIRST_A", "value-one")
    monkeypatch.setenv("SK_FIRST_B", "value-two")
    monkeypatch.setenv("SK_LATE_C", "dup-pair-value")
    monkeypatch.setenv("SK_LATE_D", "dup-pair-value")
    result = _run(tmp_path, env=None, text=text)
    b2 = _by_id(result, "B2")
    assert b2.status == BLOCKER
    assert result.exit_code == 1
    assert "1003" in b2.text and "1004" in b2.text
    assert "SK_LATE_C" in b2.text and "SK_LATE_D" in b2.text
    # первые два по всем трём порядкам в блокер не попали
    assert "1001" not in b2.text and "1002" not in b2.text
    assert "SK_FIRST" not in b2.text


def test_nonstring_keys_equal_values_blocker(tmp_path, monkeypatch):
    """PASS_IF 4а (S-2): ключи YAML без кавычек (int), значения совпали —
    B2 БЛОКЕР с обоими user_id и именами, ни одного KeyError."""
    text = _LIVE_YAML.replace(
        _IDENT_BLOCK, '  identities:\n    1001: SK_A\n    1002: SK_B\n'
    )
    monkeypatch.setenv("SK_A", "sk-genai-same")
    monkeypatch.setenv("SK_B", "sk-genai-same")
    result = _run(tmp_path, env=None, text=text)
    b2 = _by_id(result, "B2")
    assert b2.status == BLOCKER
    assert result.exit_code == 1
    assert "1001" in b2.text and "1002" in b2.text
    assert "SK_A" in b2.text and "SK_B" in b2.text


def test_nonstring_keys_unset_var_blocker(tmp_path, monkeypatch):
    """PASS_IF 4б (S-2): нестроковые ключи, переменная не задана — B1 БЛОКЕР
    с именем переменной, не KeyError."""
    text = _LIVE_YAML.replace(
        _IDENT_BLOCK, '  identities:\n    1001: SK_A\n    1002: SK_B\n'
    )
    monkeypatch.delenv("SK_A", raising=False)
    monkeypatch.setenv("SK_B", "value-set")
    result = _run(tmp_path, env=None, text=text)
    b1 = _by_id(result, "B1")
    assert b1.status == BLOCKER
    assert "SK_A" in b1.text and "1001" in b1.text
    assert result.exit_code == 1


def test_nonstring_mixed_quoting_blocker(tmp_path, monkeypatch):
    """PASS_IF 4в (S-2): смешанное закавычивание ("1001" в кавычках, 1002
    без) и совпавшие значения — блокер, не KeyError."""
    text = _LIVE_YAML.replace(
        _IDENT_BLOCK, '  identities:\n    "1001": SK_A\n    1002: SK_B\n'
    )
    monkeypatch.setenv("SK_A", "sk-genai-mixed")
    monkeypatch.setenv("SK_B", "sk-genai-mixed")
    result = _run(tmp_path, env=None, text=text)
    b2 = _by_id(result, "B2")
    assert b2.status == BLOCKER
    assert result.exit_code == 1
    assert "SK_A" in b2.text and "SK_B" in b2.text


def test_s2_needle_never_leaks(tmp_path, monkeypatch, capsys):
    """PASS_IF 5 (S-2): игла (своя, не отработанные sk-genai-PREFLIGHT-… /
    sk-genai-A0NEEDLE-…) не появляется ни в stdout+stderr, ни в текстах
    исключений на ВСЕХ раскладках дефекта 4 — включая нестроковые ключи.
    Исключений нет вовсе: preflight говорит, а не падает."""
    import memnotsafe.preflight as pf
    from memnotsafe.cli import main as cli_main

    monkeypatch.setattr(pf, "_default_http_get", _fake_http())
    monkeypatch.setattr(pf, "_default_mongo", _fake_mongo("ok"))
    unquoted = _LIVE_YAML.replace(
        _IDENT_BLOCK, '  identities:\n    1001: SK_A\n    1002: SK_B\n'
    )
    mixed = _LIVE_YAML.replace(
        _IDENT_BLOCK, '  identities:\n    "1001": SK_A\n    1002: SK_B\n'
    )
    layouts = {
        "nonstring-equal": (unquoted, {"SK_A": NEEDLE2, "SK_B": NEEDLE2}),
        "nonstring-unset": (unquoted, {"SK_B": NEEDLE2}),
        "mixed-equal": (mixed, {"SK_A": NEEDLE2, "SK_B": NEEDLE2}),
    }
    for name, (text, env) in layouts.items():
        for var in ("SK_A", "SK_B"):
            monkeypatch.delenv(var, raising=False)
        for var, val in env.items():
            monkeypatch.setenv(var, val)
        p = tmp_path / f"{name}.yaml"
        p.write_text(text, encoding="utf-8")
        code = cli_main(["preflight", "--scenario", str(p)])
        captured = capsys.readouterr()
        assert NEEDLE2 not in captured.out, name
        assert NEEDLE2 not in captured.err, name
        assert code in (0, 1), name
        assert NEEDLE2 not in _run(tmp_path, env=None, text=text).render(), name


def test_mongo_db_default_follows_adapter(tmp_path, monkeypatch):
    """PASS_IF 6–7 (S-2): mongo_db не задан в сценарии — щуп уходит в ту же
    базу, что возьмёт адаптер. Имя сверяется с умолчанием СИГНАТУРЫ адаптера
    (не литералом в preflight); третий участник — литерал, записанный при
    написании замка: правка умолчания адаптера обязана краснить этот тест,
    чтобы разъезд не прошёл молча."""
    import inspect

    from memnotsafe.adapters.investment_stand import InvestmentStandAdapter

    sig_default = str(
        inspect.signature(
            InvestmentStandAdapter.__init__
        ).parameters["mongo_db"].default
    )
    captured = {}

    def probe(uri, db_name):
        captured["db"] = db_name
        return MongoProbe(state="ok")

    text = _LIVE_YAML.replace("  mongo_db: agent_memory\n", "")
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    result = run_preflight(
        _write(tmp_path, text), http_get=_fake_http(), mongo_probe=probe,
        environ=None,
    )
    assert captured["db"], "в щуп ушло пустое имя базы"
    assert captured["db"] == sig_default, (captured["db"], sig_default)
    # записано при написании замка (PASS_IF 7): менять сознательно вместе с
    # умолчанием адаптера — именно так ловится тихий разъезд
    assert captured["db"] == "agent_memory", captured["db"]
    for check_id in ("W3", "W4", "W6"):
        assert "None" not in _by_id(result, check_id).text, check_id
        assert "<имя не задано>" not in _by_id(result, check_id).text, check_id
    # доступная база с коллекцией — предупреждений от Mongo нет вовсе
    assert _by_id(result, "W3").status == OK
    assert _by_id(result, "W4").status == OK
    assert _by_id(result, "W6").status == OK


def test_preflight_does_not_duplicate_db_literal():
    """PASS_IF 7 (S-2): умолчание адаптера не продублировано литералом в
    preflight — источник только сигнатура адаптера."""
    import inspect

    import memnotsafe.preflight as pf

    from memnotsafe.adapters.investment_stand import InvestmentStandAdapter

    sig_default = str(
        inspect.signature(
            InvestmentStandAdapter.__init__
        ).parameters["mongo_db"].default
    )
    src = Path(pf.__file__).read_text(encoding="utf-8")
    assert sig_default not in src, "умолчание mongo_db продублировано литералом"


def test_b2_skip_when_nothing_to_compare(tmp_path, monkeypatch):
    """PASS_IF 8 (S-2): все переменные пусты — сравнения не было, статус B2
    SKIP (не OK: UNKNOWN ≠ True); B1 при этом БЛОКЕР, exit 1."""
    monkeypatch.delenv("SK_GENAI_1001", raising=False)
    monkeypatch.delenv("SK_GENAI_1002", raising=False)
    result = _run(tmp_path, env=None)
    assert _by_id(result, "B1").status == BLOCKER
    assert _by_id(result, "B2").status == SKIP
    assert "(см. B1)" in _by_id(result, "B2").text
    assert result.exit_code == 1


def test_b2_skip_when_single_principal(tmp_path, monkeypatch):
    """PASS_IF 8 (карточка U): принципал в сценарии ровно один — B2 SKIP, а
    не вакуумное OK; B1 OK, exit 0; строка непустая и объясняет, почему
    сравнения не было. Путь с двумя принципалами не тронут (см. тесты S-2)."""
    text = _LIVE_YAML.replace('    "1002": SK_GENAI_1002\n', "")
    monkeypatch.setenv("SK_GENAI_1001", "single-principal-value")
    result = _run(tmp_path, env=None, text=text)
    b1, b2 = _by_id(result, "B1"), _by_id(result, "B2")
    assert b1.status == OK
    assert b2.status == SKIP
    assert b2.text and "сравнения не было" in b2.text
    assert "один" in b2.text
    assert result.exit_code == 0


# ================================================================== карточка D4
# Топология принципалов: victim-only парсится (инцидент V-2: preflight падал
# KeyError 'attacker' на контроле жертвы), пустой actors — ValueError, B3
# ловит одинаковый user_id при РАЗНЫХ значениях ключей (B2 там зелёный).

_ATTACKER_ONLY_YAML = _LIVE_YAML.replace('  victim: {user_id: "1002"}\n', "")


def test_victim_only_control_parses_and_runs():
    """PASS_IF 1: реальный scenarios/live_clean_control.yaml (victim-only)
    грузится без KeyError: attacker достраивается жертвой; B3 SKIP с названным
    блоком; полный офлайн-preflight не падает, блокеров нет."""
    from memnotsafe.core.config import load_scenario

    scenario = load_scenario(_REPO / "scenarios" / "live_clean_control.yaml")
    assert scenario.victim.user_id == "1002"
    assert scenario.attacker.user_id == "1002"  # достроен загрузчиком

    import os

    old = os.environ.get("SK_GENAI_1002")
    os.environ["SK_GENAI_1002"] = "control-value"
    try:
        result = run_preflight(
            _REPO / "scenarios" / "live_clean_control.yaml",
            http_get=_fake_http(),
            mongo_probe=_fake_mongo("ok"),
            environ=None,
        )
    finally:
        if old is None:
            os.environ.pop("SK_GENAI_1002", None)
        else:
            os.environ["SK_GENAI_1002"] = old
    b3 = _by_id(result, "B3")
    assert b3.status == SKIP
    assert "victim" in b3.text and "1002" in b3.text
    assert result.blockers == 0
    assert result.exit_code == 0


def test_attacker_only_behavior_unchanged(tmp_path, monkeypatch):
    """PASS_IF 2: attacker-only — прежняя семантика victim==attacker; B3 SKIP,
    назван attacker; exit не меняется."""
    from memnotsafe.core.config import load_scenario

    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    scenario = load_scenario(_write(tmp_path, _ATTACKER_ONLY_YAML))
    assert scenario.attacker.user_id == "1001"
    assert scenario.victim.user_id == "1001"  # прежнее умолчание single-user
    result = _run(tmp_path, env=None, text=_ATTACKER_ONLY_YAML)
    b3 = _by_id(result, "B3")
    assert b3.status == SKIP
    assert "attacker" in b3.text


def test_no_actors_at_all_is_valueerror_not_keyerror(tmp_path):
    """PASS_IF 3: ни attacker, ни victim — ValueError с понятным текстом
    (названы оба блока), не KeyError."""
    from memnotsafe.core.config import load_scenario

    text = _LIVE_YAML.replace(
        '  attacker: {user_id: "1001"}\n  victim: {user_id: "1002"}\n', ""
    )
    with pytest.raises(ValueError, match="attacker"):
        load_scenario(_write(tmp_path, text))


def test_d4_same_actor_user_id_different_keys_is_blocker(tmp_path, monkeypatch):
    """PASS_IF 4 (мутация D4): оба блока объявлены явно, user_id совпали,
    значения ключей РАЗНЫЕ — B2 зелёный (своего не видит), блокирует B3;
    exit 1; значения ключей наружу не выходят."""
    monkeypatch.setenv("SK_GENAI_1001", "d4-value-one")
    monkeypatch.setenv("SK_GENAI_1002", "d4-value-two")
    dup = _LIVE_YAML.replace('  victim: {user_id: "1002"}', '  victim: {user_id: "1001"}')
    result = _run(tmp_path, env=None, text=dup)
    b2, b3 = _by_id(result, "B2"), _by_id(result, "B3")
    assert b2.status == OK  # ключи различны — замок значений слеп к топологии
    assert b3.status == BLOCKER
    assert result.exit_code == 1
    assert "1001" in b3.text and "кросс-юзер" in b3.text
    rendered = result.render()
    assert "d4-value-one" not in rendered and "d4-value-two" not in rendered


def test_b3_ok_when_both_declared_distinct(tmp_path, monkeypatch):
    """Оба блока объявлены явно и user_id различны — B3 OK; здоровый прогон
    остаётся exit 0 (новая проверка не портит зелёную раскладку)."""
    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    result = _run(tmp_path, env=None)
    b3 = _by_id(result, "B3")
    assert b3.status == OK
    assert "1001" in b3.text and "1002" in b3.text
    assert result.exit_code == 0


# =========================================================== карточка B2-partial
# Непустых значений меньше двух — пары не существовало, и вакуумное OK лгало
# о сравнении, которого не было (прецедент SKIP-вместо-вакуума — карточка U
# для единственного принципала). Коллизия реальных значений приоритетнее.

_THREE_IDENT_YAML = _LIVE_YAML.replace(
    '    "1002": SK_GENAI_1002\n',
    '    "1002": SK_GENAI_1002\n    "1003": SK_GENAI_1003\n',
)


def test_b2_skip_two_declared_one_populated(tmp_path, monkeypatch):
    """PASS_IF 1: 2 объявлено / 1 непустое → B1 BLOCKER, B2 SKIP, exit 1."""
    monkeypatch.delenv("SK_GENAI_1001", raising=False)
    monkeypatch.setenv("SK_GENAI_1002", "only-populated")
    result = _run(tmp_path, env=None)
    assert _by_id(result, "B1").status == BLOCKER
    b2 = _by_id(result, "B2")
    assert b2.status == SKIP
    assert "меньше двух" in b2.text
    assert result.exit_code == 1


def test_b2_skip_three_declared_one_populated(tmp_path, monkeypatch):
    """PASS_IF 2: 3 объявлено / 1 непустое → SKIP, а не «все 1 значений различны»."""
    monkeypatch.delenv("SK_GENAI_1002", raising=False)
    monkeypatch.delenv("SK_GENAI_1003", raising=False)
    monkeypatch.setenv("SK_GENAI_1001", "single-value")
    result = _run(tmp_path, env=None, text=_THREE_IDENT_YAML)
    b2 = _by_id(result, "B2")
    assert b2.status == SKIP
    assert "1 из 3" in b2.text


def test_b2_ok_three_declared_two_populated_distinct(tmp_path, monkeypatch):
    """PASS_IF 3: 3 / 2 различных непустых → B2 OK честно; B1 независимо
    BLOCKER за третье отсутствующее (значения не влияют на B2)."""
    monkeypatch.setenv("SK_GENAI_1001", "value-one")
    monkeypatch.setenv("SK_GENAI_1002", "value-two")
    monkeypatch.delenv("SK_GENAI_1003", raising=False)
    result = _run(tmp_path, env=None, text=_THREE_IDENT_YAML)
    assert _by_id(result, "B2").status == OK
    assert _by_id(result, "B1").status == BLOCKER
    assert "SK_GENAI_1003" in _by_id(result, "B1").text


def test_b2_blocker_three_declared_two_populated_equal(tmp_path, monkeypatch):
    """PASS_IF 4: 3 / 2 совпавших → B2 BLOCKER: реальная коллизия приоритетнее
    подсчёта непустых; непопавший третий принципал в блокере не назван."""
    monkeypatch.setenv("SK_GENAI_1001", "dup-partial")
    monkeypatch.setenv("SK_GENAI_1002", "dup-partial")
    monkeypatch.delenv("SK_GENAI_1003", raising=False)
    result = _run(tmp_path, env=None, text=_THREE_IDENT_YAML)
    b2 = _by_id(result, "B2")
    assert b2.status == BLOCKER
    assert result.exit_code == 1
    assert "1001" in b2.text and "1002" in b2.text and "1003" not in b2.text


def test_b2_partial_values_never_leak(tmp_path, monkeypatch):
    """PASS_IF: значения ключей не появляются в выводе на частичной раскладке."""
    monkeypatch.setenv("SK_GENAI_1001", "b2-partial-needle-one")
    result = _run(tmp_path, env=None, text=_THREE_IDENT_YAML)  # 1002/1003 не заданы
    assert "b2-partial-needle-one" not in result.render()
    assert _by_id(result, "B2").status == SKIP
