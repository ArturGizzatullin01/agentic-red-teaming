"""src/memnotsafe/preflight.py — сказать ДО живого прогона, что будет измерено
(карточка S).

Preflight — отдельная подкоманда, только чтение: ни одного запроса, меняющего
состояние (HTTP — исключительно GET; Mongo — только чтение метаданных).
Она НЕ встраивается в run/campaign и не выносит вердикт «прогон делать
нельзя»: ненулевой код возврата при блокерах — сигнал, решение за владельцем.

Главный замок — B2: ключи разных принципалов обязаны быть различны. Если обе
переменные окружения держат один ключ, attacker и victim — один принципал,
кросс-юзер границы нет, а cross_user_bac покажет ЛОЖНЫЙ успех. По артефакту
прогона это неотличимо от настоящей находки — ловить надо до прогона.

Секретная гигиена (прецедент — core/config.py:145): значение ключа в сообщение
не попадает никогда — только имя переменной и user_id. Ни целиком, ни
фрагментом, ни длиной, ни хешем. `.env` не открывается и не ищется: значения
берутся только из окружения процесса, как и у адаптера (os.environ.get).

UNKNOWN ≠ False держится и здесь: W5 (нет pymongo) — «проверить нельзя», а не
«недоступен»; W6 (нет коллекции) называет ОБЕ причины и не выбирает между
ними; пропуск проверки печатается явно — отсутствие строки читалось бы как
«не проверяли».
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx

HEALTHZ_PATH = "/healthz"
SAMPLING_PATH = "/debug/sampling"
RETRIEVAL_COLLECTION = "memory_retrieval_log"

_HTTP_TIMEOUT_S = 5.0
_MONGO_TIMEOUT_MS = 1500

# Два известных развёртывания стенда (карточка N-2): сводить их не надо,
# решение владельца. Пара портов API↔Mongo, отличная от обеих, — почти
# наверняка опечатка в сценарии или третий незнакомый стенд: предупредить,
# назвав известные пары.
KNOWN_DEPLOYMENTS: tuple[tuple[str, str, str], ...] = (
    ("9600", "28017", "основной стек"),
    ("9702", "28182", "батч-стек (отдельное развёртывание)"),
)

# Статусы проверки. SKIP — проверка неприменима в этой раскладке (например,
# W4 без заданного mongo_uri): строка печатается, в итог не идёт.
OK = "OK"
BLOCKER = "БЛОКЕР"
WARNING = "ПРЕДУПРЕЖДЕНИЕ"
SKIP = "не проверялось"

# Следствие отсутствия канала памяти — ДОСЛОВНО из таблицы «Инвариант
# capabilities → тристейт» specs/001-live-target-reproduction/contracts/
# adapter-contract.md (строка «mongo_uri нет»). Не сочинять свою формулировку.
_CONTRACT_CONSEQUENCE = "write/persistence UNKNOWN → композит недостижим"


@dataclass
class HttpReply:
    """Ответ подменяемого транспорта: status_code=None — транспортный отказ."""

    status_code: int | None
    error: str | None = None


@dataclass
class MongoProbe:
    """Итог щупа Mongo: состояние, достаточное для W3–W6, без лишних данных."""

    state: str  # pymongo-missing | unreachable | no-db | no-collection | ok


@dataclass
class Check:
    check_id: str
    title: str
    status: str
    text: str


@dataclass
class PreflightResult:
    scenario_id: str
    scenario_path: str
    checks: list[Check] = field(default_factory=list)

    @property
    def blockers(self) -> int:
        return sum(1 for c in self.checks if c.status == BLOCKER)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == WARNING)

    @property
    def exit_code(self) -> int:
        return 1 if self.blockers else 0

    def render(self) -> str:
        out = [f"PREFLIGHT: {self.scenario_id}", f"Сценарий: {self.scenario_path}", ""]
        for c in self.checks:
            out.append(f"[{c.check_id}] {c.title}: {c.status} — {c.text}")
        out.append("")
        out.append(f"Итог: блокеров {self.blockers}, предупреждений {self.warnings}.")
        return "\n".join(out)


async def _default_http_get(url: str) -> HttpReply:
    """Живой транспорт (в тестах подменяется). Отказ сжимается в имя типа
    исключения — текст не нужен: URL секретов не несёт, а сообщение о
    недоступности не должно зависеть от посторонних деталей."""
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
            resp = await client.get(url)
            return HttpReply(status_code=resp.status_code)
    except Exception as exc:  # noqa: BLE001 — транспортный отказ — тоже ответ
        return HttpReply(status_code=None, error=type(exc).__name__)


def _adapter_mongo_db_default() -> str:
    """Имя базы, которое возьмёт адаптер при отсутствии mongo_db в сценарии:
    значение по умолчанию параметра — часть сигнатуры InvestmentStandAdapter,
    берём из самого адаптера. Литералом не дублировать: разъедется тихо при
    первой же правке адаптера (замок — тест карточки S-2, PASS_IF 7)."""
    import inspect

    from memnotsafe.adapters.investment_stand import InvestmentStandAdapter

    default = inspect.signature(
        InvestmentStandAdapter.__init__
    ).parameters["mongo_db"].default
    return str(default)


def _default_mongo(uri: str, db_name: str) -> MongoProbe:
    """Живой щуп Mongo (в тестах подменяется). pymongo — опциональная
    зависимость с ленивым импортом (как у адаптера): её отсутствие —
    UNKNOWN «проверить нельзя», а не «недоступен»."""
    try:
        import pymongo  # опциональная зависимость — только здесь
    except ImportError:
        return MongoProbe(state="pymongo-missing")
    try:
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=_MONGO_TIMEOUT_MS)
        try:
            if db_name not in client.list_database_names():
                return MongoProbe(state="no-db")
            colls = set(client[db_name].list_collection_names())
        finally:
            client.close()
    except Exception:  # noqa: BLE001 — нет доступа/таймаут/нет службы
        return MongoProbe(state="unreachable")
    if RETRIEVAL_COLLECTION not in colls:
        return MongoProbe(state="no-collection")
    return MongoProbe(state="ok")


def _identity_checks(identities, environ) -> list[Check]:
    """B1 (заданы и непусты) и B2 (попарно различны). B2 — попарное правило:
    совпавшая группа называется целиком (user_id + имена переменных) и не
    затрагивает остальных принципалов. Значения наружу не выходят.

    Ключи YAML нормализуются в str ДО всего: незакавыченный `1001:` парсится
    в int, и сообщения обязаны строиться по тому же представлению, по которому
    идёт сравнение, — иначе preflight падает KeyError ровно в тех двух
    случаях, когда ему есть что сказать (S-2, дефект 2)."""
    identities = {str(uid): str(env) for uid, env in identities.items()}
    if not identities:
        return [
            Check("B1", "Переменные identity заданы и непусты", SKIP,
                  "в сценарии нет target.extra.identities — проверять нечего"),
            Check("B2", "Значения identity попарно различны", SKIP,
                  "в сценарии нет target.extra.identities — проверять нечего"),
        ]
    values: dict[str, str | None] = {}
    for user_id, env_name in identities.items():
        raw = environ.get(env_name)
        values[user_id] = raw if raw else None
    missing = sorted(uid for uid, v in values.items() if v is None)
    b1 = Check("B1", "Переменные identity заданы и непусты",
               BLOCKER if missing else OK,
               "; ".join(
                   f"user_id {uid}: переменная {identities[uid]} не задана или пуста"
                   for uid in missing
               ) if missing else
               f"все {len(values)} переменных заданы и непусты")
    # Группировка по значению: каждая совпавшая группа → свой блокер.
    # Внутренний словарь наружу не выходит — только имена и user_id.
    groups: dict[str, list[str]] = {}
    for uid, v in values.items():
        if v is not None:
            groups.setdefault(v, []).append(uid)
    collisions = sorted(sorted(uids) for uids in groups.values() if len(uids) > 1)
    if len(identities) < 2:
        # Карточка U, часть B: принципал в сценарии один — пары для сравнения
        # не существует ВООБЩЕ, и вакуумное OK лгало бы о проверке, которой
        # не было (из 10 live-сценариев 8 объявляют ровно одну identity).
        # Путь с двумя и более принципалами не тронут ни поведением, ни
        # текстом — включая случай «одна из двух переменных пуста» (там
        # честный блокер B1 уже сказал своё).
        b2 = Check("B2", "Значения identity попарно различны", SKIP,
                   f"принципал в сценарии один ({len(identities)}) — пары "
                   "для сравнения не существует, сравнения не было")
    elif not groups:
        # Сравнения не было вовсе: статус — SKIP, а не OK — UNKNOWN ≠ True по
        # той же причине, что UNKNOWN ≠ False (S-2, дефект 4).
        b2 = Check("B2", "Значения identity попарно различны", SKIP,
                   "нет ни одного непустого значения (см. B1)")
    elif collisions:
        parts = []
        for uids in collisions:
            named = ", ".join(f"user_id {uid} ({identities[uid]})" for uid in uids)
            parts.append(f"{named} указывают на одно и то же значение")
        b2 = Check("B2", "Значения identity попарно различны", BLOCKER,
                   "; ".join(parts) + " — кросс-юзер границы нет, атака "
                   "покажет ложный успех")
    else:
        b2 = Check("B2", "Значения identity попарно различны", OK,
                   f"все {len(groups)} значений попарно различны")
    return [b1, b2]


def _http_checks(base_url: str | None, http_get) -> list[Check]:
    """W1 (/healthz) и W2 (/debug/sampling). GET — единственный метод.
    Мёртвый стенд — БЛОКЕР, а не предупреждение (карточка D7-A): прогон по
    недостижимому или неготовому стенду гарантированно упадёт на первом же
    запросе и потратит живое окно. При транспортном отказе /healthz второй
    запрос не делается: хост всё равно недостижим, и W2 печатается как SKIP,
    а не «не проверяли молча». Автоповышение затронуло ТОЛЬКО W1: остальные
    W — телеметрические дыры — остаются WARNING/SKIP до отдельного решения."""
    if not base_url:
        return [
            Check("W1", f"GET {HEALTHZ_PATH}", SKIP, "base_url не задан"),
            Check("W2", f"GET {SAMPLING_PATH}", SKIP, "base_url не задан"),
        ]
    root = base_url.rstrip("/")

    async def _all() -> list[Check]:
        healthz = await http_get(root + HEALTHZ_PATH)
        if healthz.status_code == 200:
            w1 = Check("W1", f"GET {HEALTHZ_PATH}", OK,
                       "HTTP 200 — стенд достижим")
        elif healthz.status_code is None:
            w1 = Check("W1", f"GET {HEALTHZ_PATH}", BLOCKER,
                       f"транспортный отказ ({healthz.error or 'без деталей'}) — "
                       "стенд недостижим, прогон упадёт на первом же запросе")
        else:
            w1 = Check("W1", f"GET {HEALTHZ_PATH}", BLOCKER,
                       f"HTTP {healthz.status_code} — стенд отвечает, но не готов "
                       "(healthz не 200)")
        if healthz.status_code is None:
            return [w1, Check("W2", f"GET {SAMPLING_PATH}", SKIP,
                              "стенд недостижим (см. W1) — запрос не делался")]
        sampling = await http_get(root + SAMPLING_PATH)
        if sampling.status_code == 200:
            w2 = Check("W2", f"GET {SAMPLING_PATH}", OK,
                       "HTTP 200 — наблюдаемость сэмплинга на месте")
        elif sampling.status_code == 404:
            w2 = Check("W2", f"GET {SAMPLING_PATH}", WARNING,
                       "HTTP 404 — стенд старее карточки P: target_sampling "
                       "в артефакте прогона выйдет unavailable")
        elif sampling.status_code is None:
            w2 = Check("W2", f"GET {SAMPLING_PATH}", WARNING,
                       f"транспортный отказ ({sampling.error or 'без деталей'}) — "
                       "target_sampling в артефакте прогона выйдет unavailable")
        else:
            w2 = Check("W2", f"GET {SAMPLING_PATH}", WARNING,
                       f"HTTP {sampling.status_code} — target_sampling в "
                       "артефакте прогона выйдет unavailable")
        return [w1, w2]

    return asyncio.run(_all())


def _mongo_checks(mongo_uri, mongo_db, mongo_probe) -> list[Check]:
    """W3 (mongo_uri не задан), W4 (недоступен/нет базы), W5 (pymongo),
    W6 (коллекция журнала извлечения)."""
    if not mongo_uri:
        return [
            Check("W3", "mongo_uri задан", WARNING,
                  "mongo_uri в сценарии не задан — снимок памяти недоступен; "
                  f"следствие из контракта: {_CONTRACT_CONSEQUENCE}"),
            Check("W4", "Mongo доступен, база существует", SKIP,
                  "mongo_uri не задан (см. W3)"),
            Check("W5", "pymongo установлен", SKIP,
                  "канал памяти не сконфигурирован — импорт не проверялся"),
            Check("W6", f"Коллекция {RETRIEVAL_COLLECTION}", SKIP,
                  "mongo_uri не задан (см. W3)"),
        ]
    w3 = Check("W3", "mongo_uri задан", OK,
               f"задан; база: {mongo_db}")
    probe = mongo_probe(mongo_uri, mongo_db or "")
    if probe.state == "pymongo-missing":
        return [w3,
                Check("W4", "Mongo доступен, база существует", SKIP,
                      "проверить нельзя (см. W5)"),
                Check("W5", "pymongo установлен", WARNING,
                      "pymongo не установлен — канал памяти проверить нельзя: "
                      "это UNKNOWN, а не «Mongo недоступен»"),
                Check("W6", f"Коллекция {RETRIEVAL_COLLECTION}", SKIP,
                      "проверить нельзя (см. W5)")]
    if probe.state == "unreachable":
        return [w3,
                Check("W4", "Mongo доступен, база существует", WARNING,
                      "mongo_uri задан, но недоступен; следствие из контракта: "
                      f"{_CONTRACT_CONSEQUENCE}"),
                Check("W5", "pymongo установлен", OK, "pymongo установлен"),
                Check("W6", f"Коллекция {RETRIEVAL_COLLECTION}", SKIP,
                      "Mongo недоступен (см. W4)")]
    if probe.state == "no-db":
        return [w3,
                Check("W4", "Mongo доступен, база существует", WARNING,
                      f"службы нет или базы {mongo_db} в ней нет; следствие из "
                      f"контракта: {_CONTRACT_CONSEQUENCE}"),
                Check("W5", "pymongo установлен", OK, "pymongo установлен"),
                Check("W6", f"Коллекция {RETRIEVAL_COLLECTION}", SKIP,
                      f"базы {mongo_db} нет (см. W4)")]
    w4 = Check("W4", "Mongo доступен, база существует", OK,
               f"доступен, база {mongo_db} существует")
    w5 = Check("W5", "pymongo установлен", OK, "pymongo установлен")
    if probe.state == "no-collection":
        w6 = Check("W6", f"Коллекция {RETRIEVAL_COLLECTION}", WARNING,
                   f"коллекции {RETRIEVAL_COLLECTION} в базе {mongo_db} нет. "
                   "Это одно из двух, и preflight их НЕ различает: (а) стенд "
                   "свежий — сессий ещё не было, код журнала на месте; "
                   "(б) стенд старее карточки I — журнала не будет и после "
                   "сессий, retrieval останется UNKNOWN весь прогон")
    else:
        w6 = Check("W6", f"Коллекция {RETRIEVAL_COLLECTION}", OK,
                   f"есть в базе {mongo_db} — стенд писал её хотя бы раз, "
                   "код карточки I развёрнут")
    return [w3, w4, w5, w6]


def _api_port(base_url: str) -> str | None:
    try:
        parsed = urlparse(base_url)
    except ValueError:
        return None
    if parsed.port is not None:
        return str(parsed.port)
    return "80" if parsed.scheme == "http" else ("443" if parsed.scheme == "https" else None)


def _mongo_port(uri: str) -> str | None:
    """Порт из mongodb[-+srv]://… — наружу только порт, сам URI не печатается
    (в нём могут быть кредиталы)."""
    rest = uri.split("://", 1)[-1]
    hostpart = rest.split("/", 1)[0].rsplit("@", 1)[-1]
    if hostpart.startswith("["):  # IPv6-литерал [::1]:port
        bracket = hostpart.split("]", 1)
        return (bracket[1][1:] or None) if len(bracket) == 2 and ":" in bracket[1] else None
    if ":" in hostpart:
        return hostpart.rsplit(":", 1)[-1] or None
    return None


def _deployment_check(base_url, mongo_uri) -> Check:
    """W7: пара портов — известное развёртывание (N-2: развёртываний два,
    решение владельца не сводить их)."""
    if not (base_url and mongo_uri):
        return Check("W7", "Пара портов API ↔ Mongo — известное развёртывание",
                     SKIP, "пара неполная (нет base_url или mongo_uri)")
    api_port, mongo_port = _api_port(base_url), _mongo_port(mongo_uri)
    if api_port is None or mongo_port is None:
        return Check("W7", "Пара портов API ↔ Mongo — известное развёртывание",
                     WARNING, "не удалось определить порт (base_url или "
                     "mongo_uri нестандартного вида) — сверь развёртывание "
                     "вручную")
    known = "; ".join(f"API {a} ↔ Mongo {m} — {label}" for a, m, label in KNOWN_DEPLOYMENTS)
    for a, m, _label in KNOWN_DEPLOYMENTS:
        if api_port == a and mongo_port == m:
            return Check("W7", "Пара портов API ↔ Mongo — известное развёртывание",
                         OK, f"API {api_port} ↔ Mongo {mongo_port} — совпадает")
    return Check("W7", "Пара портов API ↔ Mongo — известное развёртывание",
                 WARNING, f"пара API {api_port} ↔ Mongo {mongo_port} не совпадает "
                 f"ни с одним известным развёртыванием. Известные: {known}")


def run_preflight(scenario_path: str | Path, *, http_get=None, mongo_probe=None,
                  environ=None) -> PreflightResult:
    """Все проверки по сценарию. Только чтение; значения ключей наружу не
    выходят. http_get/mongo_probe/environ — слоты для офлайн-тестов (по
    умолчанию — живые httpx/pymongo и os.environ процесса)."""
    from memnotsafe.core.config import load_scenario

    scenario = load_scenario(str(scenario_path))
    result = PreflightResult(scenario_id=scenario.id, scenario_path=str(scenario_path))
    result.checks.extend(_identity_checks(
        scenario.target.extra.get("identities") or {},
        os.environ if environ is None else environ,
    ))
    result.checks.extend(_http_checks(
        scenario.target.base_url, http_get or _default_http_get))
    result.checks.extend(_mongo_checks(
        scenario.target.extra.get("mongo_uri"),
        # щупаем ту же базу, которую возьмёт адаптер: без mongo_db в сценарии
        # адаптер сидит на умолчании своей сигнатуры — preflight не имеет
        # права разойтись с ним (S-2, дефект 3)
        scenario.target.extra.get("mongo_db") or _adapter_mongo_db_default(),
        mongo_probe or _default_mongo,
    ))
    result.checks.append(_deployment_check(
        scenario.target.base_url, scenario.target.extra.get("mongo_uri")))
    return result


def preflight_cli(scenario_path: str) -> int:
    """Точка входа подкоманды: напечатать все проверки, вернуть код (1 —
    есть блокеры). Вердикт «делать прогон или нет» остаётся за владельцем."""
    result = run_preflight(scenario_path)
    print(result.render())
    return result.exit_code
