"""src/memnotsafe/adapters/http_endpoint.py — CARD-T1: generic HTTP target
adapter (tier-1, линия Влада): «пользователь даёт URL и ключ своего
LLM-эндпоинта в YAML → одна команда → отчёт», уровень простоты promptfoo.

EXT-A (поток EXT-OPERATOR, карта 1/4): адаптер умеет строиться из
версионированного target-профиля (adapters/profile.py). Профиль декларативно
задаёт транспорт (путь/mapping полей запроса и ответа), identity (как цель
различает принципалов), сессию (native id в запросе или локальная история +
финализация закрытием) и заявленную наблюдаемость. Профиль — строгий: опечатка
в ключе падает ДО запроса, границу хоста проверяем ДО чтения ключа (G1), extra
не смеет перекрыть model/messages (G2), наблюдаемость чёрного ящика честно
нулевая (заявка канала → отказ). БЕЗ профиля адаптер работает ровно как раньше
(регресс: bb-сценарии с плоскими ключами target не меняются).

Отличие от adapters/openai.py (черновик без карточки): ключ ТОЛЬКО из env —
отсутствие переменной = ValueError при создании (паттерн langfuse_sink
P11-3; литерал ключа в YAML/сценарии/параметрах невозможен по построению —
конфиг несёт только ИМЯ переменной api_key_env); история сессий живёт В
АДАПТЕРЕ (эндпоинт stateless — это и есть семантика сессии tier-1);
reset/settle деградируют ЧЕСТНО, наблюдаемость не выдумывается.

Честные границы (ноль выдуманной наблюдаемости, UNKNOWN≠False):
  - get_trace/snapshot/snapshot_user = None — каналы не наблюдаемы в tier-1;
    оракулы обязаны уходить в UNKNOWN (capabilities все False);
  - send() НЕ синтезирует call/result из текста ответа (G4): чёрный ящик не
    порождает жёсткой телеметрии, adoption ловится citation-путём по тексту
    (мягкое signature_match), а не выдуманным tool_result без detail.channel;
  - wait_until_persistent → SettleResult.unavailable с именем сигнала;
  - reset_state: внешнего сброса у произвольного HTTP-таргета НЕ существует —
    reset_available=False навсегда; очищается только ЛОКАЛЬНАЯ история адаптера;
    изоляцию прогонов держат свежие session_id, а не «сброс». Загрязнение между
    попытками выявляется свежими session_id + маркерами, не внешним reset;
  - сеть/4xx/5xx → исключение транспорта без ретраев.

Таймаут конечен и ограничен сверху 30 с (значение больше — громкий
ValueError конфигурации, не молчаливый clamp).
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx

from memnotsafe.adapters.base import Capabilities, ProbeResult, SendResult, SettleResult, TargetAdapter
from memnotsafe.adapters.profile import ProfileError, TargetProfile

MAX_TIMEOUT_S = 30.0
DEFAULT_API_KEY_ENV = "MEMNOTSAFE_TARGET_API_KEY"
DEFAULT_CHAT_PATH = "/v1/chat/completions"


class HttpEndpointAdapter(TargetAdapter):
    """OpenAI-совместимая chat-ручка как чёрный ящик tier-1 (goal-driven arch:
    ручка заказчика → контракт TargetAdapter без доступа к памяти цели)."""

    def __init__(
        self,
        base_url: str,
        *,
        model_name: str = "target-agent",
        api_key_env: str = DEFAULT_API_KEY_ENV,
        chat_path: str = DEFAULT_CHAT_PATH,
        timeout_s: float = MAX_TIMEOUT_S,
        request_extra_fields: dict[str, Any] | None = None,
        profile: TargetProfile | None = None,
        # `**_ignored` живёт ТОЛЬКО на legacy-пути (без профиля): регресс
        # bb-сценариев с плоскими ключами target побайтово прежний. На пути
        # профиля посторонних kwarg нет — конфиг строг по построению (карта §6).
        **_ignored: Any,
    ) -> None:
        if not base_url:
            raise ValueError(
                "HttpEndpointAdapter: base_url обязателен (target.base_url в YAML или --target)"
            )
        if float(timeout_s) > MAX_TIMEOUT_S:
            raise ValueError(
                f"HttpEndpointAdapter: timeout_s={timeout_s} больше допустимых {MAX_TIMEOUT_S} с — "
                "таймаут конечен и ограничен, долгие зависания не настраиваются"
            )

        self._profile = profile
        self.model_name = model_name
        self.request_extra_fields = request_extra_fields or {}
        # История и user_id по сессиям — состояние АДАПТЕРА (эндпоинт stateless).
        self._sessions: dict[str, list[dict[str, str]]] = {}
        self._session_users: dict[str, str] = {}
        # Наблюдаемость чёрного ящика: ноль каналов (оракулы → UNKNOWN).
        self.capabilities = Capabilities(
            trace=False, memory_snapshot=False, tool_calls=False, retrieval=False,
        )
        # Внешнего сброса у HTTP-таргета не существует — честная деградация.
        self.reset_available = False

        if profile is not None:
            base_url, headers = self._init_from_profile(profile, base_url)
        else:
            self.chat_path = chat_path
            self.api_key_env = api_key_env
            api_key = os.environ.get(api_key_env, "").strip()
            if not api_key:
                raise ValueError(
                    f"HttpEndpointAdapter: ключ эндпоинта не найден в env {api_key_env!r} — "
                    "ключ читается ТОЛЬКО из окружения (литерал в YAML/сценарии запрещён §3.8); "
                    "положите значение в локальный .env/окружение вне репо"
                )
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=float(timeout_s),
            headers=headers,
        )

    # ------------------------------------------------- инициализация из профиля

    def _init_from_profile(self, profile: TargetProfile, base_url: str) -> tuple[str, dict[str, str]]:
        """Разбор профиля в поля адаптера. Порядок важен: граница хоста (G1)
        проверяется ДО чтения любого ключа; честная трансляция наблюдаемости —
        заявленный канал у tier-1 отвергается (нет снапшота/трассы/телеметрии/
        внешнего reset)."""
        # G1: чужой/небезопасный хост отвергается до чтения ключа и до запроса.
        profile.check_host_boundary(base_url)

        obs = profile.observation
        claimed = [
            name
            for name, val in (
                ("memory_snapshot", obs.memory_snapshot),
                ("retrieval_trace", obs.retrieval_trace),
                ("tool_telemetry", obs.tool_telemetry),
                ("reset", obs.reset),
            )
            if val
        ]
        if claimed:
            raise ProfileError(
                f"http_endpoint tier-1 не имеет канала наблюдения, а профиль заявляет {claimed}: "
                "честно транслировать нельзя (нет снапшота памяти / трассы / телеметрии tool / "
                "внешнего reset). Уберите флаги или подключите адаптер с реальным каналом."
            )

        self.chat_path = profile.transport.chat_path
        headers: dict[str, str] = {"Content-Type": "application/json"}

        # Сервисная авторизация к самой ручке (bearer_env) — читается сразу;
        # per-principal Authorization (identity=bearer_env) ставится на каждый send.
        if profile.auth.scheme == "bearer_env":
            self.api_key_env = profile.auth.api_key_env
            api_key = os.environ.get(profile.auth.api_key_env or "", "").strip()
            if not api_key:
                raise ValueError(
                    f"HttpEndpointAdapter: сервисный ключ ручки не найден в env "
                    f"{profile.auth.api_key_env!r} — ключ читается ТОЛЬКО из окружения "
                    "(имя переменной в профиле, значение вне репо)"
                )
            headers["Authorization"] = f"Bearer {api_key}"
        else:
            self.api_key_env = None
        return base_url, headers

    # ---------------------------------------------------------------- сессии

    async def new_session(self, user_id: str) -> str:
        session_id = f"http-{user_id}-{uuid.uuid4().hex[:8]}"
        self._sessions[session_id] = []
        self._session_users[session_id] = user_id
        return session_id

    async def send(self, session_id: str, message: str) -> SendResult:
        history = self._sessions.get(session_id)
        if history is None:
            raise ValueError(
                f"HttpEndpointAdapter: неизвестная/закрытая сессия {session_id!r} — "
                "история сессий живёт в адаптере и удаляется при close/reset"
            )
        history.append({"role": "user", "content": message})
        if self._profile is not None:
            body, headers = self._profile_request(session_id, history)
            resp = await self._client.post(self.chat_path, json=body, headers=headers or None)
        else:
            body = {
                "model": self.model_name,
                "messages": list(history),
                **self.request_extra_fields,
            }
            resp = await self._client.post(self.chat_path, json=body)
        resp.raise_for_status()  # 4xx/5xx → транспортная ошибка, без ретраев
        raw = resp.json()
        content = self._extract_content(raw)
        history.append({"role": "assistant", "content": str(content)})
        # G4: чёрный ящик не синтезирует call/result из текста — events пусты,
        # жёсткой телеметрии нет; принятие судит citation-путь по тексту (мягко).
        return SendResult(content=str(content), events=[], raw=raw)

    def _profile_request(self, session_id: str, history: list[dict[str, str]]) -> tuple[dict[str, Any], dict[str, str]]:
        """Тело и заголовки запроса по профилю. Контрактные поля ставятся ПОСЛЕ
        extra_fields (G2: extra не перекрывает model/messages/identity/session —
        и на уровне разбора это уже запрещено, здесь — второй рубеж)."""
        assert self._profile is not None
        prof = self._profile
        req = prof.transport.request
        user_id = self._session_users.get(session_id, "")

        body: dict[str, Any] = dict(prof.transport.extra_fields)  # extra — фундамент
        body[req.model_field] = self.model_name
        body[req.messages_field] = [
            {req.role_key: m["role"], req.content_key: m["content"]} for m in history
        ]

        headers: dict[str, str] = {}
        ident = prof.identity
        if ident.scheme == "bearer_env":
            principal = ident.principal_for(user_id)
            if principal is None or not principal.env:
                raise ValueError(
                    f"HttpEndpointAdapter: для user_id={user_id!r} нет принципала с env в профиле "
                    f"(identity.scheme=bearer_env). Известные: {[p.user_id for p in ident.principals]}"
                )
            key = os.environ.get(principal.env, "").strip()
            if not key:
                raise ValueError(
                    f"HttpEndpointAdapter: переменная окружения {principal.env!r} пуста — "
                    f"нет ключа для принципала subject={principal.subject!r}"
                )
            headers["Authorization"] = f"Bearer {key}"
        elif ident.scheme == "request_header":
            principal = ident.principal_for(user_id)
            headers[ident.header] = (principal.value if principal and principal.value else user_id)
        elif ident.scheme == "request_field":
            principal = ident.principal_for(user_id)
            body[ident.field_name] = (principal.value if principal and principal.value else user_id)
        # scheme native_session/none: идентичность несёт сессия либо не выражается.

        if prof.session.mode == "native" and prof.session.native_field:
            body[prof.session.native_field] = session_id

        return body, headers

    def _extract_content(self, raw: Any) -> str:
        """Достаёт текст ответа. По профилю — заданным content_path; без профиля
        — OpenAI-путём choices[0].message.content."""
        path: tuple[Any, ...]
        if self._profile is not None:
            path = self._profile.transport.content_path
        else:
            path = ("choices", 0, "message", "content")
        node: Any = raw
        try:
            for step in path:
                node = node[step]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(
                f"HttpEndpointAdapter: ответ не соответствует content_path {list(path)} "
                f"({type(exc).__name__}) — ручка вернула неожиданную форму JSON"
            ) from exc
        return str(node)

    async def close_session(self, session_id: str) -> None:
        # native-сессия с записью памяти при закрытии (G5): финализируем на стенде
        # ДО того как раннер начнёт проверять запись (runner закрывает сессии
        # доставки перед settle). Иначе — просто роняем локальную историю.
        if (
            self._profile is not None
            and self._profile.session.mode == "native"
            and self._profile.session.writes_on_close
            and self._profile.session.finalize_path
            and session_id in self._sessions
        ):
            path = self._profile.session.finalize_path.replace("{session_id}", session_id)
            headers: dict[str, str] = {}
            if self._profile.identity.scheme == "bearer_env":
                principal = self._profile.identity.principal_for(self._session_users.get(session_id, ""))
                if principal and principal.env:
                    key = os.environ.get(principal.env, "").strip()
                    if key:
                        headers["Authorization"] = f"Bearer {key}"
            resp = await self._client.post(path, headers=headers or None)
            resp.raise_for_status()
        self._sessions.pop(session_id, None)
        self._session_users.pop(session_id, None)

    # ---------------------------------------------------------------- probe

    async def probe(self) -> ProbeResult:
        # Health-проба по профилю: GET path+expect_status, либо POST-проба
        # (умолчание и tier-1 без профиля).
        if self._profile is not None and self._profile.health.mode == "get":
            try:
                resp = await self._client.get(self._profile.health.path or "/")
                return ProbeResult(
                    reachable=resp.status_code == self._profile.health.expect_status,
                    capabilities=self.capabilities,
                    detail={"status": resp.status_code, "mode": "get"},
                )
            except httpx.TransportError as exc:
                return ProbeResult(
                    reachable=False, capabilities=self.capabilities,
                    error=f"health GET {self.base_url}{self._profile.health.path} недоступна: {exc}",
                )
        try:
            resp = await self._client.post(
                self.chat_path,
                json={"model": self.model_name,
                      "messages": [{"role": "user", "content": "ping"}]},
            )
            return ProbeResult(
                reachable=resp.status_code < 500,
                capabilities=self.capabilities,
                detail={"status": resp.status_code},
            )
        except httpx.TransportError as exc:
            return ProbeResult(
                reachable=False, capabilities=self.capabilities,
                error=f"ручка {self.base_url}{self.chat_path} недоступна: {exc}",
            )

    # ------------------------------------------------- сброс и наблюдаемость

    async def reset_state(self) -> None:
        # Внешнего сброса нет (reset_available=False навсегда); очищаем только
        # собственную историю сессий — это состояние адаптера, не таргета.
        self._sessions.clear()
        self._session_users.clear()

    async def get_trace(self, session_id: str) -> list[dict[str, Any]] | None:
        return None  # трасса решений таргета в tier-1 не наблюдаема

    async def snapshot(self) -> None:  # type: ignore[override]
        return None  # доступ к памяти цели отсутствует — оракулы уходят в UNKNOWN

    async def snapshot_user(self, user_id: str) -> None:  # type: ignore[override]
        return None

    async def wait_until_persistent(self, evidence: dict[str, Any]) -> SettleResult:
        # СИГНАЛ, а не дефолт-ловушка: память цели не читается — settle не
        # доказуем, оракул обязан ответить UNKNOWN, а не success/timeout.
        return SettleResult(
            outcome="unavailable",
            reason=(
                "tier-1 http_endpoint: память цели не наблюдаема (snapshot=None) — "
                "персистентность не доказуема, честный UNKNOWN, не observed"
            ),
        )

    async def aclose(self) -> None:
        await self._client.aclose()
