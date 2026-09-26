"""src/memnotsafe/adapters/profile.py — EXT-A: версионированная схема target
profile для tier-1 чёрного ящика (поток EXT-OPERATOR, карта 1/4).

Профиль декларативно описывает ЧУЖУЮ цель, которую оператор ИБ подключает по
URL: транспорт (путь/метод/mapping полей запроса и ответа), identity (как цель
различает принципалов), сессию (native id в запросе или локальная история
адаптера + жизненный цикл), health-пробу и заявленные возможности наблюдения.
Секретов НЕ содержит — только ИМЕНА переменных окружения (как identities живого
стенда). Читается точечно в core/config.py; исполняется adapters/http_endpoint.py.

Строгость (карта §6): неизвестный ключ на ЛЮБОМ уровне — ProfileError ДО первого
запроса. Никакого **_ignored: опечатка в имени поля не имеет права молча
включить дефолт и увести прогон мимо намерения оператора.

Границы безопасности (замки аудита, подтверждены A0):
  G1 — граница хоста. Все пути профиля (chat_path, finalize_path, health.path)
       ОБЯЗАНЫ быть относительными к base_url: абсолютный URL, protocol-relative
       (`//host`) или схема (`http://…`) в пути отвергаются при разборе; base_url
       с учётными данными (userinfo) и удалённый плейнтекст-HTTP без явного
       transport.allow_remote отвергаются ДО чтения ключа и до запроса — иначе
       httpx-клиент с Bearer-заголовком унёс бы ключ на чужой хост.
  G2 — зарезервированные поля. messages/model/identity/session/auth-поля заняты
       контрактом; конфликт в request.extra_fields — ошибка конфигурации до
       вызова цели (иначе статический extra перекрыл бы сообщения атаки).
  G3 — identity-handshake. Два ENV-имени ≠ два субъекта. Cross-user допускается
       ТОЛЬКО при доказанной независимости принципалов (разные субъекты, разные
       токены и явная аттестация оператора cross_user_independent). Иначе честный
       статус «независимость не доказана» → отказ до прогона с человеческой
       причиной.
  G6 — провенанс. normalized_digest() даёт стабильный sha256 профиля без значений
       секретов (в профиле их и нет — только имена env); digest + schema_version
       входят в experiment_id (core/experiment.py), чтобы эффективная цель, а не
       только строка adapter из YAML, определяла тождество эксперимента.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from memnotsafe.core.goal_contract import canonical_json, sha256_hex

SUPPORTED_SCHEMA_VERSIONS = (1,)

# Схемы identity: как цель различает принципала на уровне протокола.
IDENTITY_SCHEMES = ("bearer_env", "request_header", "request_field", "native_session", "none")
AUTH_SCHEMES = ("bearer_env", "none")
SESSION_MODES = ("adapter_history", "native")
HEALTH_MODES = ("get", "post_only")

# Литералы, которые нельзя переопределять пользовательскими полями тела (G2):
# они несут семантику контракта, а не полезную нагрузку.
_RESERVED_LITERALS = frozenset({"messages", "model", "identity", "session", "auth", "authorization"})


class ProfileError(ValueError):
    """Нарушение контракта target-профиля. Поднимается ДО чтения ключа и до
    первого сетевого вызова (карта §6): оператор узнаёт об ошибке конфигурации
    раньше, чем прогон коснётся цели."""


# --------------------------------------------------------------------- разбор


def _as_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProfileError(f"{where}: ожидается отображение (mapping), получено {type(value).__name__}")
    return value


def _reject_unknown(block: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(block) - allowed)
    if unknown:
        raise ProfileError(
            f"{where}: неизвестный(е) ключ(и) {unknown} — опечатка или неподдерживаемое поле; "
            f"допустимы {sorted(allowed)} (строгий разбор, никакого **_ignored)"
        )


def _as_bool(value: Any, where: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ProfileError(f"{where}: ожидается булево (true/false), получено {value!r}")
    return value


def _as_str(value: Any, where: str, default: str | None) -> str | None:
    if value is None:
        return default
    if not isinstance(value, str) or not value.strip():
        raise ProfileError(f"{where}: ожидается непустая строка, получено {value!r}")
    return value


def _validate_relative_path(path: str, where: str) -> str:
    """G1: путь ОБЯЗАН быть относительным к base_url. Абсолютный URL со схемой,
    protocol-relative `//host` и путь без ведущего '/' отвергаются — так путь не
    может увести запрос (и Bearer-заголовок) на чужой хост."""
    if not isinstance(path, str) or not path.strip():
        raise ProfileError(f"{where}: путь обязан быть непустой строкой")
    if "://" in path or path.startswith("//"):
        raise ProfileError(
            f"{where}={path!r}: абсолютный/protocol-relative URL запрещён — путь только "
            f"относительно base_url (G1: чужой хост не читается и не вызывается)"
        )
    if not path.startswith("/"):
        raise ProfileError(
            f"{where}={path!r}: путь обязан начинаться с '/' (относительный к base_url, G1)"
        )
    return path


# -------------------------------------------------------------- секции профиля


@dataclass(frozen=True)
class RequestMapping:
    model_field: str = "model"
    messages_field: str = "messages"
    role_key: str = "role"
    content_key: str = "content"

    def as_digest(self) -> dict[str, Any]:
        return {
            "model_field": self.model_field,
            "messages_field": self.messages_field,
            "role_key": self.role_key,
            "content_key": self.content_key,
        }


@dataclass(frozen=True)
class TransportSpec:
    chat_path: str = "/v1/chat/completions"
    method: str = "POST"
    allow_remote: bool = False
    request: RequestMapping = field(default_factory=RequestMapping)
    content_path: tuple[Any, ...] = ("choices", 0, "message", "content")
    extra_fields: dict[str, Any] = field(default_factory=dict)

    def as_digest(self) -> dict[str, Any]:
        return {
            "chat_path": self.chat_path,
            "method": self.method,
            "allow_remote": self.allow_remote,
            "request": self.request.as_digest(),
            "content_path": list(self.content_path),
            "extra_fields": self.extra_fields,
        }


@dataclass(frozen=True)
class AuthSpec:
    scheme: str = "bearer_env"
    api_key_env: str | None = None

    def as_digest(self) -> dict[str, Any]:
        # api_key_env — ИМЯ переменной, не значение: в digest попадает имя.
        return {"scheme": self.scheme, "api_key_env": self.api_key_env}


@dataclass(frozen=True)
class Principal:
    subject: str
    user_id: str
    env: str | None = None
    value: str | None = None

    def as_digest(self) -> dict[str, Any]:
        return {"subject": self.subject, "user_id": self.user_id, "env": self.env, "value": self.value}


@dataclass(frozen=True)
class IdentitySpec:
    scheme: str = "none"
    header: str | None = None
    field_name: str | None = None
    cross_user_independent: bool = False
    principals: tuple[Principal, ...] = ()

    def as_digest(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "header": self.header,
            "field": self.field_name,
            "cross_user_independent": self.cross_user_independent,
            "principals": [p.as_digest() for p in self.principals],
        }

    def principal_for(self, user_id: str) -> Principal | None:
        for p in self.principals:
            if p.user_id == user_id:
                return p
        return None

    def _independence_token(self, p: Principal) -> str:
        """Токен, доказывающий отдельность принципала на уровне протокола:
        для bearer_env — ИМЯ env-ключа (разные аккаунты = разные ключи); для
        header/field — значение идентификатора (по умолчанию user_id)."""
        if self.scheme == "bearer_env":
            return f"env:{p.env}"
        if self.scheme in ("request_header", "request_field"):
            return f"val:{p.value or p.user_id}"
        return f"user:{p.user_id}"


@dataclass(frozen=True)
class SessionSpec:
    mode: str = "adapter_history"
    native_field: str | None = None
    writes_on_close: bool = False
    finalize_path: str | None = None

    def as_digest(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "native_field": self.native_field,
            "writes_on_close": self.writes_on_close,
            "finalize_path": self.finalize_path,
        }


@dataclass(frozen=True)
class ObservationSpec:
    memory_snapshot: bool = False
    retrieval_trace: bool = False
    tool_telemetry: bool = False
    reset: bool = False

    def as_digest(self) -> dict[str, Any]:
        return {
            "memory_snapshot": self.memory_snapshot,
            "retrieval_trace": self.retrieval_trace,
            "tool_telemetry": self.tool_telemetry,
            "reset": self.reset,
        }


@dataclass(frozen=True)
class HealthProbe:
    mode: str = "post_only"
    path: str | None = None
    expect_status: int | None = None

    def as_digest(self) -> dict[str, Any]:
        return {"mode": self.mode, "path": self.path, "expect_status": self.expect_status}


@dataclass(frozen=True)
class TargetProfile:
    schema_version: int
    transport: TransportSpec
    auth: AuthSpec
    identity: IdentitySpec
    session: SessionSpec
    observation: ObservationSpec
    health: HealthProbe

    # ----------------------------------------------------------- провенанс (G6)

    def as_digest(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "transport": self.transport.as_digest(),
            "auth": self.auth.as_digest(),
            "identity": self.identity.as_digest(),
            "session": self.session.as_digest(),
            "observation": self.observation.as_digest(),
            "health": self.health.as_digest(),
        }

    def normalized_digest(self) -> str:
        """Стабильный sha256 нормализованного профиля БЕЗ значений секретов
        (в профиле хранятся только имена env). Каноническая сериализация — тот
        же helper, что у ExperimentSpec, чтобы digest'ы были сопоставимы."""
        return sha256_hex(canonical_json(self.as_digest()))

    # ------------------------------------------------------- граница хоста (G1)

    def check_host_boundary(self, base_url: str) -> None:
        """Отвергает чужой/небезопасный хост ДО чтения ключа и до запроса.
        base_url с учётными данными и удалённый плейнтекст-HTTP без явного
        allow-флага запрещены; пути профиля уже проверены относительными при
        разборе."""
        parsed = urlparse(base_url or "")
        netloc = parsed.netloc or ""
        if parsed.username or parsed.password or "@" in netloc:
            raise ProfileError(
                f"base_url {base_url!r} несёт учётные данные (userinfo) — запрещено (G1): "
                "ключ читается только из окружения, не из URL"
            )
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        is_local = host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or host.endswith(".localhost")
        if not is_local and scheme != "https" and not self.transport.allow_remote:
            raise ProfileError(
                f"удалённый плейнтекст-HTTP таргет {base_url!r} без явного "
                "transport.allow_remote=true запрещён (G1): ключ не читается, запрос не "
                "отправляется. Используйте https или подтвердите allow_remote осознанно."
            )

    # -------------------------------------------------- независимость (G3)

    def validate_for_actors(self, attacker_user_id: str, victim_user_id: str) -> None:
        """Отказ ДО прогона, если сценарий cross-user, а профиль не доказывает
        независимость двух принципалов. Human-readable причина называет, какое
        именно условие не выполнено (одно значение под разными именами → тот же
        токен; два ключа одного субъекта → тот же subject; сервер игнорирует
        identity → нет схемы-переносчика; нет аттестации → «не доказано»)."""
        single_user = attacker_user_id == victim_user_id
        if single_user:
            return  # single-user допустим всегда (карта §2)

        if self.identity.scheme in ("none",) or not self.identity.principals:
            raise ProfileError(
                f"cross-user сценарий (attacker={attacker_user_id}, victim={victim_user_id}), "
                "но профиль не объявляет принципалов/identity-схему — сервер не различает "
                "субъектов. Независимость не доказана → отказ (G3)."
            )

        atk = self.identity.principal_for(attacker_user_id)
        vic = self.identity.principal_for(victim_user_id)
        if atk is None or vic is None:
            missing = [u for u, p in ((attacker_user_id, atk), (victim_user_id, vic)) if p is None]
            raise ProfileError(
                f"cross-user сценарий требует объявленных принципалов для обоих user_id; "
                f"в профиле нет: {missing}. Независимость не доказана → отказ (G3)."
            )
        if atk.subject == vic.subject:
            raise ProfileError(
                f"cross-user сценарий, но принципалы attacker={attacker_user_id} и "
                f"victim={victim_user_id} указывают на ОДИН субъект {atk.subject!r} "
                "(два ключа одного субъекта ≠ два субъекта) → отказ (G3)."
            )
        atk_token = self.identity._independence_token(atk)
        vic_token = self.identity._independence_token(vic)
        if atk_token == vic_token:
            raise ProfileError(
                f"cross-user сценарий, но принципалы делят один идентификатор "
                f"({atk_token}) — одно значение под разными именами не создаёт двух "
                "субъектов → отказ (G3)."
            )
        if not self.identity.cross_user_independent:
            raise ProfileError(
                f"cross-user сценарий: два ENV-имени ≠ два субъекта. Профиль не подтвердил "
                "независимость принципалов (identity.cross_user_independent). Пока независимость "
                "не доказана серверной привязкой/handshake — отказ (G3). Для single-user это поле не нужно."
            )


# ------------------------------------------------------------ разбор секций


def _parse_request(raw: Any) -> RequestMapping:
    block = _as_mapping(raw, "profile.transport.request")
    _reject_unknown(block, frozenset(RequestMapping().__dict__), "profile.transport.request")
    d = RequestMapping()
    return RequestMapping(
        model_field=_as_str(block.get("model_field"), "profile.transport.request.model_field", d.model_field),
        messages_field=_as_str(block.get("messages_field"), "profile.transport.request.messages_field", d.messages_field),
        role_key=_as_str(block.get("role_key"), "profile.transport.request.role_key", d.role_key),
        content_key=_as_str(block.get("content_key"), "profile.transport.request.content_key", d.content_key),
    )


def _parse_content_path(raw: Any) -> tuple[Any, ...]:
    if raw is None:
        return ("choices", 0, "message", "content")
    if not isinstance(raw, list) or not raw:
        raise ProfileError(
            "profile.transport.response.content_path: ожидается непустой список шагов "
            "(ключи-строки и индексы-числа), например [choices, 0, message, content]"
        )
    for step in raw:
        if not isinstance(step, (str, int)) or isinstance(step, bool):
            raise ProfileError(
                f"profile.transport.response.content_path: шаг {step!r} обязан быть строкой или числом"
            )
    return tuple(raw)


def _parse_transport(raw: Any) -> TransportSpec:
    block = _as_mapping(raw, "profile.transport")
    _reject_unknown(
        block,
        frozenset({"chat_path", "method", "allow_remote", "request", "response", "extra_fields"}),
        "profile.transport",
    )
    chat_path = _validate_relative_path(
        block.get("chat_path", "/v1/chat/completions"), "profile.transport.chat_path"
    )
    method = _as_str(block.get("method"), "profile.transport.method", "POST").upper()
    if method not in ("POST",):
        raise ProfileError(
            f"profile.transport.method={method!r} не поддерживается (tier-1 chat-ручка — только POST)"
        )
    response_block = _as_mapping(block.get("response"), "profile.transport.response")
    _reject_unknown(response_block, frozenset({"content_path"}), "profile.transport.response")
    extra_fields = block.get("extra_fields") or {}
    if not isinstance(extra_fields, dict):
        raise ProfileError(
            f"profile.transport.extra_fields: ожидается отображение, получено {type(extra_fields).__name__}"
        )
    return TransportSpec(
        chat_path=chat_path,
        method=method,
        allow_remote=_as_bool(block.get("allow_remote"), "profile.transport.allow_remote", False),
        request=_parse_request(block.get("request")),
        content_path=_parse_content_path(response_block.get("content_path")),
        extra_fields=dict(extra_fields),
    )


def _parse_auth(raw: Any) -> AuthSpec:
    block = _as_mapping(raw, "profile.auth")
    _reject_unknown(block, frozenset({"scheme", "api_key_env"}), "profile.auth")
    scheme = _as_str(block.get("scheme"), "profile.auth.scheme", "bearer_env")
    if scheme not in AUTH_SCHEMES:
        raise ProfileError(f"profile.auth.scheme={scheme!r} не поддерживается (доступны {list(AUTH_SCHEMES)})")
    api_key_env = _as_str(block.get("api_key_env"), "profile.auth.api_key_env", None)
    if scheme == "bearer_env" and not api_key_env:
        raise ProfileError("profile.auth.scheme=bearer_env требует profile.auth.api_key_env (ИМЯ переменной окружения)")
    return AuthSpec(scheme=scheme, api_key_env=api_key_env)


def _parse_principal(raw: Any, idx: int) -> Principal:
    where = f"profile.identity.principals[{idx}]"
    block = _as_mapping(raw, where)
    _reject_unknown(block, frozenset({"subject", "user_id", "env", "value"}), where)
    subject = _as_str(block.get("subject"), f"{where}.subject", None)
    if not subject:
        raise ProfileError(f"{where}.subject обязателен (имя субъекта/аккаунта, не секрет)")
    user_id = block.get("user_id")
    if user_id is None or str(user_id).strip() == "":
        raise ProfileError(f"{where}.user_id обязателен (совпадает с actor.user_id сценария)")
    return Principal(
        subject=subject,
        user_id=str(user_id),
        env=_as_str(block.get("env"), f"{where}.env", None),
        value=_as_str(block.get("value"), f"{where}.value", None),
    )


def _parse_identity(raw: Any) -> IdentitySpec:
    block = _as_mapping(raw, "profile.identity")
    _reject_unknown(
        block,
        frozenset({"scheme", "header", "field", "cross_user_independent", "principals"}),
        "profile.identity",
    )
    scheme = _as_str(block.get("scheme"), "profile.identity.scheme", "none")
    if scheme not in IDENTITY_SCHEMES:
        raise ProfileError(f"profile.identity.scheme={scheme!r} не поддерживается (доступны {list(IDENTITY_SCHEMES)})")
    principals_raw = block.get("principals") or []
    if not isinstance(principals_raw, list):
        raise ProfileError("profile.identity.principals: ожидается список принципалов")
    principals = tuple(_parse_principal(p, i) for i, p in enumerate(principals_raw))

    header = _as_str(block.get("header"), "profile.identity.header", None)
    field_name = _as_str(block.get("field"), "profile.identity.field", None)

    # Схема-специфичные обязательности + запрет «сервер игнорирует identity».
    if scheme == "bearer_env":
        for p in principals:
            if not p.env:
                raise ProfileError(
                    f"profile.identity.scheme=bearer_env: принципал subject={p.subject!r} обязан "
                    "нести env (ИМЯ переменной с ключом принципала)"
                )
    elif scheme == "request_header" and not header:
        raise ProfileError("profile.identity.scheme=request_header требует profile.identity.header (имя заголовка)")
    elif scheme == "request_field" and not field_name:
        raise ProfileError("profile.identity.scheme=request_field требует profile.identity.field (имя поля тела)")

    return IdentitySpec(
        scheme=scheme,
        header=header,
        field_name=field_name,
        cross_user_independent=_as_bool(block.get("cross_user_independent"), "profile.identity.cross_user_independent", False),
        principals=principals,
    )


def _parse_session(raw: Any) -> SessionSpec:
    block = _as_mapping(raw, "profile.session")
    _reject_unknown(
        block,
        frozenset({"mode", "native_field", "writes_on_close", "finalize_path"}),
        "profile.session",
    )
    mode = _as_str(block.get("mode"), "profile.session.mode", "adapter_history")
    if mode not in SESSION_MODES:
        raise ProfileError(f"profile.session.mode={mode!r} не поддерживается (доступны {list(SESSION_MODES)})")
    native_field = _as_str(block.get("native_field"), "profile.session.native_field", None)
    writes_on_close = _as_bool(block.get("writes_on_close"), "profile.session.writes_on_close", False)
    finalize_path = block.get("finalize_path")
    if finalize_path is not None:
        finalize_path = _validate_relative_path(finalize_path, "profile.session.finalize_path")
    if mode == "adapter_history" and native_field:
        raise ProfileError(
            "profile.session.native_field задан, но mode=adapter_history — native id уходит в запрос "
            "только при mode=native (явность, карта §3)"
        )
    if writes_on_close and not finalize_path:
        raise ProfileError(
            "profile.session.writes_on_close=true требует finalize_path (как именно закрытие пишет "
            "память чужого стенда — G5)"
        )
    return SessionSpec(mode=mode, native_field=native_field, writes_on_close=writes_on_close, finalize_path=finalize_path)


def _parse_observation(raw: Any) -> ObservationSpec:
    block = _as_mapping(raw, "profile.observation")
    allowed = frozenset({"memory_snapshot", "retrieval_trace", "tool_telemetry", "reset"})
    _reject_unknown(block, allowed, "profile.observation")
    return ObservationSpec(
        memory_snapshot=_as_bool(block.get("memory_snapshot"), "profile.observation.memory_snapshot", False),
        retrieval_trace=_as_bool(block.get("retrieval_trace"), "profile.observation.retrieval_trace", False),
        tool_telemetry=_as_bool(block.get("tool_telemetry"), "profile.observation.tool_telemetry", False),
        reset=_as_bool(block.get("reset"), "profile.observation.reset", False),
    )


def _parse_health(raw: Any) -> HealthProbe:
    block = _as_mapping(raw, "profile.health")
    _reject_unknown(block, frozenset({"mode", "path", "expect_status"}), "profile.health")
    mode = _as_str(block.get("mode"), "profile.health.mode", "post_only")
    if mode not in HEALTH_MODES:
        raise ProfileError(f"profile.health.mode={mode!r} не поддерживается (доступны {list(HEALTH_MODES)})")
    path = block.get("path")
    expect_status = block.get("expect_status")
    if mode == "get":
        if not path:
            raise ProfileError("profile.health.mode=get требует path (относительный путь GET-пробы)")
        path = _validate_relative_path(path, "profile.health.path")
        if not isinstance(expect_status, int) or isinstance(expect_status, bool):
            raise ProfileError("profile.health.mode=get требует expect_status (целочисленный HTTP-статус)")
    else:
        if path is not None or expect_status is not None:
            raise ProfileError("profile.health.mode=post_only не принимает path/expect_status (проба только POST-ом)")
    return HealthProbe(mode=mode, path=path, expect_status=expect_status)


def _check_reserved_extra_fields(profile: TargetProfile) -> None:
    """G2: request.extra_fields не имеет права нести зарезервированные ключи —
    иначе статический extra перекрыл бы model/messages/identity/session/auth."""
    reserved = set(_RESERVED_LITERALS)
    reserved.add(profile.transport.request.model_field)
    reserved.add(profile.transport.request.messages_field)
    if profile.session.mode == "native" and profile.session.native_field:
        reserved.add(profile.session.native_field)
    if profile.identity.scheme == "request_field" and profile.identity.field_name:
        reserved.add(profile.identity.field_name)
    clash = sorted(set(profile.transport.extra_fields) & reserved)
    if clash:
        raise ProfileError(
            f"profile.transport.extra_fields конфликтует с зарезервированными полями {clash} "
            "(G2): extra не имеет права перекрыть model/messages/identity/session/auth — "
            "иначе он подменил бы сообщения атаки. Ошибка конфигурации до вызова цели."
        )


def load_profile(raw: Any) -> TargetProfile:
    """Строгий разбор target-профиля. schema_version обязателен; неизвестный ключ
    на любом уровне — ProfileError. Возврат — неизменяемый TargetProfile."""
    block = _as_mapping(raw, "profile")
    _reject_unknown(
        block,
        frozenset({"schema_version", "transport", "auth", "identity", "session", "observation", "health"}),
        "profile",
    )
    if "schema_version" not in block:
        raise ProfileError("profile.schema_version обязателен (версионированная схема, карта §задача)")
    schema_version = block.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise ProfileError(f"profile.schema_version обязан быть целым числом, получено {schema_version!r}")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ProfileError(
            f"profile.schema_version={schema_version} не поддерживается (доступны {list(SUPPORTED_SCHEMA_VERSIONS)})"
        )

    profile = TargetProfile(
        schema_version=schema_version,
        transport=_parse_transport(block.get("transport")),
        auth=_parse_auth(block.get("auth")),
        identity=_parse_identity(block.get("identity")),
        session=_parse_session(block.get("session")),
        observation=_parse_observation(block.get("observation")),
        health=_parse_health(block.get("health")),
    )
    _check_reserved_extra_fields(profile)
    return profile
