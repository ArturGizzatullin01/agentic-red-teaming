"""src/memnotsafe/core/config.py — YAML как чистый configuration layer:
КТО атакует/жертва, КАКОЙ adapter/family, СКОЛЬКО повторов. Никакой Python-
логики в YAML — сами шаги атаки декларирует класс в src/memnotsafe/attacks/*.py."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:  # только для аннотаций (config импортируется рано)
    from memnotsafe.adapters.profile import TargetProfile


@dataclass
class ActorConfig:
    user_id: str


@dataclass
class TargetSpec:
    adapter: str = "mock"
    base_url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    # EXT-A: версионированный target-профиль (adapters/profile.py). None —
    # сценарий без профиля: legacy-путь, поведение прежнее (регресс).
    profile: "TargetProfile | None" = None


@dataclass
class JudgeSpec:
    """Конфигурация LLM-судьи из блока `judge:` сценария
    (contracts/scenario-judge.schema.md). Блок опционален целиком: его
    отсутствие эквивалентно `enabled: false`, поэтому сценарии, написанные до
    этой фичи, работают без правок и без сети (FR-001, SC-003).

    Секретов здесь нет — только ИМЯ переменной окружения, как в `identities`
    живого стенда."""

    enabled: bool = False
    model: str | None = None
    base_url: str = "https://openrouter.ai/api/v1"
    api_key_env: str = "OPENROUTER_API_KEY"
    min_confidence: float = 0.7
    max_retries: int = 2
    timeout_s: float = 30.0
    max_calls: int | None = None
    max_artifact_chars: int = 8000
    temperature: float = 0.0

    def resolve_max_calls(self, repetitions: int) -> int:
        """Бюджет HTTP-запросов на КАМПАНИЮ. Умолчание — потолок худшего случая
        `3 × repetitions × (1 + max_retries)`: три судимые стадии на случай,
        каждая с повторами. Потолок известен до запуска, поэтому стоимость
        прогона предсказуема (SC-006)."""
        if self.max_calls is not None:
            return self.max_calls
        return 3 * max(repetitions, 1) * (1 + self.max_retries)


@dataclass
class Scenario:
    id: str
    path: Path
    target: TargetSpec
    attacker: ActorConfig
    victim: ActorConfig
    attack_family: str
    repetitions: int = 1
    # P18 (CARD-P18): человекочитаемое имя сценария для каталога мастера `go`.
    # Аддитивно и опционально: default None, старые YAML без ключа `title:`
    # грузятся как раньше; ключ в существующие сценарии не расставляется —
    # мастер падает на имя семейства из реестра, если title не задан.
    title: str | None = None
    stop_on_success: bool = False
    trigger_override: str | None = None
    oracle_overrides: dict[str, Any] = field(default_factory=dict)
    judge: JudgeSpec = field(default_factory=JudgeSpec)
    # Путь к корпусу атак для family="generated" (фича 004). Аддитивно: у обычных
    # сценариев остаётся None, поведение существующих прогонов не меняется.
    corpus_path: Path | None = None
    require_case_marker: bool = False
    # FIX-C (G3.1/G3.2): режим сброса памяти стенда между попытками. Дефолт
    # отныне "namespace" — чистятся ТОЛЬКО свои сессии; "global" (delete_many по
    # всем 4 коллекциям, включая глобальный слой политик — предмет G3.2) требует
    # явного слова reset_scope: global И непустого target.reset_ack. Прежний
    # молчаливый глобальный wipe был эрратой G3.1 (живые прогоны стирали то, что
    # измеряли). Значение прокидывает build_adapter; опечатку ловит адаптер.
    reset_scope: str = "namespace"
    raw: dict[str, Any] = field(default_factory=dict)


def load_scenario(path: str | Path) -> Scenario:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Сценарий не найден: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    try:
        actors = raw["actors"]
        attack = raw["attack"]
    except KeyError as exc:
        raise ValueError(f"В сценарии {path} отсутствует обязательное поле {exc}") from exc

    target_raw = raw.get("target", {}) or {}
    # EXT-A: точка чтения профиля. Присутствует блок target.profile → строгий
    # разбор (опечатка ключа падает здесь, ДО построения адаптера и запроса).
    profile_raw = target_raw.get("profile")
    if profile_raw is not None:
        from memnotsafe.adapters.profile import load_profile

        target_profile = load_profile(profile_raw)
    else:
        target_profile = None
    # Три валидные формы actor-блоков (карточка D4): оба; только attacker
    # (single-user атака); только victim (контроль единственного принципала).
    # Отсутствующий блок достраивается вторым — после загрузки отличить
    # «объявлены оба» от «достроен» можно только по raw, что и делает B3.
    # `actors:` без тела парсится в None — это тоже «ни attacker, ни victim».
    attacker_raw = (actors or {}).get("attacker")
    victim_raw = (actors or {}).get("victim")
    if not attacker_raw and not victim_raw:
        raise ValueError(
            f"В сценарии {path} в блоке actors нет ни attacker, ни victim "
            "(блок отсутствует или пуст) — нужен хотя бы один "
            "(второй достроится им же: single-user/контроль)"
        )
    if not victim_raw:
        victim_raw = attacker_raw  # single-user атаки: victim==attacker по умолчанию
    elif not attacker_raw:
        attacker_raw = victim_raw  # victim-only (контроль жертвы): attacker==victim

    return Scenario(
        id=raw.get("id", path.stem),
        path=path,
        target=TargetSpec(
            adapter=target_raw.get("adapter", "mock"),
            base_url=target_raw.get("base_url"),
            extra={k: v for k, v in target_raw.items() if k not in ("adapter", "base_url", "profile")},
            profile=target_profile,
        ),
        attacker=ActorConfig(user_id=str(attacker_raw["user_id"])),
        victim=ActorConfig(user_id=str(victim_raw["user_id"])),
        attack_family=attack["family"],
        repetitions=int((raw.get("metrics") or {}).get("repetitions", 1)),
        title=(str(raw["title"]) if raw.get("title") is not None else None),
        stop_on_success=bool((raw.get("metrics") or {}).get("stop_on_success", False)),
        trigger_override=(raw.get("trigger") or {}).get("prompt"),
        oracle_overrides=raw.get("oracle", {}) or {},
        judge=_parse_judge(raw.get("judge")),
        corpus_path=(Path(attack["corpus"]) if attack.get("corpus") else None),
        require_case_marker=bool(raw.get("require_case_marker", False)),
        reset_scope=str(raw.get("reset_scope", "namespace")),
        raw=raw,
    )


def _parse_judge(block: Any) -> JudgeSpec:
    """Разбор опционального блока `judge:`. Валидация значений — отдельным
    шагом (`validate_judge_spec`) уже ПОСЛЕ применения флагов CLI: иначе
    `--no-judge` не смог бы погасить заведомо неполный блок в сценарии."""
    if not block:
        return JudgeSpec()
    if not isinstance(block, dict):
        raise ValueError(f"Блок judge: должен быть отображением, получено {type(block).__name__}")

    defaults = JudgeSpec()
    max_calls = block.get("max_calls", defaults.max_calls)
    return JudgeSpec(
        enabled=bool(block.get("enabled", defaults.enabled)),
        model=block.get("model", defaults.model),
        base_url=str(block.get("base_url", defaults.base_url)),
        api_key_env=str(block.get("api_key_env", defaults.api_key_env)),
        min_confidence=float(block.get("min_confidence", defaults.min_confidence)),
        max_retries=int(block.get("max_retries", defaults.max_retries)),
        timeout_s=float(block.get("timeout_s", defaults.timeout_s)),
        max_calls=None if max_calls is None else int(max_calls),
        max_artifact_chars=int(block.get("max_artifact_chars", defaults.max_artifact_chars)),
        temperature=float(block.get("temperature", defaults.temperature)),
    )


def validate_judge_spec(spec: JudgeSpec, scenario_id: str) -> None:
    """Ошибка конфигурации судьи — не результат атаки: RunnerError -> exit 1
    ДО первого обращения к таргету (Принцип VII, FR-020). Оператор узнаёт о
    плохом конфиге раньше, чем прогон потратит вызовы к стенду.

    Значение ключа в сообщение не попадает никогда — только имя переменной."""
    from memnotsafe.core.runner import RunnerError

    if not spec.enabled:
        return  # выключенный судья не валидируется: его параметры не используются

    if not spec.model:
        raise RunnerError(
            f"Сценарий {scenario_id}: judge.enabled=true требует judge.model "
            f"(идентификатор модели-судьи, отличной от модели таргета)"
        )
    if not os.environ.get(spec.api_key_env, "").strip():
        raise RunnerError(
            f"Сценарий {scenario_id}: переменная окружения {spec.api_key_env} не задана или пуста — "
            f"судья не может обратиться к провайдеру"
        )
    if not 0.0 <= spec.min_confidence <= 1.0:
        raise RunnerError(f"Сценарий {scenario_id}: judge.min_confidence={spec.min_confidence} вне диапазона [0.0, 1.0]")
    if spec.max_retries < 0:
        raise RunnerError(f"Сценарий {scenario_id}: judge.max_retries={spec.max_retries} должен быть >= 0")
    if spec.timeout_s <= 0:
        raise RunnerError(f"Сценарий {scenario_id}: judge.timeout_s={spec.timeout_s} должен быть > 0")
    if spec.max_artifact_chars <= 0:
        raise RunnerError(
            f"Сценарий {scenario_id}: judge.max_artifact_chars={spec.max_artifact_chars} должен быть > 0"
        )
    if spec.max_calls is not None and spec.max_calls <= 0:
        raise RunnerError(f"Сценарий {scenario_id}: judge.max_calls={spec.max_calls} должен быть > 0")
    if spec.temperature < 0:
        raise RunnerError(f"Сценарий {scenario_id}: judge.temperature={spec.temperature} должен быть >= 0")


# EXT-B (ДЕФЕКТ-3): имена известных адаптеров. --target с одним из них — ЯВНОЕ
# переключение адаптера; любая другая строка трактуется как URL (base_url).
KNOWN_ADAPTERS = ("mock", "openai", "openai_compatible", "http_endpoint", "investment_stand")


@dataclass(frozen=True)
class EffectiveTarget:
    """Единая эффективная цель прогона (EXT-B): то, с чем РЕАЛЬНО будут говорить,
    а не только строка adapter из YAML (ДЕФЕКТ-3). Одна точка резолва
    (resolve_effective_target) снабжает ею build_adapter, ExperimentSpec и
    метаданные кампании — смена цели меняет тождество эксперимента."""

    adapter: str
    base_url: str | None
    profile: "TargetProfile | None"


def resolve_effective_target(scenario: Scenario, target_override: str | None = None) -> EffectiveTarget:
    """ЕДИНАЯ точка резолва эффективной цели (EXT-B, ДЕФЕКТ-3). --target:
      - имя известного адаптера → ЯВНОЕ переключение адаптера (документированная
        семантика флага; mock — сброс base_url/profile в smoke);
      - строка-URL → переопределение base_url;
      - 'mock' → явный mock.
    Замок «никогда тихий mock»: URL поверх mock-сценария — ОТКАЗ с причиной и
    подсказкой, а не молчаливый MockTarget, игнорирующий URL (иначе прогон думает,
    что бьёт живую цель). Профиль (EXT-A) исполняет только http_endpoint tier-1;
    на mock профиль осознанно не переносится (явный smoke)."""
    adapter = scenario.target.adapter
    base_url = scenario.target.base_url
    profile = scenario.target.profile

    if target_override:
        if target_override in KNOWN_ADAPTERS:
            adapter = target_override
        else:
            # target_override — URL. НИКОГДА не тихий mock.
            if adapter == "mock":
                raise ValueError(
                    f"Сценарий {scenario.id}: adapter=mock, а --target={target_override!r} — это URL. "
                    "Молчаливый mock по URL запрещён: URL был бы проигнорирован, а прогон считал бы, что "
                    "бьёт живую цель. Подсказка: смените adapter в сценарии на живой "
                    "(openai/openai_compatible/http_endpoint/investment_stand); либо передайте "
                    "--target <имя-известного-адаптера> для ЯВНОГО переключения; либо --target mock "
                    "для явного smoke."
                )
            base_url = target_override

    if adapter == "mock":
        # mock не ходит по сети и не исполняет профиль — эффективная цель чиста.
        return EffectiveTarget(adapter="mock", base_url=None, profile=None)

    if profile is not None and adapter != "http_endpoint":
        # Профиль не имеет права молча простаивать на чужом адаптере (EXT-A):
        # его исполняет только http_endpoint tier-1.
        raise ValueError(
            f"Сценарий {scenario.id}: target.profile поддерживается только adapter=http_endpoint "
            f"(EXT-A), эффективный adapter={adapter!r}"
        )
    return EffectiveTarget(adapter=adapter, base_url=base_url, profile=profile)


def apply_project_judge_defaults(scenario: Scenario, args=None, environ=None) -> None:
    """EXT-B (судья из конфигурации): единый КАНОНИЧЕСКИЙ порядок резолва судьи
    (задокументирован здесь и в LOG):

        1) явные флаги --judge-*  (применяются раньше, в cli._apply_judge_overrides);
        2) блок `judge:` сценария;
        3) дефолт ПРОЕКТА из окружения: MEMNOTSAFE_JUDGE_MODEL / _BASE_URL / _API_KEY_ENV;
        4) при отсутствии настроенной цели — человеческая ошибка ДО обращения к
           таргету (validate_judge_spec: enabled без model → RunnerError, exit 1).

    Захардкоженный OpenRouter больше НЕ активный молчаливый дефолт: он остаётся
    лишь инертным значением поля (сериализация/выключенный судья), но включённый
    судья без настроенной цели не уходит на OpenRouter молча — он падает
    человеческой ошибкой на шаге 4.

    Заполняем из проектного ENV ТОЛЬКО сценарии БЕЗ своего блока `judge:` и ТОЛЬКО
    поля, не заданные ни флагом, ни блоком (замок: judge-блоки и D1-пресет не
    ломаются — блок пропускается целиком, а флаги имеют приоритет)."""
    environ = os.environ if environ is None else environ
    if isinstance(scenario.raw.get("judge"), dict):
        return  # сценарий выбрал свой судью — не трогаем
    spec = scenario.judge

    def _flag(name: str):
        return getattr(args, name, None) if args is not None else None

    if not _flag("judge_model") and not spec.model:
        env_model = (environ.get("MEMNOTSAFE_JUDGE_MODEL") or "").strip()
        if env_model:
            spec.model = env_model
    if not _flag("judge_base_url"):
        env_base = (environ.get("MEMNOTSAFE_JUDGE_BASE_URL") or "").strip()
        if env_base:
            spec.base_url = env_base
    if not _flag("judge_api_key_env"):
        env_key = (environ.get("MEMNOTSAFE_JUDGE_API_KEY_ENV") or "").strip()
        if env_key:
            spec.api_key_env = env_key


def build_adapter(scenario: Scenario, target_override: str | None = None):
    """Резолвит TargetAdapter по ЕДИНОЙ эффективной цели (EXT-B). --target с CLI
    переопределяет base_url (или сам adapter, если передано имя известного
    адаптера) — не трогает атаку/сценарий. Тонкая обёртка над
    resolve_effective_target + build_adapter_from_effective: одна точка резолва."""
    return build_adapter_from_effective(scenario, resolve_effective_target(scenario, target_override))


def build_adapter_from_effective(scenario: Scenario, effective: EffectiveTarget):
    """Строит адаптер из уже разрешённой эффективной цели. Отдельная точка входа,
    чтобы вызывающий (cli) резолвил цель ОДИН раз и прокинул ту же EffectiveTarget
    в эксперимент/метаданные (совпадение адаптера и артефактов)."""
    from memnotsafe.adapters.mock import MockTarget

    adapter_name = effective.adapter
    base_url = effective.base_url

    if adapter_name == "mock":
        vulnerable = bool(scenario.target.extra.get("vulnerable", True))
        return MockTarget(vulnerable=vulnerable)

    if adapter_name in ("openai", "openai_compatible"):
        from memnotsafe.adapters.openai import OpenAICompatibleAdapter

        if not base_url:
            raise ValueError(f"Сценарию {scenario.id} нужен target.base_url или --target <url> для adapter=openai")
        return OpenAICompatibleAdapter(base_url=base_url, **scenario.target.extra)

    if adapter_name == "http_endpoint":
        from memnotsafe.adapters.http_endpoint import HttpEndpointAdapter

        if not base_url:
            raise ValueError(f"Сценарию {scenario.id} нужен target.base_url или --target <url> для adapter=http_endpoint")
        if effective.profile is not None:
            # EXT-A: отказ ДО прогона (G3) — cross-user без доказанной независимости
            # принципалов не строит адаптер и не читает ключ. Человекочитаемая
            # причина поднимается из profile.validate_for_actors.
            effective.profile.validate_for_actors(
                scenario.attacker.user_id, scenario.victim.user_id
            )
            return HttpEndpointAdapter(
                base_url=base_url,
                profile=effective.profile,
                model_name=scenario.target.extra.get("model_name", "target-agent"),
            )
        return HttpEndpointAdapter(base_url=base_url, **scenario.target.extra)

    if adapter_name == "investment_stand":
        from memnotsafe.adapters.investment_stand import InvestmentStandAdapter

        if not base_url:
            raise ValueError(f"Сценарию {scenario.id} нужен target.base_url или --target <url> для adapter=investment_stand")
        # FIX-C: reset_scope прокидывается ЯВНО. global — деструктивный сброс всех
        # коллекций: только по явному слову И с непустым target.reset_ack (защита
        # от опечатки и от унаследованного молчаливого global). Опечатку в самом
        # значении ловит конструктор адаптера (прецедент scope not in _RESET_SCOPES).
        reset_scope = scenario.reset_scope
        if reset_scope == "global":
            ack = str(scenario.target.extra.get("reset_ack", "") or "").strip()
            if not ack:
                raise ValueError(
                    f"Сценарий {scenario.id}: reset_scope=global — деструктивный сброс "
                    "ВСЕХ коллекций стенда (включая глобальный слой политик, предмет "
                    "G3.2). Требуется явное подтверждение target.reset_ack: <непустая "
                    "строка>. Иначе используйте reset_scope: namespace (по умолчанию) "
                    "— чистятся только свои сессии."
                )
        # scope — единственный источник reset_scope; исключаем scope/reset_ack из
        # extra, чтобы не было дубля kwarg и чтобы reset_ack не утёк в адаптер.
        extra = {k: v for k, v in scenario.target.extra.items() if k not in ("scope", "reset_ack")}
        return InvestmentStandAdapter(base_url=base_url, scope=reset_scope, **extra)

    raise ValueError(f"Неизвестный adapter={adapter_name!r} в сценарии {scenario.id}")
