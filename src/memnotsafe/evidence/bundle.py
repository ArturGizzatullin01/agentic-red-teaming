"""src/memnotsafe/evidence/bundle.py — файловый пакет доказательств попытки
(P10a, фича 007).

Пакет = каталог `runs/<name>/bundles/<case_id>/` с артефактами в `artifacts/`
и `manifest.json`, который пишется ПОСЛЕДНИМ и атомарно (tmp + os.replace).
Манифест содержит schema_version, идентификаторы попытки, слоты доказательств
с состояниями и sha256 каждого артефакта.

Состояния слота — три, и они НЕ взаимозаменяемы:
- `present`     — артефакт в пакете, checksum совпадает;
- `absent`      — слот для этой попытки не предусмотрен (например, у атаки
                  нет tool-фазы); это НЕ утверждение о телеметрии;
- `unavailable` — слот предусмотрен, но телеметрия его не наблюдала (снимок
                  не удался, событий нет). Отсутствие наблюдения НЕ превращается
                  в доказанное отсутствие события (Принцип IV).

Чтение (`read_bundle`) отклоняет: отсутствующий/незавершённый манифест,
чужую schema_version, некорректные типы/диапазоны полей, пути вне пакета и
любое несовпадение sha256/размера. Старые runs без каталога bundles/ читаются
как «пакетов нет» (find_bundles → {}), никакие поля за читателя не
выдумываются. Replay работает без target и без вызовов моделей — пакет это
данные, а не живой канал.

Граница честности: sha256/размер доказывают целостность и ловят случайную
порчу и наивную подмену ФАЙЛА, но не криптографическую подлинность —
злоумышленник, переписавший и артефакт, и манифест с новым checksum, будет
пройден. Подпись/внешнее доверенное хранилище — вне скоупа фичи 007.

Секреты в манифест не попадают по построению: пишутся только поля,
переданные вызывающим слоем явно (идентификаторы, статусы, checksums).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

BUNDLE_SCHEMA_VERSION = 1

# Слоты пакета. m0–m3 — фазовые снимки (P06); transcript — журнал диалога;
# settle — исход ожидания записи (P05); candidate —payload/trigger/цель;
# memory_diff — диф M0→M1 (канал записи); tool_events — события вызовов
# инструмента кейса; trace — трасса кейса.
BUNDLE_SLOTS = (
    "m0", "m1", "m2", "m3",
    "transcript", "settle", "candidate", "memory_diff", "tool_events", "trace",
)

# Опциональные слоты (P09-full, фича 010): новый пакет перечисляет их всегда,
# но ИСТОРИЧЕСКИЙ манифест без них остаётся валидным — при чтении такой слот
# нормализуется в `absent` («не предусмотрен», не утверждение о телеметрии).
# Семантика present/absent/unavailable — та же, что у обязательных слотов;
# present обязан иметь path/sha256/bytes.
BUNDLE_SLOTS_OPTIONAL = ("context_tool_evidence",)

STATUS_PRESENT = "present"
STATUS_ABSENT = "absent"
STATUS_UNAVAILABLE = "unavailable"


class BundleError(ValueError):
    """Контрактное нарушение пакета: незавершён, чужая версия, путь вне пакета,
    повреждённый или подменённый артефакт. Диагностическая ошибка, не краш."""


# sha256 в манифесте — только 64 hex-символа в нижнем регистре (формат
# hashlib.hexdigest); верхний регистр/короткие/нечислобуквенные — отказ.
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class SlotRecord:
    status: str
    path: str | None = None      # относительный путь ВНУТРИ пакета
    sha256: str | None = None
    bytes: int | None = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.bytes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SlotRecord":
        return cls(
            status=str(data.get("status")),
            path=data.get("path"),
            sha256=data.get("sha256"),
            bytes=data.get("bytes"),
        )


@dataclass
class EvidenceBundle:
    """Прочитанный/записанный пакет. `sealed` означает: кампания завершила
    попытку, манифест записан атомарно и полный."""

    schema_version: int
    run_id: str
    case_id: str
    attempt_no: int
    experiment_id: str | None
    candidate_id: str | None
    parent_candidate_id: str | None
    goal_digest: str | None
    slots: dict[str, SlotRecord] = field(default_factory=dict)
    sealed: bool = False

    def manifest(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "kind": "evidence_bundle",
            "run_id": self.run_id,
            "case_id": self.case_id,
            "attempt_no": self.attempt_no,
            "experiment_id": self.experiment_id,
            "candidate_id": self.candidate_id,
            "parent_candidate_id": self.parent_candidate_id,
            "goal_digest": self.goal_digest,
            "sealed": self.sealed,
            "slots": {name: rec.to_dict() for name, rec in sorted(self.slots.items())},
        }

    def present(self, slot: str) -> bool:
        rec = self.slots.get(slot)
        return bool(rec and rec.status == STATUS_PRESENT)


def write_bundle(
    bundle_dir: str | Path,
    *,
    run_id: str,
    case_id: str,
    attempt_no: int = 1,
    experiment_id: str | None = None,
    candidate_id: str | None = None,
    parent_candidate_id: str | None = None,
    goal_digest: str | None = None,
    payloads: dict[str, object | None] | None = None,
    files: dict[str, Path | None] | None = None,
) -> EvidenceBundle:
    """Собирает пакет: артефакты → artifacts/<slot>.json (или копия файла),
    затем манифест с sealed=True атомарно последним.

    Семантика слотов: значение None в payloads/files (слот упомянут, но
    телеметрии нет) → `unavailable`; слот, не упомянутый вовсе, → `absent`.
    Имена артефактов производятся только от имён слотов — пользовательские
    пути в пакет не попадают."""

    bundle_dir = Path(bundle_dir)
    artifacts_dir = bundle_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    payloads = payloads or {}
    files = files or {}

    slots: dict[str, SlotRecord] = {}
    mentioned = set(payloads) | set(files)
    known_slots = tuple(BUNDLE_SLOTS) + tuple(BUNDLE_SLOTS_OPTIONAL)
    for slot in sorted(mentioned):
        if slot not in known_slots:
            raise BundleError(f"неизвестный слот пакета: {slot!r} (известные: {list(known_slots)})")
        name = f"{slot}.json"
        rel = f"artifacts/{name}"
        target = bundle_dir / rel
        payload = payloads.get(slot)
        source = files.get(slot)
        if slot == "context_tool_evidence" and payload is not None:
            # fail-fast: структурно неверную запись телеметрии не оставляем в
            # пакете — она стала бы «доказательством», которое replay отвергнет
            from memnotsafe.evidence.telemetry import TelemetryError, parse_context_tool_evidence

            try:
                payload = parse_context_tool_evidence(payload)
            except TelemetryError as exc:
                raise BundleError(f"слот context_tool_evidence нарушает контракт телеметрии: {exc}") from exc
        if payload is not None:
            target.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8",
            )
        elif source is not None:
            if not Path(source).exists():
                slots[slot] = SlotRecord(status=STATUS_UNAVAILABLE)
                continue
            target.write_bytes(Path(source).read_bytes())
        else:
            slots[slot] = SlotRecord(status=STATUS_UNAVAILABLE)
            continue
        slots[slot] = SlotRecord(
            status=STATUS_PRESENT,
            path=rel,
            sha256=_sha256_file(target),
            bytes=target.stat().st_size,
        )
    for slot in BUNDLE_SLOTS:
        slots.setdefault(slot, SlotRecord(status=STATUS_ABSENT))
    # опциональные слоты новый пакет перечисляет всегда (единообразие манифеста)
    for slot in BUNDLE_SLOTS_OPTIONAL:
        slots.setdefault(slot, SlotRecord(status=STATUS_ABSENT))

    bundle = EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        run_id=run_id,
        case_id=case_id,
        attempt_no=attempt_no,
        experiment_id=experiment_id,
        candidate_id=candidate_id,
        parent_candidate_id=parent_candidate_id,
        goal_digest=goal_digest,
        slots=slots,
        sealed=True,
    )
    # Манифест — ПОСЛЕДНИМ и атомарно: пакет без манифеста (сбой до replace)
    # читателем за завершённый не выдаётся.
    tmp = bundle_dir / "manifest.json.tmp"
    tmp.write_text(json.dumps(bundle.manifest(), ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, bundle_dir / "manifest.json")
    return bundle


def _safe_rel_path(bundle_dir: Path, rel: str) -> Path:
    """Путь артефакта обязан оставаться внутри пакета: без абсолютных форм,
    без «..», без выхода за корень каталога (защита от подмены манифеста)."""
    candidate = (bundle_dir / rel)
    resolved_root = bundle_dir.resolve()
    resolved = candidate.resolve()
    if not str(resolved).startswith(str(resolved_root) + os.sep):
        raise BundleError(f"путь артефакта вне пакета запрещён: {rel!r}")
    return candidate


def _validate_slot_record(bundle_dir: Path, name: str, rec: SlotRecord) -> None:
    """ОБЯЗАТЕЛЬНАЯ валидация записи слота в манифесте (фикс приёмки P1):
    present без path/sha256/bytes, неизвестный статус или неизвестное имя
    слота — контрактное нарушение, а не «пропуск проверки checksum».
    Фикс приёмки P2: строгие типы и диапазоны — sha256 только нижний hex-64,
    bytes только неотрицательное целое."""
    known_slots = tuple(BUNDLE_SLOTS) + tuple(BUNDLE_SLOTS_OPTIONAL)
    if name not in known_slots:
        raise BundleError(f"пакет {bundle_dir}: неизвестный слот {name!r} в манифесте")
    if rec.status not in (STATUS_PRESENT, STATUS_ABSENT, STATUS_UNAVAILABLE):
        raise BundleError(f"пакет {bundle_dir}: слот {name!r}: неизвестный статус {rec.status!r}")
    if rec.status == STATUS_PRESENT:
        if not rec.path:
            raise BundleError(f"пакет {bundle_dir}: слот {name!r} present без пути — манифест неполон")
        if (
            not isinstance(rec.sha256, str)
            or _SHA256_RE.fullmatch(rec.sha256) is None
        ):
            raise BundleError(
                f"пакет {bundle_dir}: слот {name!r} present с некорректным sha256 "
                "(ожидается 64 hex-символа в нижнем регистре) — манифест неполон"
            )
        if isinstance(rec.bytes, bool) or not isinstance(rec.bytes, int) or rec.bytes < 0:
            raise BundleError(
                f"пакет {bundle_dir}: слот {name!r} present с некорректным размером "
                f"{rec.bytes!r} (ожидается неотрицательное целое) — манифест неполон"
            )


def read_bundle(bundle_dir: str | Path, *, verify: bool = True) -> EvidenceBundle:
    """Читает и верифицирует пакет. Манифест валидируется ЦЕЛИКОМ (статусы,
    пути, обязательные sha256), затем каждый present-артефакт перепроверяется
    по checksum. Любое нарушение — BundleError с именем слота; «тихо починить»
    подменённый или недоописанный манифест нельзя."""
    bundle_dir = Path(bundle_dir)
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        raise BundleError(f"пакет {bundle_dir}: manifest.json отсутствует — пакет незавершён")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"пакет {bundle_dir}: манифест не читается: {exc}") from exc
    if not isinstance(raw, dict):
        raise BundleError(
            f"пакет {bundle_dir}: манифест обязан быть JSON-объектом, получено {type(raw).__name__}"
        )
    if raw.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise BundleError(
            f"пакет {bundle_dir}: schema_version={raw.get('schema_version')!r} не поддерживается "
            f"(ожидается {BUNDLE_SCHEMA_VERSION})"
        )
    if not raw.get("sealed"):
        raise BundleError(f"пакет {bundle_dir}: манифест не запечатан — пакет незавершён")
    if not raw.get("kind") == "evidence_bundle":
        raise BundleError(f"пакет {bundle_dir}: чужой манифест (kind={raw.get('kind')!r})")
    if not str(raw.get("run_id") or "") or not str(raw.get("case_id") or ""):
        raise BundleError(f"пакет {bundle_dir}: run_id/case_id обязательны — манифест неполон")
    raw_attempt_no = raw.get("attempt_no")
    if isinstance(raw_attempt_no, bool) or not isinstance(raw_attempt_no, int) or raw_attempt_no < 0:
        raise BundleError(
            f"пакет {bundle_dir}: attempt_no={raw_attempt_no!r} — ожидается неотрицательное целое"
        )

    slots: dict[str, SlotRecord] = {}
    for name, slot_raw in (raw.get("slots") or {}).items():
        if not isinstance(slot_raw, dict):
            raise BundleError(f"пакет {bundle_dir}: слот {name!r} — запись манифеста обязана быть объектом")
        rec = SlotRecord.from_dict(slot_raw)
        _validate_slot_record(bundle_dir, name, rec)
        if rec.status == STATUS_PRESENT:
            artifact = _safe_rel_path(bundle_dir, rec.path)
            if not artifact.exists():
                raise BundleError(f"пакет {bundle_dir}: артефакт слота {name!r} отсутствует: {rec.path}")
            if verify:
                # Фактический размер сверяется с заявленным ДО checksum: подмена
                # контента с пересчитанным манифестом ловится sha256, усечение/
                # дозапись с НЕпересчитанным манифестом — размером (фикс P2).
                if artifact.stat().st_size != rec.bytes:
                    raise BundleError(
                        f"пакет {bundle_dir}: артефакт слота {name!r} не совпадает по размеру "
                        f"с манифестом ({artifact.stat().st_size} != {rec.bytes}): {rec.path}"
                    )
                if _sha256_file(artifact) != rec.sha256:
                    raise BundleError(
                        f"пакет {bundle_dir}: артефакт слота {name!r} повреждён или подменён "
                        f"(sha256 не совпал: {rec.path})"
                    )
            if rec.status == STATUS_PRESENT and verify and name == "context_tool_evidence":
                # P09-full: структурная проверка содержимого телеметрии ПОСЛЕ
                # checksum — ловит нарушение контракта (пустой/дублирующийся
                # call_id, чужую фазу, неизвестные ключи) даже при пересчитанном
                # манифесте; это структурный контракт, не криптографическая
                # подлинность (её граница — в докстринге модуля).
                from memnotsafe.evidence.telemetry import TelemetryError, parse_context_tool_evidence

                try:
                    parsed = json.loads(artifact.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise BundleError(
                        f"пакет {bundle_dir}: артефакт слота {name!r} не читается как JSON: {exc}"
                    ) from exc
                try:
                    parse_context_tool_evidence(parsed)
                except TelemetryError as exc:
                    raise BundleError(
                        f"пакет {bundle_dir}: артефакт слота {name!r} нарушает контракт телеметрии: {exc}"
                    ) from exc
        slots[name] = rec
    missing_required = [s for s in BUNDLE_SLOTS if s not in slots]
    if missing_required:
        raise BundleError(
            f"пакет {bundle_dir}: слоты не перечислены в манифесте: {missing_required} — манифест неполон"
        )
    # Исторический пакет без опционального слота валиден: слот «не предусмотрен».
    # Это нормализация читателя, не утверждение о телеметрии (≠ unavailable).
    for slot in BUNDLE_SLOTS_OPTIONAL:
        slots.setdefault(slot, SlotRecord(status=STATUS_ABSENT))

    return EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        run_id=str(raw.get("run_id") or ""),
        case_id=str(raw.get("case_id") or ""),
        attempt_no=raw_attempt_no,
        experiment_id=raw.get("experiment_id"),
        candidate_id=raw.get("candidate_id"),
        parent_candidate_id=raw.get("parent_candidate_id"),
        goal_digest=raw.get("goal_digest"),
        slots=slots,
        sealed=True,
    )


def find_bundles(run_dir: str | Path) -> dict[str, Path]:
    """Завершённые пакеты прогона: {candidate_id: путь пакета}. Каталог без
    manifest.json сюда НЕ попадает (незавершённый ≠ завершённый); его
    обнаруживает verify_run_bundles / bundle_states, а не молчаливый пропуск."""
    bundles_dir = Path(run_dir) / "bundles"
    if not bundles_dir.is_dir():
        return {}
    return {
        child.name: child
        for child in sorted(bundles_dir.iterdir())
        if child.is_dir() and (child / "manifest.json").exists()
    }


def bundle_states(run_dir: str | Path) -> dict[str, str]:
    """Состояние каждого каталога пакетов прогона: 'complete' | 'incomplete'.
    Незавершённые каталоги (нет манифеста) ЯВНО видимы — их нельзя перепутать
    с отсутствием пакетов у исторического run."""
    bundles_dir = Path(run_dir) / "bundles"
    if not bundles_dir.is_dir():
        return {}
    states: dict[str, str] = {}
    for child in sorted(bundles_dir.iterdir()):
        if child.is_dir():
            states[child.name] = "complete" if (child / "manifest.json").exists() else "incomplete"
    return states


def verify_run_bundles(run_dir: str | Path) -> int:
    """Полная верификация пакетов прогона (обязательные sha256, checksums,
    seal, пути); возвращает число завершённых пакетов. Незавершённый каталог
    — BundleError «незавершённый пакет» (replay не вправе его прозевать);
    отсутствие каталога bundles/ целиком (исторический run) — 0, не ошибка."""
    states = bundle_states(run_dir)
    incomplete = [name for name, state in states.items() if state == "incomplete"]
    if incomplete:
        raise BundleError(f"незавершённый пакет: bundles/{incomplete[0]} (manifest.json отсутствует)")
    for path in (Path(run_dir) / "bundles" / name for name in sorted(states)):
        read_bundle(path)
    return len(states)


def verify_run_evidence(run_dir: str | Path) -> int:
    """Полная проверка доказательственной базы прогона (фикс приёмки P1-2):
    (а) верификация всех пакетов — verify_run_bundles; (б) сверка с историей
    попыток: evidence_error в attempts.jsonl (в т.ч. сбой ДО создания каталога
    пакета, когда verеfi_run_bundles видно лишь пустоту) и завершённая попытка
    без пакета — BundleError. Возвращает число завершённых пакетов."""
    count = verify_run_bundles(run_dir)
    from memnotsafe.core.attempt import (
        COMPLETED_OUTCOMES,
        OUTCOME_EVIDENCE_ERROR,
        read_history,
    )

    from memnotsafe.core.attempt import AttemptHistoryError

    try:
        entries = read_history(Path(run_dir) / "attempts.jsonl")
    except AttemptHistoryError as exc:
        raise BundleError(str(exc)) from exc
    failed = [e for e in entries if e.outcome == OUTCOME_EVIDENCE_ERROR]
    if failed:
        raise BundleError(
            f"пакет доказательств не записан для {failed[0].candidate_id}: {failed[0].error}"
        )
    completed = [
        e for e in entries
        if e.attempt_no >= 1 and e.outcome in COMPLETED_OUTCOMES
    ]
    missing = [
        e.candidate_id for e in completed
        if not (Path(run_dir) / "bundles" / e.candidate_id / "manifest.json").exists()
    ]
    if missing:
        raise BundleError(
            f"у завершённой попытки нет пакета доказательств: bundles/{missing[0]}"
        )
    # Согласованность манифеста с историей (Этап 3, фикс аудита): не только
    # существование файла — идентификаторы и номер попытки обязаны совпадать.
    for rec in completed:
        bundle = read_bundle(Path(run_dir) / "bundles" / rec.candidate_id)
        if (
            bundle.candidate_id != rec.candidate_id
            or bundle.case_id != rec.case_id
            or bundle.attempt_no != rec.attempt_no
        ):
            raise BundleError(
                f"манифест bundles/{rec.candidate_id} не согласован с attempts.jsonl "
                f"(manifest: case={bundle.case_id!r} candidate={bundle.candidate_id!r} "
                f"attempt_no={bundle.attempt_no}; history: case={rec.case_id!r} "
                f"attempt_no={rec.attempt_no})"
            )
    return count
