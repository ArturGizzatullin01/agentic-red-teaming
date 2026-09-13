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
чужую schema_version, пути вне пакета и любое несовпадение sha256. Старые
runs без каталога bundles/ читаются как «пакетов нет» (find_bundles → {}),
никакие поля за читателя не выдумываются. Replay работает без target и без
вызовов моделей — пакет это данные, а не живой канал.

Секреты в манифест не попадают по построению: пишутся только поля,
переданные вызывающим слоем явно (идентификаторы, статусы, checksums).
"""

from __future__ import annotations

import hashlib
import json
import os
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

STATUS_PRESENT = "present"
STATUS_ABSENT = "absent"
STATUS_UNAVAILABLE = "unavailable"


class BundleError(ValueError):
    """Контрактное нарушение пакета: незавершён, чужая версия, путь вне пакета,
    повреждённый или подменённый артефакт. Диагностическая ошибка, не краш."""


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
    for slot in sorted(mentioned):
        if slot not in BUNDLE_SLOTS:
            raise BundleError(f"неизвестный слот пакета: {slot!r} (известные: {list(BUNDLE_SLOTS)})")
        name = f"{slot}.json"
        rel = f"artifacts/{name}"
        target = bundle_dir / rel
        payload = payloads.get(slot)
        source = files.get(slot)
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


def read_bundle(bundle_dir: str | Path, *, verify: bool = True) -> EvidenceBundle:
    """Читает и верифицирует пакет. Любое нарушение целостности/контракта —
    BundleError с именем слота; «тихо починить» подменённый файл нельзя."""
    bundle_dir = Path(bundle_dir)
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        raise BundleError(f"пакет {bundle_dir}: manifest.json отсутствует — пакет незавершён")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"пакет {bundle_dir}: манифест не читается: {exc}") from exc
    if raw.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise BundleError(
            f"пакет {bundle_dir}: schema_version={raw.get('schema_version')!r} не поддерживается "
            f"(ожидается {BUNDLE_SCHEMA_VERSION})"
        )
    if not raw.get("sealed"):
        raise BundleError(f"пакет {bundle_dir}: манифест не запечатан — пакет незавершён")

    slots: dict[str, SlotRecord] = {}
    for name, slot_raw in (raw.get("slots") or {}).items():
        rec = SlotRecord.from_dict(slot_raw)
        if rec.status == STATUS_PRESENT:
            if not rec.path:
                raise BundleError(f"пакет {bundle_dir}: слот {name!r} present без пути")
            artifact = _safe_rel_path(bundle_dir, rec.path)
            if not artifact.exists():
                raise BundleError(f"пакет {bundle_dir}: артефакт слота {name!r} отсутствует: {rec.path}")
            if verify and rec.sha256 and _sha256_file(artifact) != rec.sha256:
                raise BundleError(
                    f"пакет {bundle_dir}: артефакт слота {name!r} повреждён или подменён "
                    f"(sha256 не совпал: {rec.path})"
                )
        slots[name] = rec

    return EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        run_id=str(raw.get("run_id") or ""),
        case_id=str(raw.get("case_id") or ""),
        attempt_no=int(raw.get("attempt_no") or 1),
        experiment_id=raw.get("experiment_id"),
        candidate_id=raw.get("candidate_id"),
        parent_candidate_id=raw.get("parent_candidate_id"),
        goal_digest=raw.get("goal_digest"),
        slots=slots,
        sealed=True,
    )


def find_bundles(run_dir: str | Path) -> dict[str, Path]:
    """Каталог пакетов прогона: {case_id: путь пакета}. Нет каталога (старый
    run) → пустой словарь; каталог есть, но манифеста в подпапке нет → подпапка
    НЕ попадает в результат (незавершённый пакет не маскируется под готовый)."""
    bundles_dir = Path(run_dir) / "bundles"
    if not bundles_dir.is_dir():
        return {}
    found: dict[str, Path] = {}
    for child in sorted(bundles_dir.iterdir()):
        if child.is_dir() and (child / "manifest.json").exists():
            found[child.name] = child
    return found


def verify_run_bundles(run_dir: str | Path) -> int:
    """Полная верификация пакетов прогона (checksums, seal, пути); возвращает
    число проверенных пакетов. Любое нарушение → BundleError. Незавершённые
    каталоги (без манифеста) верификацию не проходят молча: find_bundles их
    не считает завершёнными, а attempt-history/отчёт решают, как их показать."""
    bundles = find_bundles(run_dir)
    for path in bundles.values():
        read_bundle(path)
    return len(bundles)
