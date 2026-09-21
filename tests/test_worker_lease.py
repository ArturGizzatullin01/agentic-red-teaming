"""tests/test_worker_lease.py — CARD-P13-a: файловый lease с TTL и fencing.

Замки (G3-SPEC §3, предложение 1; offline):

  1. эксклюзивность: живой замок — второй acquire немедленно отказан
     (политика отказа зафиксирована докстрингом worker.py);
  2. TTL честный: до истечения замок держит, после — не держит: acquire
     снимает orphan-замок и занимает место;
  3. fencing: токен нового держателя строго больше заменённого;
     release по УСТАРЕВШЕМУ токену — False и ничего не снимает;
  4. последовательные приобретения дают строго возрастающие токены;
  5. каталог замков создаётся конструктором.

Часы инжектируемые (норма VERDICT-P12): TTL морозится FuncClock — живых
таймеров в тесте нет. Импорт воркер-модуля внутри тестов: на чистой базе
карточки модуля нет — RED это падение конкретных тестов, а не collection
error всего файла (прецедент P12).
"""

from __future__ import annotations

from pathlib import Path


class FuncClock:
    """Ручные монотонные часы: тест двигает время явно."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def _lease_dir(tmp_path: Path) -> Path:
    return tmp_path / "locks"


def test_constructor_creates_lock_directory(tmp_path: Path) -> None:
    from memnotsafe.core.worker import FileLease

    clock = FuncClock()
    lease = FileLease(_lease_dir(tmp_path), clock=clock)
    assert lease.directory.is_dir()


def test_live_lock_rejects_second_acquire(tmp_path: Path) -> None:
    """Замок 1: живой замок — политика отказа, не ожидание."""
    from memnotsafe.core.worker import FileLease

    lease = FileLease(_lease_dir(tmp_path), clock=FuncClock())
    first = lease.acquire("reset", ttl=10.0)
    assert first is not None
    assert lease.acquire("reset", ttl=10.0) is None, "живой замок обязан отказать"


def test_lock_before_ttl_holds_exclusivity(tmp_path: Path) -> None:
    """Замок 2a: TTL честный — ДО истечения замок держит эксклюзивность."""
    from memnotsafe.core.worker import FileLease

    clock = FuncClock(start=0.0)
    lease = FileLease(_lease_dir(tmp_path), clock=clock)
    assert lease.acquire("reset", ttl=5.0) is not None
    clock.now = 4.999
    assert lease.acquire("reset", ttl=5.0) is None, "неистёкший замок снят раньше TTL"


def test_expired_lock_is_taken_over_with_greater_token(tmp_path: Path) -> None:
    """Замок 2b: истёкший/orphan замок не держит — новое acquire занимает
    место с НОВЫМ монотонным токеном (строго больше заменённого)."""
    from memnotsafe.core.worker import FileLease

    clock = FuncClock(start=0.0)
    lease = FileLease(_lease_dir(tmp_path), clock=clock)
    first = lease.acquire("reset", ttl=5.0)
    assert first is not None
    clock.now = 6.0
    second = lease.acquire("reset", ttl=5.0)
    assert second is not None, "истёкший замок обязан перекладываться"
    assert second.fencing_token > first.fencing_token


def test_stale_holder_release_rejected_after_takeover(tmp_path: Path) -> None:
    """Замок 3: устаревший держатель — fencing: release(старый токен) False,
    новый замок не снят (эксклюзивность по-прежнему у нового держателя)."""
    from memnotsafe.core.worker import FileLease

    clock = FuncClock(start=0.0)
    lease = FileLease(_lease_dir(tmp_path), clock=clock)
    first = lease.acquire("reset", ttl=5.0)
    assert first is not None
    clock.now = 6.0
    second = lease.acquire("reset", ttl=5.0)
    assert second is not None
    assert lease.release(first.fencing_token) is False, "устаревший токен принят"
    assert lease.acquire("reset", ttl=5.0) is None, "новый замок снят устаревшим release"
    assert lease.release(second.fencing_token) is True


def test_release_allows_reacquire(tmp_path: Path) -> None:
    """Корректный держатель освобождает — место сразу занимается."""
    from memnotsafe.core.worker import FileLease

    lease = FileLease(_lease_dir(tmp_path), clock=FuncClock())
    first = lease.acquire("reset", ttl=10.0)
    assert first is not None
    assert lease.release(first.fencing_token) is True
    second = lease.acquire("reset", ttl=10.0)
    assert second is not None
    assert second.fencing_token > first.fencing_token


def test_sequential_tokens_strictly_monotonic(tmp_path: Path) -> None:
    """Замок 4: последовательные приобретения — строго возрастающие токены."""
    from memnotsafe.core.worker import FileLease

    lease = FileLease(_lease_dir(tmp_path), clock=FuncClock())
    tokens = []
    for _ in range(3):
        held = lease.acquire("reset", ttl=1.0)
        assert held is not None
        tokens.append(held.fencing_token)
        assert lease.release(held.fencing_token) is True
    assert tokens[0] < tokens[1] < tokens[2], tokens


def test_fencing_token_exposed_on_lease(tmp_path: Path) -> None:
    """API-буква карточки: fencing_token доступен на объекте Lease."""
    from memnotsafe.core.worker import FileLease

    lease = FileLease(_lease_dir(tmp_path), clock=FuncClock())
    held = lease.acquire("reset", ttl=10.0)
    assert held is not None
    assert isinstance(held.fencing_token, int) and held.fencing_token >= 1
    assert held.expires_at == 10.0
