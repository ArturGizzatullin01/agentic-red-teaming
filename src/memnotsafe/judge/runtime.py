"""src/memnotsafe/judge/runtime.py — LLMJudge: всё, что происходит вокруг
одного вызова модели (data-model §7, §8, §9; FR-012, FR-020).

Здесь живут три вещи, которых нет ни в клиенте, ни в разборе:

1. **Бюджет кампании.** Считается в HTTP-запросах, а не в стадиях: повтор при
   невалидном ответе стоит столько же, сколько первый вызов. Исчерпание не
   обрывает кампанию — оставшиеся стадии получают `unavailable`/
   `budget_exhausted`, и уже собранные случаи не пропадают.
2. **Деградация без обрыва.** Любой сбой сети превращается в вердикт с
   причиной, а не в исключение: сбой инструмента не делает результаты атаки
   недействительными (FR-020). Ошибки КОНФИГУРАЦИИ, наоборот, ловятся раньше —
   `validate_judge_spec` в core/config.py, до первого обращения к таргету.
3. **Артефакт вызова.** Полный вход (system, user с оградой и nonce), сырой
   ответ, каждая попытка и разобранный вердикт — то, по чему судейский вердикт
   перепроверяется постфактум без повторного прогона атаки (SC-007).

Судья вызывается на трёх стадиях ВСЕГДА и параллельно дословной проверке, в
том числе когда та уже сказала True: расхождение вердиктов — штатный сигнал
качества маркерных правил (FR-016/FR-019), а не исключительная ситуация.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from memnotsafe.core.config import JudgeSpec
from memnotsafe.core.models import JUDGED_STAGES, JudgeVerdict
from memnotsafe.judge.client import JudgeCallResult, JudgeClient
from memnotsafe.judge.prompt import build_prompt
from memnotsafe.judge.rubrics import Rubric, find_rubric
from memnotsafe.judge.verdict import VerdictParse, parse_judge_response, utc_now


class SupportsComplete(Protocol):
    """Контракт транспорта. Ровно он подменяется стабом в офлайн-тестах."""

    async def complete(self, system: str, user: str) -> JudgeCallResult: ...

    async def aclose(self) -> None: ...


@dataclass
class JudgeBudget:
    limit: int
    used: int = 0
    exhausted_at: str | None = None

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    def spend(self) -> None:
        self.used += 1


class LLMJudge:
    def __init__(
        self,
        spec: JudgeSpec,
        *,
        client: SupportsComplete | None = None,
        repetitions: int = 1,
        artifacts_dir: Path | None = None,
    ):
        self.spec = spec
        self.client: SupportsComplete = client or JudgeClient(
            model=spec.model or "",
            base_url=spec.base_url,
            api_key_env=spec.api_key_env,
            timeout_s=spec.timeout_s,
            temperature=spec.temperature,
        )
        self.budget = JudgeBudget(limit=spec.resolve_max_calls(repetitions))
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else None
        self.rubrics_used: set[str] = set()
        self.failures = 0
        self.outcome_counts: dict[str, int] = {}

    # ------------------------------------------------------------ публичное API

    async def evaluate_stages(
        self,
        *,
        case_id: str,
        expected_effect: dict[str, Any],
        artifact: str,
        baseline: str,
    ) -> dict[str, JudgeVerdict]:
        """Три вердикта на случай. `write`, `persistence` и `tool` сюда не
        попадают по построению: JUDGED_STAGES — единственный список стадий,
        которые судья вообще видит (FR-014)."""
        verdicts: dict[str, JudgeVerdict] = {}
        for stage in JUDGED_STAGES:
            verdict = await self.evaluate(
                stage=stage,
                case_id=case_id,
                expected_effect=expected_effect,
                artifact=artifact,
                baseline=baseline,
            )
            if verdict is not None:
                verdicts[stage] = verdict
        return verdicts

    async def evaluate(
        self,
        *,
        stage: str,
        case_id: str,
        expected_effect: dict[str, Any],
        artifact: str,
        baseline: str,
    ) -> JudgeVerdict | None:
        rubric = find_rubric(stage, expected_effect.get("type"))
        if rubric is None:
            return None  # звать судью не с чем: рубрики на эту пару нет

        self.rubrics_used.add(rubric.identifier)
        artifact_ref = f"judge/{case_id}-{stage}.json"

        # Пустой артефакт: оценивать нечего, вызов не делается, бюджет цел.
        if not artifact.strip():
            return self._record(
                JudgeVerdict(
                    stage=stage, outcome="skipped", model=self._model, rubric=rubric.identifier,
                    created_at=utc_now(), artifact_ref="", error="empty_artifact",
                )
            )

        if self.budget.exhausted:
            self.budget.exhausted_at = self.budget.exhausted_at or case_id
            return self._record(
                JudgeVerdict(
                    stage=stage, outcome="unavailable", model=self._model, rubric=rubric.identifier,
                    created_at=utc_now(), artifact_ref="", error="budget_exhausted",
                )
            )

        return self._record(
            await self._call_with_retries(
                stage=stage, case_id=case_id, rubric=rubric, artifact=artifact,
                baseline=baseline, artifact_ref=artifact_ref,
            )
        )

    def metadata(self) -> dict[str, Any]:
        """Блок `metadata.judge` при АКТИВНОМ судье (data-model §8). Форму для
        неактивного — ровно `{"active": false}` — собирает campaign.py: там же,
        где известно, что судьи не было вовсе (FR-013)."""
        return {
            "active": True,
            "model": self._model,
            "rubrics": sorted(self.rubrics_used),
            "min_confidence": self.spec.min_confidence,
            "calls_used": self.budget.used,
            "calls_limit": self.budget.limit,
            "budget_exhausted": self.budget.exhausted,
            "failures": self.failures,
            "outcomes": dict(sorted(self.outcome_counts.items())),
        }

    async def aclose(self) -> None:
        await self.client.aclose()

    # ------------------------------------------------------------ внутреннее

    @property
    def _model(self) -> str:
        return self.spec.model or ""

    async def _call_with_retries(
        self,
        *,
        stage: str,
        case_id: str,
        rubric: Rubric,
        artifact: str,
        baseline: str,
        artifact_ref: str,
    ) -> JudgeVerdict:
        prompt = build_prompt(
            stage=stage, rubric=rubric, artifact=artifact, baseline=baseline,
            max_artifact_chars=self.spec.max_artifact_chars,
        )
        attempts: list[dict[str, Any]] = []
        last_raw: dict[str, Any] | None = None
        last_parse: VerdictParse | None = None
        verdict: JudgeVerdict | None = None

        for n in range(1, self.spec.max_retries + 2):
            if self.budget.exhausted:
                # Бюджет кончился между повторами: фиксируем причину и выходим,
                # не делая запроса.
                self.budget.exhausted_at = self.budget.exhausted_at or case_id
                verdict = JudgeVerdict(
                    stage=stage, outcome="unavailable", model=self._model, rubric=rubric.identifier,
                    created_at=utc_now(), artifact_ref=artifact_ref, error="budget_exhausted",
                )
                attempts.append({"n": n, "status": None, "latency_ms": 0, "result": "unavailable",
                                 "error": "budget_exhausted"})
                break

            self.budget.spend()
            call = await self.client.complete(prompt.system, prompt.user)

            if not call.ok:
                self.failures += 1
                attempts.append({"n": n, "status": call.status, "latency_ms": call.latency_ms,
                                 "result": "unavailable", "error": call.error})
                verdict = JudgeVerdict(
                    stage=stage, outcome="unavailable", model=self._model, rubric=rubric.identifier,
                    created_at=utc_now(), artifact_ref=artifact_ref, error=call.error or "transport",
                )
                continue  # сетевой сбой повторяем, пока есть попытки и бюджет

            last_raw = call.raw
            last_parse = parse_judge_response(
                call.content,
                stage=stage,
                sent_artifact=prompt.sent_artifact,
                baseline=baseline,
                min_confidence=self.spec.min_confidence,
                model=self._model,
                rubric=rubric.identifier,
                artifact_ref=artifact_ref,
            )
            verdict = last_parse.verdict
            attempts.append({"n": n, "status": call.status, "latency_ms": call.latency_ms,
                             "result": verdict.outcome, "error": verdict.error or None})
            if not last_parse.retryable:
                break

        assert verdict is not None  # цикл делает минимум одну итерацию
        self._write_artifact(
            case_id=case_id, stage=stage, rubric=rubric, prompt=prompt, attempts=attempts,
            raw=last_raw, parse=last_parse, verdict=verdict,
        )
        return verdict

    def _record(self, verdict: JudgeVerdict) -> JudgeVerdict:
        self.outcome_counts[verdict.outcome] = self.outcome_counts.get(verdict.outcome, 0) + 1
        return verdict

    def _write_artifact(self, *, case_id, stage, rubric, prompt, attempts, raw, parse, verdict) -> None:
        """`runs/<name>/judge/<case_id>-<stage>.json`. Сырой ответ пишется даже
        когда разбор провалился: иначе причина `invalid_json` недоказуема.
        Секретов в артефакте нет — заголовки сюда не попадают."""
        if self.artifacts_dir is None:
            return
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "case_id": case_id,
            "stage": stage,
            "rubric": rubric.identifier,
            "model": self._model,
            "created_at": verdict.created_at,
            "artifact_truncated": prompt.truncation.to_dict(),
            "request": {
                "system": prompt.system,
                "user": prompt.user,
                "params": {"temperature": self.spec.temperature, "timeout_s": self.spec.timeout_s},
            },
            "attempts": attempts,
            "raw_response": raw,
            "parsed": parse.parsed if parse else None,
            "verdict": verdict.to_dict(),
        }
        (self.artifacts_dir / f"{case_id}-{stage}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
