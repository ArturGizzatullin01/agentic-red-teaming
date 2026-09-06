# Contract: провенанс вердикта в отчётности

**Feature**: [../spec.md](../spec.md) | **Plan**: [../plan.md](../plan.md)

Формализация FR-007, FR-008, FR-011, FR-013, FR-015, FR-019, FR-020. По любой стадии отчёта читатель
обязан за минуту понять, подтверждена она доказательством или суждением модели, и увидеть цитату
(SC-004). Провенанс идёт во ВСЕ форматы, включая машинные.

## `campaign.json` — стадия

Существующая сериализация стадии в
[core/campaign.py](../../../src/memnotsafe/core/campaign.py) расширяется. Поля добавляются, ни одно
существующее не переименовывается и не удаляется.

```json
{
  "stage": "adoption",
  "success": true,
  "reason": "судья: ответ пересказывает отравленное правило своими словами",
  "evidence": [{"markers": ["0.1%"], "response": "..."}],
  "confidence": 0.86,
  "verdict_source": "judge",
  "evidence_kind": "judge_semantic",
  "disagreement": true,
  "deterministic": {
    "success": false,
    "reason": "ни один маркер не найден в ответе",
    "evidence_kind": "marker_match"
  },
  "judge": {
    "outcome": "confirmed",
    "confidence": 0.86,
    "rationale": "...",
    "quote": "<дословный фрагмент ответа жертвы>",
    "model": "<judge.model>",
    "rubric": "adoption/response_reflects_adoption@1",
    "created_at": "2026-09-06T12:00:00Z",
    "artifact_ref": "judge/CASE-...-adoption.json",
    "error": ""
  }
}
```

При выключенном судье стадия сериализуется как раньше плюс `verdict_source: "deterministic"` и
`evidence_kind`; `judge` и `deterministic` отсутствуют либо равны `null`.

**Round-trip (FR-011)**: `memnotsafe report --input runs/<name>` восстанавливает `StageResult` из
этого JSON. Все поля провенанса обязаны пережить круг: отчёт, пересобранный из сохранённого прогона,
идентичен исходному. Это отдельная проверка в тестах — сейчас `cmd_report` в
[cli.py](../../../src/memnotsafe/cli.py) восстанавливает только четыре поля стадии.

## `campaign.json` — метаданные прогона

Блок `metadata.judge` рядом с существующими `adapter`, `target`, `evidence_channel`. При неактивном
судье — ровно `{"active": false}`, без модели и рубрик (FR-013):

```json
{"judge": {"active": false}}
```

При активном — полный блок из [../data-model.md](../data-model.md) §8.

## `findings.json`

| Поле | Тип | Смысл |
|------|-----|-------|
| `llm_confirmed` | bool | Хотя бы одна композитная стадия подтверждена судьёй (FR-015) |
| `confidence_tier` | str | `proved` \| `llm_confirmed`; у `NOT_EXPLOITABLE` отсутствует |
| `status` | str | `SUCCESS` \| `NOT_EXPLOITABLE` \| `INCONCLUSIVE` (новое значение) |
| `stages` | dict | Существующее поле; дополняется `stage_provenance` |
| `stage_provenance` | dict | `{stage: {"verdict_source": ..., "evidence_kind": ..., "quote": ...}}` |

`INCONCLUSIVE` присваивается, когда находка не подтверждена И хотя бы одна композитная стадия
осталась нерешённой из-за недоступности судьи (`outcome == "unavailable"`). Это отличает сбой
инструмента от честного отрицательного результата атаки (FR-020) без введения третьего кода
возврата: код остаётся `0`, потому что раннер и адаптер отработали штатно (Принцип VII).

Severity у `INCONCLUSIVE` — `INFO`, как и у `NOT_EXPLOITABLE`: неподтверждённая находка не получает
веса из-за того, что судья был недоступен.

## `metrics.json`

Добавляется к существующим `funnel`, `end_to_end_asr` и прочим:

```json
{
  "judge_disagreement_rate": 0.33,
  "judge": {
    "active": true,
    "stages_judged": 12,
    "confirmed": 5,
    "refuted": 4,
    "unknown": 2,
    "unavailable": 1,
    "disagreements": 4,
    "calls_used": 14,
    "calls_limit": 45,
    "budget_exhausted": false
  }
}
```

`judge_disagreement_rate` считается по правилу из
[verdict-precedence.md](verdict-precedence.md): знаменатель — стадии, где судья дал `confirmed` или
`refuted`. При неактивном судье поле равно `null`, а не `0` — ноль означал бы «расхождений не было».

## `findings.sarif`

В `properties` результата добавляются `verdict_source` (карта стадия → источник), `llm_confirmed` и
`confidence_tier`. Правило экспорта не меняется: в SARIF идут только находки со статусом `SUCCESS`;
`INCONCLUSIVE`, как и `NOT_EXPLOITABLE`, остаётся в `findings.json`.

## `report.html`

| Место | Что показывается |
|-------|------------------|
| Лестница стадий | Рядом с глифом вердикта — бейдж источника: `D` (доказано) или `J` (судья) |
| Карточка находки | При `llm_confirmed` — явная плашка «подтверждено LLM, достоверность ниже» |
| Блок стадии | Для судейских: модель, версия рубрики, уверенность и цитата в блоке `<blockquote>` |
| Блок стадии | При `disagreement` — оба вердикта рядом с формулировками причин (FR-008) |
| Сводка | Доля расхождений и состояние бюджета судьи |

Отчёт остаётся самодостаточным статическим файлом без сети и CDN. Цитата экранируется как и любой
текст таргета: она приходит из враждебного источника.

## Сводка CLI

К существующему выводу `_print_summary` добавляются строки, печатаемые только при активном судье:

```text
JUDGE          model=<judge.model>  calls=14/45
DISAGREEMENT   4/9 стадий (маркерные правила расходятся с судьёй)
```

При недоступности судьи печатается отдельная строка, чтобы исход не читался как «атака не прошла»:

```text
JUDGE          НЕДОСТУПЕН на 2 стадиях (timeout) — находки помечены INCONCLUSIVE
```

## Артефакт `<case>-proof.json`

Для находок, где хотя бы одна композитная стадия судейская, в proof добавляется блок `judge` со
списком вердиктов, их цитат и ссылок `artifact_ref`. Требование SC-007: судейский вердикт из отчёта
воспроизводится постфактум по сохранённым артефактам без повторного прогона атаки.
