# memnotsafe · Mission Control (`console/`)

A static, **offline, read-only** web console for inspecting memnotsafe run
artifacts. It renders the JSON/HTML a run already produces — it does not run
attacks, does not touch a live target, and performs **no network I/O**.

## What it reads

Everything comes from a `runs/<name>/` directory produced by `memnotsafe`:

| Artifact | Producer | Used for |
|---|---|---|
| `campaign.json` | `core/campaign_serialize.py` | run identity, `aggregate_metrics.funnel`, per-case stage verdicts |
| `findings.json` | `reporting/findings.py` | case status (`SUCCESS` / `NOT_EXPLOITABLE` / `INCONCLUSIVE`), severity, ATT&CK / OWASP mapping |
| `attempts.jsonl` | `core/attempt.py` | attempt-history roll-up (outcomes, candidates, transport retries) |
| `budget-ledger.jsonl` | `core/ledger.py` | budget roll-up (operations, blocked, `usage=null` → *unknown*) |
| `report.html` | `reporting/html_report.py` | linked / previewed full report |
| `threat-report.html` | `reporting/threat_report.py` | linked / previewed business report (when present) |

Only `campaign.json` is required; every other artifact degrades gracefully and
its absence is surfaced as an "artifact note", never hidden.

## Doctrine — the reason this exists

A stage verdict is **pass**, **fail**, or **UNKNOWN** (the artifacts store this
as `true` / `false` / `null`). The console keeps all three distinct:

- **UNKNOWN ≠ safe** — an unobserved stage is not a passed control. It is drawn
  amber, and a run with any unknown stage never reads as "controlled".
- **UNKNOWN ≠ exploited** — an unobserved stage is not a confirmed exploit. It
  is tracked on its own axis and never inflates ASR.

The ASR denominator stays the completed **cases** from `campaign.json`; attempt
records (which can exceed cases under escalation) are only summarized
descriptively.

## Views

- **Gallery** — every run as a card with stamps (run id, target, case count,
  end-to-end ASR, top severity, verdict, unknown-stage count).
- **Run page** — metrics, the six-stage kill-chain funnel (tri-state bars),
  a per-case table (status / severity / stage tri-dots / ATT&CK+OWASP mapping),
  attempt and budget roll-ups, and previews/links to the full HTML reports.
- **Load your own run** — pick a local `runs/<name>/` set of files in the
  browser (FileReader only; nothing is uploaded) and view it with the same UI.

## Fixtures

`fixtures/` holds real runs generated with `memnotsafe campaign --target mock`
(synthetic offline data only — no live memory, no secrets):

- `run-cross-user-bac-vulnerable` — full chain succeeds → **EXPLOITED**.
- `run-cross-user-bac-protected` — external effect blocked → **CONTROLLED**.
- `run-tool-route-hijack-skipped` — adoption/tool unobserved → **INCONCLUSIVE**
  (ASR 0% but *not* safe — the UNKNOWN ≠ safe case).

## Develop

```bash
cd console
npm install
npm run dev        # local dev server
npm run build      # type-check + production build to dist/
npm run preview    # serve the built dist/
npm test           # vitest smoke tests (parser, tri-state doctrine, render)
```

The build is self-contained and `base` is relative, so `dist/` can be served
from any path or opened over `file://`.
