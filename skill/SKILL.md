# memnotsafe pilot — one-command memory red-team pilot

Run a first, honest red-team pass against your own LLM endpoint (an
OpenAI-compatible chat API) and get a business-readable report — in one command.
This is a **tier-1** pilot: it drives your endpoint as a black box (URL + key),
so it never invents observability it does not have. When a channel cannot be
observed, the report says **UNKNOWN**, never "safe".

## 1. Install

```
pip install -e .          # from the memnotsafe checkout
memnotsafe --help         # sanity check
```

## 2. Provide your endpoint key (via environment only)

The pilot reads your endpoint key **only** from an environment variable — never
from a file, the config, or the command line. Put the value in your shell (or a
local `.env` that you do not commit):

```
export MEMNOTSAFE_TARGET_API_KEY=<your-endpoint-key>
```

The config file stores only the **name** of this variable, never the value.

## 3. Create a config

```
memnotsafe pilot --init            # writes ./pilot.yaml + prints the next step
```

Open `pilot.yaml` and fill in your endpoint:

```yaml
version: 1
target:
  adapter: http_endpoint
  # Host ROOT, WITHOUT /v1 — the pilot posts to <base_url>/v1/chat/completions.
  base_url: "https://your-endpoint.example"
  model: "your-model-name"
  api_key_env: MEMNOTSAFE_TARGET_API_KEY          # variable NAME only
budget_cap: 20      # max pilot runs against your endpoint (required)
iterations: 1
```

`budget_cap` is mandatory — it is the ceiling on how much the pilot will exercise
your endpoint.

**Watch the `base_url`:** give the host root (no trailing `/v1`). The pilot sends
requests to `<base_url>/v1/chat/completions`, so a `base_url` that already ends in
`/v1` becomes `/v1/v1/...` and the endpoint returns 404 (the probe reports it).

## 4. Run the pilot

```
memnotsafe pilot --config pilot.yaml --output runs/pilot-run
```

The pilot chains: build the endpoint adapter → **probe** (is it reachable, what
can be observed) → **preflight** (what will be measured) → run a small **starter
pack** of checks drawn from the built-in registry → render
**`runs/pilot-run/threat-report.html`** → print a console summary (verdict stamp,
`N of M` proven, report path).

Common, human-readable stops (no stack traces):

- **key not set** → the pilot tells you which environment variable to export;
- **endpoint unreachable** → the pilot prints the probe reason (check `base_url`);
- **missing `budget_cap`** → the pilot tells you to add it.

## 5. Read the report

Open `runs/pilot-run/threat-report.html`. The headline **stamp** is one of:

- `COMPROMISE PROVEN` — a check proved an end-to-end memory compromise;
- `COMPROMISE NOT PROVEN` — a check was deterministically disproved;
- `INCONCLUSIVE` — the outcome could not be observed. For a tier-1 black-box
  endpoint this is expected and honest: **INCONCLUSIVE is not "safe"** — the
  attack ran, but without memory observability the result cannot be certified.

`N of M` counts proven compromises out of attempts.

## 6. Re-test after a fix (retest)

After you change your endpoint or its guardrails, run again and compare against
the previous pilot directory:

```
memnotsafe pilot --config pilot.yaml --output runs/pilot-run-2 --baseline runs/pilot-run
```

The retest section reports each case as **FIXED**, **STILL VULNERABLE**, **NEW**,
or **UNKNOWN**. Note the safety rule: a case that is now **UNKNOWN** is **never**
reported as FIXED — you cannot certify a fix you cannot observe. On a tier-1
endpoint (no memory observability), retest results are typically UNKNOWN by
design; certifying FIXED needs an observable target.

## Notes

- No secrets are ever written to reports, configs, or the console — only
  environment-variable **names** appear.
- The pilot reuses the same engine, preflight and report renderer as the rest of
  the toolkit; it does not add new attacks.
