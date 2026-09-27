---
name: memnotsafe-operator
description: "Use when someone asks Claude to understand or operate the memnotsafe project: inspect the CLI, run an offline mock smoke check, prepare a pilot against a third-party OpenAI-compatible endpoint (target profile), configure the LLM judge, manage the local Docker stand, or read a threat-report."
---

# memnotsafe operator

Help the user work with the memnotsafe CLI (agentic-memory red teaming — it attacks an
agent's long-term memory across sessions, not a single prompt→response). Ground every
command in the checkout and CLI version actually available on their machine. This skill
supplies a workflow; it does not install the project, grant Docker access, or supply
credentials.

## First check

1. Locate the intended checkout by its `pyproject.toml` and `src/memnotsafe/` directory.
   Never assume a username, drive, or fixed path.
2. Read its README and `memnotsafe --help`. Check the active package with
   `python -c "import memnotsafe; print(memnotsafe.__file__)"`; flag an editable install
   that points at a different checkout.
3. The top-level commands on current main are: `probe`, `preflight`, `run`, `campaign`,
   `orchestrate`, `generate`, `report`, `judge-calibrate`, `replay`, `threat-report`,
   `go`, `pilot`, `stand`. Before recommending `go`, `pilot`, or `stand`, confirm them
   with `memnotsafe go --help` / `pilot --help` / `stand --help`. If one is absent, say
   this installed version does not provide it — do not invent flags.
4. State the selected branch or version, the target type (`mock`, `http_endpoint`,
   `openai`/`openai_compatible`, or `investment_stand`), and whether the proposed step
   uses a live endpoint.

## Safe default

- For orientation, read project files and explain available commands. An offline mock run
  is a smoke check only — never present it as proof about a live target.
- Treat `INCONCLUSIVE` / `UNKNOWN` as a visibility limit, never as a clean bill of health.
  So is `NOT PROVEN`: the attack ran and the observed chain broke, but what was written
  before the break may still sit in memory (see **Reading a threat-report**).
- Do not read or display `.env` contents, tokens, API keys, or passwords. Configuration
  examples may show environment-variable **names** only. Check presence without printing
  values.
- Do not start or stop Docker, rotate keys, or run a live attack or pilot unless the user
  explicitly requests it and names the target. Before a live run, show the endpoint, the
  attempt/call budget, and whether the judge is enabled.
- Do not commit, push, merge, or approve on the user's behalf unless separately requested.
  Respect the repository's own handoff and review process.

## Offline mock smoke (no checkout needed)

The starter-pack scenarios ship inside the installed wheel (package
`memnotsafe.pilot_scenarios`), so a bare `pip install memnotsafe` can smoke-test them from
any directory without the repository:

```bash
memnotsafe probe --target mock
memnotsafe run --scenario cross_user_bac.yaml --target mock --output runs/smoke
```

`run --scenario` takes a filesystem path; a **bare bundled name**
(`cross_user_bac.yaml`, `cross_user_bac_c_mk_operand.yaml`, `direct_poisoning.yaml`,
`cross_user_bac_protected.yaml`) resolves from the packaged copy when it is not on disk.
`memnotsafe go` with no `--scenario` lists these same bundled scenarios when the current
directory has no `./scenarios`. In a full checkout, `./scenarios/*.yaml` (the whole
registry) is used instead. A mock run exercises a deliberately vulnerable stand — it is a
smoke check of the tooling, not evidence about any real system.

## Never a silent mock

Passing a URL as `--target` while the scenario's own `adapter` is `mock` is **refused**,
not silently ignored:

```
Сценарий <id>: adapter=mock, а --target='https://host' — это URL. Молчаливый mock по URL
запрещён: URL был бы проигнорирован, а прогон считал бы, что бьёт живую цель.
```

The point of the refusal: a mock adapter cannot reach a URL, so the run would have looked
like a live test while actually hitting the offline mock. Resolve it one of three explicit
ways, exactly as the hint says:

- change the scenario's `target.adapter` to a live adapter
  (`openai` / `openai_compatible` / `http_endpoint` / `investment_stand`); or
- pass `--target <known-adapter-name>` to switch the adapter explicitly; or
- pass `--target mock` for an explicit smoke run.

`--target mock` (explicit smoke) and `--target <adapter-name>` (explicit switch) are never
refused — only a URL layered over a mock scenario is.

## Target profile — a third-party OpenAI-compatible endpoint

A **target profile** (added in the target-profile work) describes someone else's endpoint
declaratively, inside a scenario's `target:` block under a `profile:` sub-block. It is a
scenario-level feature honored by `run`, `campaign`, and `go` — and **only** for
`adapter: http_endpoint` (a `mock` scenario never carries a profile). Parsing is strict:
an unknown key at any level fails before the first request, so typos surface early.

```yaml
target:
  adapter: http_endpoint
  base_url: "https://your-endpoint.example"     # profile.transport.chat_path is appended
  profile:
    schema_version: 1
    transport:                    # HOW to talk to it
      chat_path: "/v1/chat/completions"          # relative to base_url; POST only
      request: { model_field: model, messages_field: messages, role_key: role, content_key: content }
      response: { content_path: [choices, 0, message, content] }
    auth:                         # bearer_env | none
      scheme: bearer_env
      api_key_env: MEMNOTSAFE_TARGET_API_KEY     # ENV NAME only — never the value
    identity:                     # who each principal is (none | request_header | request_field | native_session | bearer_env)
      scheme: none
      cross_user_independent: false              # attest only if per-user identities are truly independent
      # principals: [{ subject: "...", user_id: "1001", env: SK_GENAI_1001 }]
    session:                      # adapter_history | native
      mode: adapter_history
    observation:                  # what evidence the endpoint can expose (all default false)
      memory_snapshot: false
      retrieval_trace: false
      tool_telemetry: false
    health:                       # post_only (default) | get
      mode: post_only             # for `get`: also set `path` and `expect_status`
```

Blocks, in the order the card cares about: **transport** (path/method/request+response field
mapping), **auth** (scheme + `api_key_env` name), **identity** (per-principal identity and
the `cross_user_independent` attestation gate), **session** (history vs native), and
**health** plus **observation/snapshot** (which evidence channels the endpoint exposes). No
block ever holds a secret value — only environment-variable names.

**Pilot does not take a profile.** `memnotsafe pilot` uses a simpler `http_endpoint` target
(see below): its `pilot.yaml` carries `target.adapter`/`base_url`/`model`/`api_key_env` plus
`budget_cap`/`iterations`, with no `profile:` block. Reach for a full profile through a
scenario run/`go` when the endpoint's transport, identity, or evidence shape differs from the
plain OpenAI-compatible default.

## Judge (LLM-as-judge) from configuration

The semantic judge is configured, never hardcoded-on. There is no active silent default
provider: a judge that is enabled but has no target model stops the run with a human error
**before** any target is touched. Configuration precedence (highest first):

1. **CLI flags** on `run` / `campaign` / `go`: `--judge` (force on), `--no-judge` (force off,
   wins over `--judge`), `--judge-model <name>`, `--judge-max-calls <n>`.
2. **Scenario `judge:` block** — `enabled`, `model`, `base_url`, `api_key_env`, `max_calls`.
3. **Project environment defaults**, applied only to scenarios that declare no `judge:`
   block of their own: `MEMNOTSAFE_JUDGE_MODEL`, `MEMNOTSAFE_JUDGE_BASE_URL`,
   `MEMNOTSAFE_JUDGE_API_KEY_ENV` (again a variable **name**, not a key value).
4. Otherwise, if a judge is enabled with no model, a clear error and exit 1:
   `judge.enabled=true требует judge.model` — fix by naming a judge model (distinct from the
   target model) via a flag, the scenario block, or the project env.

Note the judge's `base_url`/`api_key_env` come from the scenario block or the
`MEMNOTSAFE_JUDGE_*` env — there are no `--judge-base-url` / `--judge-api-key-env` flags. A
judge verdict is a semantic opinion, not independent evidence: reading the state of memory
and judging meaning are separate channels; never let a judge stand in for the deterministic
oracle.

## Docker stand

If the installed CLI provides `memnotsafe stand`, its subcommands are `up`, `down`,
`status`, `keys` (confirm with `memnotsafe stand --help`):

- `stand up` — bring the stack up and wait for healthz on `:9600`.
- `stand status` — healthz + container table.
- `stand keys` — reissue the `SK_GENAI_*` client keys into `.env` (backs up `.env.bak`).
  Only when explicitly requested; never print issued key values.
- `stand down` — stop it.

The Compose directory is resolved from `MEMNOTSAFE_STACK2_DIR` (or the project's supported
config key), never hardcoded from the skill author's machine. After `up`, verify the CLI's
health check before calling the stand ready. Do not claim `stand` works merely because its
source exists on an unmerged branch.

## Pilot or run

For a third-party endpoint, prefer the project's pilot flow and inspect the generated
config before any request:

```bash
memnotsafe pilot --init                                   # writes pilot.yaml template + next-step hint
# 1) export MEMNOTSAFE_TARGET_API_KEY=<key>   (value stays in your environment, not the file)
# 2) edit base_url and model in pilot.yaml
memnotsafe pilot --config pilot.yaml --output runs/pilot-run
# then open runs/pilot-run/threat-report.html
```

`pilot --init` refuses to overwrite an existing config. The pilot runs the starter pack of
registry scenarios against your endpoint under a required `budget_cap` (a hard ceiling on
runs against the endpoint); once the budget is spent, the rest is honestly skipped.

For a single scenario, `run` and the guided `go` wizard:

```bash
memnotsafe run --scenario <path-or-bundled-name> --target mock --output runs/demo
memnotsafe go --scenario <path>                           # preflight → confirm → run → threat-report
```

`go` shows whether the target is `MOCK (smoke)` or a live stand and asks for confirmation
before a live run; under `--yes` a live target additionally requires `--live-ack`. Keep the
key value in the environment and put only its variable name in YAML. Use a finite budget.
Follow the exact installed CLI flags rather than inventing commands.

After a run, report the command used with secret values redacted, the report path, the
number of attempts, and the verdict. Separate proven results from unknown or unobservable
ones. If a prerequisite is missing, give the smallest concrete setup step and stop that
operation.

## Reading a threat-report

`memnotsafe threat-report --input runs/<name>` reads `runs/<name>/campaign.json` (written by
`run`/`campaign`/`pilot`/`go`) and writes `threat-report.html` next to the run (or to
`--output`). Exit codes: `0` report assembled; `1` input/output contract error; `2`
insufficient artifacts (with an honest list of what is missing). Each case gets one of three
verdicts, mapped from the oracle's tri-state:

- **PROVEN** — the compromise was shown by independent (non-judge) evidence.
- **NOT PROVEN** — an observed stage refuted it. **Not the same as "safe":** the attack ran,
  the chain broke at an observed point, but content written earlier may remain in memory.
- **INCONCLUSIVE** — unobserved or contradictory; the payload may still be in memory. The
  campaign stamp mirrors these (`COMPROMISE PROVEN` / `COMPROMISE NOT PROVEN` /
  `INCONCLUSIVE`).

Always carry the doctrine into the summary: **UNKNOWN is not safe.** A stage that was not
observed is neither a pass nor a fail; report visibility gaps as gaps, not as clean results.
