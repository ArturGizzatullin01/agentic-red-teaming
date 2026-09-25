// The doctrine, in code.
//
// memnotsafe distinguishes three verdicts, and the console must never collapse
// them. The two rules that everything else follows from:
//
//   UNKNOWN != safe   — absence of evidence is not evidence that the control
//                       held. An unobserved stage is an open question, drawn
//                       amber, never green.
//   UNKNOWN != red    — an unobserved stage is not a confirmed exploit either.
//                       It must not inflate the attack-success count.
//
// So `null` stage verdicts map to 'unknown', and 'unknown' is counted on its
// own axis in the funnel — never folded into pass or fail.

import type {
  Campaign,
  CaseResult,
  Finding,
  Funnel,
  FunnelCell,
  StageName,
  TriState,
} from './types'
import { STAGE_ORDER } from './types'

export function toTriState(v: boolean | null | undefined): TriState {
  if (v === true) return 'pass'
  if (v === false) return 'fail'
  return 'unknown'
}

function emptyCell(): FunnelCell {
  return { pass: 0, fail: 0, unknown: 0, total: 0 }
}

// Recompute the funnel from the raw case results. campaign.json already ships
// aggregate_metrics.funnel; we recompute here as an independent check (used by
// the tests) and as a fallback when a hand-assembled run lacks the aggregate.
export function funnelFromResults(results: CaseResult[]): Funnel {
  const funnel = Object.fromEntries(
    STAGE_ORDER.map((s) => [s, emptyCell()]),
  ) as Funnel

  for (const result of results) {
    for (const stage of result.stages) {
      const cell = funnel[stage.stage as StageName]
      if (!cell) continue // ignore stages outside the known chain
      cell.total += 1
      cell[toTriState(stage.success)] += 1
    }
  }
  return funnel
}

export function funnelHasUnknown(funnel: Funnel): boolean {
  return STAGE_ORDER.some((s) => (funnel[s]?.unknown ?? 0) > 0)
}

export function totalUnknownStages(funnel: Funnel): number {
  return STAGE_ORDER.reduce((n, s) => n + (funnel[s]?.unknown ?? 0), 0)
}

// A case carries an unknown stage when any stage verdict is null. Such a case
// must show the "UNKNOWN != safe" caveat even when its overall status reads
// NOT_EXPLOITABLE, because the chain was not fully observed.
export function caseHasUnknownStage(result: CaseResult): boolean {
  return result.stages.some((s) => s.success === null || s.success === undefined)
}

export type RunVerdict = 'exploited' | 'controlled' | 'inconclusive'

// The single source of truth for one case's verdict. Both the run roll-up and
// the per-case status badge go through here, so they can never disagree.
//
// The subtle, doctrine-critical case: findings.json can label a case
// NOT_EXPLOITABLE (overall success=false) while some of its stages were never
// observed (success=null). That is NOT "controlled" — the chain was not fully
// seen, so it is inconclusive. Absence of evidence is not evidence the control
// held.
export function caseVerdict(result: CaseResult, finding?: Finding): RunVerdict {
  if (finding?.status === 'SUCCESS' || result.success === true) return 'exploited'
  if (finding?.status === 'INCONCLUSIVE') return 'inconclusive'
  if (result.success === null || caseHasUnknownStage(result)) return 'inconclusive'
  return 'controlled'
}

function findingMap(findings: Finding[] | null): Map<string, Finding> {
  const m = new Map<string, Finding>()
  for (const f of findings ?? []) m.set(f.case_id, f)
  return m
}

// Roll a whole run up to one of the three doctrine verdicts. Priority:
//   any exploited case            -> exploited
//   else any inconclusive/unknown -> inconclusive (never "controlled")
//   else                          -> controlled
// This deliberately refuses to call a run "controlled" while any question is
// still open.
export function runVerdict(run: {
  campaign: Campaign
  findings: Finding[] | null
}): RunVerdict {
  const { campaign } = run
  const byCase = findingMap(run.findings)
  let anyInconclusive = false
  for (const r of campaign.results) {
    const v = caseVerdict(r, byCase.get(r.case_id))
    if (v === 'exploited') return 'exploited'
    if (v === 'inconclusive') anyInconclusive = true
  }
  // Defensive: an aggregate that claims successes without any success flag in
  // results still reads as exploited rather than silently "controlled".
  if (campaign.aggregate_metrics.successful > 0) return 'exploited'
  return anyInconclusive ? 'inconclusive' : 'controlled'
}

export interface StatusCounts {
  exploited: number
  controlled: number
  inconclusive: number
}

// Per-case verdict counts for a run, using the shared caseVerdict so the tally
// matches both the run badge and each row's status.
export function statusCounts(run: {
  campaign: Campaign
  findings: Finding[] | null
}): StatusCounts {
  const counts: StatusCounts = { exploited: 0, controlled: 0, inconclusive: 0 }
  const byCase = findingMap(run.findings)
  for (const r of run.campaign.results) {
    counts[caseVerdict(r, byCase.get(r.case_id))] += 1
  }
  return counts
}

export function pct(n: number): string {
  return `${Math.round(n * 100)}%`
}
