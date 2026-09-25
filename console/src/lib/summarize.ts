// Small, pure roll-ups over the optional artifacts (attempts.jsonl and
// budget-ledger.jsonl). These honor the artifacts' own contracts:
//   - the ASR denominator is the count of completed CASES from campaign.json,
//     never the attempt-history line count (attempts can exceed cases under
//     escalation); we only summarize attempt outcomes descriptively here.
//   - the ledger records usage=null as "unknown", never zero. We count such
//     operations without inventing a cost.

import type { AttemptRecord, LedgerEntry } from './types'

export interface AttemptSummary {
  total: number
  byOutcome: Record<string, number>
  transportRetries: number
  // candidates beyond the logical case count = escalation rewrites
  distinctCases: number
  distinctCandidates: number
}

export function summarizeAttempts(attempts: AttemptRecord[] | null): AttemptSummary | null {
  if (!attempts || attempts.length === 0) return null
  const byOutcome: Record<string, number> = {}
  const cases = new Set<string>()
  const candidates = new Set<string>()
  let transportRetries = 0
  for (const a of attempts) {
    byOutcome[a.outcome] = (byOutcome[a.outcome] ?? 0) + 1
    if (a.case_id) cases.add(a.case_id)
    if (a.candidate_id) candidates.add(a.candidate_id)
    if ((a.transport_retry ?? 0) > 0) transportRetries += 1
  }
  return {
    total: attempts.length,
    byOutcome,
    transportRetries,
    distinctCases: cases.size,
    distinctCandidates: candidates.size,
  }
}

export interface LedgerSummary {
  total: number
  byOperation: Record<string, number>
  byPhase: Record<string, number>
  blocked: number
  unknownOutcome: number
  usageKnown: number
  usageUnknown: number
}

export function summarizeLedger(ledger: LedgerEntry[] | null): LedgerSummary | null {
  if (!ledger || ledger.length === 0) return null
  const byOperation: Record<string, number> = {}
  const byPhase: Record<string, number> = {}
  let blocked = 0
  let unknownOutcome = 0
  let usageKnown = 0
  let usageUnknown = 0
  for (const e of ledger) {
    byOperation[e.operation] = (byOperation[e.operation] ?? 0) + 1
    byPhase[e.phase] = (byPhase[e.phase] ?? 0) + 1
    if (e.phase === 'blocked') blocked += 1
    if (e.phase === 'unknown_outcome') unknownOutcome += 1
    // usage=null is an explicit "unknown", not a zero.
    if (e.usage == null) usageUnknown += 1
    else usageKnown += 1
  }
  return {
    total: ledger.length,
    byOperation,
    byPhase,
    blocked,
    unknownOutcome,
    usageKnown,
    usageUnknown,
  }
}
