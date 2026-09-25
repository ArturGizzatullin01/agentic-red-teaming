// Parsing / normalization of a run directory's artifacts into RunArtifacts.
//
// Two callers feed the same parser:
//   - the bundled fixtures (loaded as raw strings via import.meta.glob), and
//   - the local file loader (files the operator picks in the browser).
// Neither path performs any network I/O.

import type {
  AttemptRecord,
  Campaign,
  Finding,
  Funnel,
  LedgerEntry,
  RunArtifacts,
} from './types'
import { STAGE_ORDER } from './types'
import { funnelFromResults } from './tristate'

export class ParseError extends Error {}

// Map an arbitrary filename to the artifact slot it fills. Matching is on the
// basename so it works for both "campaign.json" and ".../run-x/campaign.json".
export type ArtifactKind =
  | 'campaign'
  | 'findings'
  | 'attempts'
  | 'ledger'
  | 'report'
  | 'threat_report'
  | 'unknown'

export function classifyFile(name: string): ArtifactKind {
  const base = name.split('/').pop()?.toLowerCase() ?? ''
  if (base === 'campaign.json') return 'campaign'
  if (base === 'findings.json') return 'findings'
  if (base === 'attempts.jsonl') return 'attempts'
  if (base === 'budget-ledger.jsonl' || base === 'budget_ledger.jsonl') return 'ledger'
  if (base === 'threat-report.html' || base === 'threat_report.html') return 'threat_report'
  if (base === 'report.html') return 'report'
  return 'unknown'
}

export function parseJsonl<T>(text: string): T[] {
  const out: T[] = []
  const lines = text.split('\n')
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue
    out.push(JSON.parse(trimmed) as T)
  }
  return out
}

// Defensive shape check for a campaign object. We do not enforce a schema
// version (the artifacts do not carry one at this level); instead we require
// the handful of fields the console actually reads, and rebuild the funnel if
// the aggregate is missing or malformed.
function coerceCampaign(raw: unknown): Campaign {
  if (!raw || typeof raw !== 'object') {
    throw new ParseError('campaign.json is not a JSON object')
  }
  const obj = raw as Record<string, unknown>
  if (!Array.isArray(obj.results)) {
    throw new ParseError('campaign.json has no results[] — not a memnotsafe campaign artifact')
  }
  const campaign = raw as Campaign

  const agg = (campaign.aggregate_metrics ?? {}) as Campaign['aggregate_metrics']
  if (!agg.funnel || !hasAllStages(agg.funnel)) {
    campaign.aggregate_metrics = {
      ...agg,
      attempts: agg.attempts ?? campaign.results.length,
      successful:
        agg.successful ?? campaign.results.filter((r) => r.success === true).length,
      end_to_end_asr: agg.end_to_end_asr ?? 0,
      funnel: funnelFromResults(campaign.results),
    }
  }
  if (!campaign.metadata) campaign.metadata = {}
  if (!campaign.run_id) campaign.run_id = campaign.metadata.run_id ?? 'UNKNOWN-RUN'
  if (!campaign.scenario_id) campaign.scenario_id = 'unknown-scenario'
  return campaign
}

function hasAllStages(funnel: Funnel): boolean {
  return STAGE_ORDER.every((s) => funnel[s] && typeof funnel[s].total === 'number')
}

export interface RawFiles {
  // basename or path -> file contents
  [name: string]: string
}

// Build a normalized run from a bag of files. `slug` is the display id (the
// run directory name for fixtures, or a user-supplied label for local loads).
export function parseRun(slug: string, files: RawFiles): RunArtifacts {
  const warnings: string[] = []
  let campaignText: string | null = null
  let findingsText: string | null = null
  let attemptsText: string | null = null
  let ledgerText: string | null = null
  let reportHtml: string | null = null
  let threatReportHtml: string | null = null

  for (const [name, text] of Object.entries(files)) {
    switch (classifyFile(name)) {
      case 'campaign':
        campaignText = text
        break
      case 'findings':
        findingsText = text
        break
      case 'attempts':
        attemptsText = text
        break
      case 'ledger':
        ledgerText = text
        break
      case 'report':
        reportHtml = text
        break
      case 'threat_report':
        threatReportHtml = text
        break
      default:
        break
    }
  }

  if (!campaignText) {
    throw new ParseError(
      `run "${slug}" has no campaign.json — the console needs at least campaign.json to render a run`,
    )
  }

  const campaign = coerceCampaign(JSON.parse(campaignText))

  let findings: Finding[] | null = null
  if (findingsText) {
    try {
      const parsed = JSON.parse(findingsText)
      findings = Array.isArray(parsed) ? (parsed as Finding[]) : null
      if (!findings) warnings.push('findings.json was present but not an array — ignored')
    } catch {
      warnings.push('findings.json could not be parsed — ignored')
    }
  } else {
    warnings.push('findings.json absent — severity / ATT&CK mapping unavailable')
  }

  let attempts: AttemptRecord[] | null = null
  if (attemptsText) {
    try {
      attempts = parseJsonl<AttemptRecord>(attemptsText)
    } catch {
      warnings.push('attempts.jsonl had a malformed line — attempt history unavailable')
    }
  } else {
    warnings.push('attempts.jsonl absent — attempt history unavailable')
  }

  let ledger: LedgerEntry[] | null = null
  if (ledgerText) {
    try {
      ledger = parseJsonl<LedgerEntry>(ledgerText)
    } catch {
      warnings.push('budget-ledger.jsonl had a malformed line — budget ledger unavailable')
    }
  } else {
    warnings.push('budget-ledger.jsonl absent — budget ledger unavailable')
  }

  if (!reportHtml) warnings.push('report.html absent — full HTML report not linkable')
  if (!threatReportHtml) {
    warnings.push('threat-report.html absent — business threat report not linkable')
  }

  return {
    slug,
    campaign,
    findings,
    attempts,
    ledger,
    reportHtml,
    threatReportHtml,
    warnings,
  }
}
