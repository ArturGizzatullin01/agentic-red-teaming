// Types mirrored from the memnotsafe artifact writers. Field names and shapes
// are taken from the producing code, not invented:
//   - campaign.json           -> core/campaign_serialize.py :: campaign_to_dict / stage_to_dict
//   - aggregate_metrics.funnel -> reporting/metrics.py (per-stage pass/fail/unknown/total)
//   - findings.json           -> reporting/findings.py :: Finding
//   - attempts.jsonl          -> core/attempt.py :: AttemptRecord.to_dict
//   - budget-ledger.jsonl     -> core/ledger.py :: LedgerEntry.to_dict
//
// Everything is read tolerantly: unknown extra keys are ignored, and missing
// optional artifacts degrade to null rather than throwing.

export type StageName =
  | 'write'
  | 'persistence'
  | 'retrieval'
  | 'adoption'
  | 'tool'
  | 'external_effect'

// The six composite stages of the kill-chain, in causal order. This is the
// funnel the operator reads top-to-bottom.
export const STAGE_ORDER: StageName[] = [
  'write',
  'persistence',
  'retrieval',
  'adoption',
  'tool',
  'external_effect',
]

export const STAGE_LABELS: Record<StageName, string> = {
  write: 'Write',
  persistence: 'Persistence',
  retrieval: 'Retrieval',
  adoption: 'Adoption',
  tool: 'Tool',
  external_effect: 'External effect',
}

// The tri-state is the heart of the doctrine. A stage verdict is a boolean OR
// null in the artifacts; null means "no telemetry / not observed", which is
// NOT the same as "safe" (false) and NOT the same as "exploited" (true).
export type TriState = 'pass' | 'fail' | 'unknown'

export interface FunnelCell {
  pass: number
  fail: number
  unknown: number
  total: number
}

export type Funnel = Record<StageName, FunnelCell>

export interface StageVerdict {
  stage: StageName
  success: boolean | null
  reason?: string
  confidence?: number | null
  verdict_source?: string
  evidence_kind?: string
  disagreement?: boolean
}

export interface CaseResult {
  case_id: string
  attack_id: string
  family: string
  success: boolean | null
  stages: StageVerdict[]
  attacker_user_id?: string | null
  victim_user_id?: string | null
  // evidence is intentionally left as unknown: the console never blindly
  // renders it (it can carry payload/transcript text). Individual, vetted
  // fields are read where needed.
  evidence?: unknown
}

export interface CampaignMetadata {
  run_id?: string
  adapter?: string
  target?: string
  reset_available?: boolean | null
  evidence_channel?: string | null
  attempts?: number
  judge?: { active?: boolean } | null
  attacker?: { active?: boolean } | null
  target_sampling?: unknown
}

export interface AsrProvenance {
  successful?: number
  independent?: number
  judge_raised_only?: number
  retrieval_tolerated_only?: number
  end_to_end_asr_independent?: number
  [k: string]: unknown
}

export interface AggregateMetrics {
  attempts: number
  successful: number
  write_rate?: number
  persistence_rate?: number
  retrieval_rate?: number
  adoption_rate?: number
  tool_hijack_rate?: number
  end_to_end_asr: number
  asr_provenance?: AsrProvenance
  funnel: Funnel
  judge_disagreement_rate?: number | null
  judge?: { active?: boolean } | null
}

export interface Campaign {
  run_id: string
  scenario_id: string
  attempts: number
  metadata: CampaignMetadata
  aggregate_metrics: AggregateMetrics
  results: CaseResult[]
}

// findings.json — case-level verdict with severity + ATT&CK / OWASP mapping.
export type FindingStatus = 'SUCCESS' | 'NOT_EXPLOITABLE' | 'INCONCLUSIVE' | string
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string

export interface Finding {
  finding_id: string
  case_id: string
  attack_id: string
  family: string
  title: string
  description: string
  severity: Severity
  status: FindingStatus
  attacker?: string | null
  victim?: string | null
  atlas_technique?: string | null
  atlas_tactic?: string | null
  owasp_asi?: string | null
  stages: Partial<Record<StageName, boolean | null>>
  confidence_tier?: string | null
  llm_confirmed?: boolean
}

export interface AttemptRecord {
  run_id: string
  case_id: string
  candidate_id: string
  parent_candidate_id: string | null
  attempt_no: number
  transport_retry: number
  outcome: string
  error?: string | null
  session_ids?: Record<string, string | null>
  timing?: Record<string, number | null> | null
}

export interface LedgerEntry {
  run_id: string
  operation: string
  phase: string
  case_id?: string | null
  candidate_id?: string | null
  attempt_no?: number
  usage?: Record<string, unknown> | null
  error?: string | null
  note?: string | null
}

// A normalized run: the campaign is required, everything else is best-effort.
export interface RunArtifacts {
  slug: string
  campaign: Campaign
  findings: Finding[] | null
  attempts: AttemptRecord[] | null
  ledger: LedgerEntry[] | null
  reportHtml: string | null
  threatReportHtml: string | null
  // Human-readable notes about what was and wasn't present. Surfaced in the
  // UI so an operator is never silently shown a partial run.
  warnings: string[]
}
