import type { RunArtifacts, Severity } from '../lib/types'
import {
  pct,
  runVerdict,
  statusCounts,
  totalUnknownStages,
} from '../lib/tristate'
import { SeverityTag, VerdictBadge } from './badges'

const SEV_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
}

function topSeverity(run: RunArtifacts): Severity | null {
  if (!run.findings || run.findings.length === 0) return null
  let best: Severity | null = null
  let bestRank = -1
  for (const f of run.findings) {
    const rank = SEV_RANK[String(f.severity).toUpperCase()] ?? 0
    if (rank > bestRank) {
      bestRank = rank
      best = f.severity
    }
  }
  return best
}

function RunCard({ run, onOpen }: { run: RunArtifacts; onOpen: (slug: string) => void }) {
  const { campaign } = run
  const verdict = runVerdict(run)
  const counts = statusCounts(run)
  const unknownStages = totalUnknownStages(campaign.aggregate_metrics.funnel)
  const sev = topSeverity(run)
  const asr = campaign.aggregate_metrics.end_to_end_asr ?? 0

  return (
    <button className="card click" onClick={() => onOpen(run.slug)}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <h3>{run.slug}</h3>
        <VerdictBadge verdict={verdict} />
      </div>
      <div className="scenario">{campaign.scenario_id}</div>
      <div className="stamps">
        <span className="stamp mono" title="run id">
          <b>{campaign.run_id}</b>
        </span>
        <span className="stamp">
          target <b>{campaign.metadata.target ?? campaign.metadata.adapter ?? '—'}</b>
        </span>
        <span className="stamp">
          cases <b>{campaign.aggregate_metrics.attempts}</b>
        </span>
        <span className="stamp">
          e2e ASR <b>{pct(asr)}</b>
        </span>
        {sev && (
          <span className="stamp">
            top <SeverityTag severity={sev} />
          </span>
        )}
      </div>
      <div className="stamps" style={{ marginTop: 8 }}>
        <span className="stamp">
          ✓ controlled <b>{counts.controlled}</b>
        </span>
        <span className="stamp">
          ✗ exploited <b>{counts.exploited}</b>
        </span>
        <span className="stamp" style={{ borderColor: unknownStages ? 'var(--unk)' : undefined }}>
          ? unknown stages <b>{unknownStages}</b>
        </span>
      </div>
    </button>
  )
}

export function RunGallery({
  runs,
  onOpen,
}: {
  runs: RunArtifacts[]
  onOpen: (slug: string) => void
}) {
  if (runs.length === 0) {
    return <p className="map">No runs loaded.</p>
  }
  return (
    <div className="grid">
      {runs.map((run) => (
        <RunCard key={run.slug} run={run} onOpen={onOpen} />
      ))}
    </div>
  )
}
