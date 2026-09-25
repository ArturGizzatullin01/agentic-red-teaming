import type { Severity, TriState } from '../lib/types'
import type { RunVerdict } from '../lib/tristate'

const VERDICT_LABEL: Record<RunVerdict, string> = {
  exploited: 'EXPLOITED',
  controlled: 'CONTROLLED',
  inconclusive: 'INCONCLUSIVE',
}

export function VerdictBadge({ verdict }: { verdict: RunVerdict }) {
  return <span className={`badge ${verdict}`}>{VERDICT_LABEL[verdict]}</span>
}

export function SeverityTag({ severity }: { severity: Severity }) {
  const cls = String(severity).toLowerCase()
  return <span className={`sev ${cls}`}>{severity}</span>
}

export function TriDot({ state, title }: { state: TriState; title?: string }) {
  return <span className={`tri ${state}`} title={title ?? state} aria-label={state} />
}

// The doctrine banner. Shown whenever a run (or case) carries an UNKNOWN, to
// keep the operator from reading "not exploited" as "safe".
export function DoctrineBadge({
  kind,
}: {
  kind: 'unknown-not-safe' | 'unknown-not-red'
}) {
  if (kind === 'unknown-not-safe') {
    return (
      <div className="doctrine" role="note">
        <span className="k">UNKNOWN ≠ safe</span>
        <span>
          Some stages were not observed (no telemetry). Absence of evidence is not
          evidence the control held — treat amber stages as open questions, not passes.
        </span>
      </div>
    )
  }
  return (
    <div className="doctrine" role="note">
      <span className="k">UNKNOWN ≠ exploited</span>
      <span>
        Unobserved stages are not counted as attack successes — they never inflate
        ASR. They are tracked on their own axis.
      </span>
    </div>
  )
}
