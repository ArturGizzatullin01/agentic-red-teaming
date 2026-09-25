import type { Funnel as FunnelType } from '../lib/types'
import { STAGE_LABELS, STAGE_ORDER } from '../lib/types'
import { TriDot } from './badges'

// The kill-chain funnel. Each stage is a stacked bar of pass / fail / unknown,
// widths proportional to counts. The unknown segment is hatched amber so it is
// never mistaken for a solid pass or fail.
export function FunnelView({ funnel }: { funnel: FunnelType }) {
  return (
    <div>
      <div className="funnel">
        {STAGE_ORDER.map((stage) => {
          const cell = funnel[stage]
          const total = Math.max(cell.total, 1)
          const w = (n: number) => `${(n / total) * 100}%`
          return (
            <div className="stage" key={stage}>
              <div className="name">
                {STAGE_LABELS[stage]}
                {cell.unknown > 0 && <TriDot state="unknown" title="has unknown" />}
              </div>
              <div
                className="bar"
                role="img"
                aria-label={`${STAGE_LABELS[stage]}: ${cell.pass} pass, ${cell.fail} fail, ${cell.unknown} unknown of ${cell.total}`}
              >
                {cell.pass > 0 && <div className="seg pass" style={{ width: w(cell.pass) }} />}
                {cell.unknown > 0 && (
                  <div className="seg unknown" style={{ width: w(cell.unknown) }} />
                )}
                {cell.fail > 0 && <div className="seg fail" style={{ width: w(cell.fail) }} />}
              </div>
              <div className="counts">
                {cell.pass}✓ · {cell.fail}✗ ·{' '}
                <span className="u">{cell.unknown}?</span> / {cell.total}
              </div>
            </div>
          )
        })}
      </div>
      <div className="legend">
        <span>
          <TriDot state="pass" /> pass
        </span>
        <span>
          <TriDot state="fail" /> fail
        </span>
        <span>
          <TriDot state="unknown" /> unknown (not observed)
        </span>
      </div>
    </div>
  )
}
