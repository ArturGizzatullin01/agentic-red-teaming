import type { CaseResult, Finding, RunArtifacts, StageName } from '../lib/types'
import { STAGE_LABELS, STAGE_ORDER } from '../lib/types'
import {
  caseHasUnknownStage,
  caseVerdict,
  funnelHasUnknown,
  pct,
  runVerdict,
  statusCounts,
  toTriState,
} from '../lib/tristate'
import { summarizeAttempts, summarizeLedger } from '../lib/summarize'
import { DoctrineBadge, SeverityTag, TriDot, VerdictBadge } from './badges'
import { FunnelView } from './Funnel'
import { ReportFrame } from './ReportFrame'

function StageRow({ result }: { result: CaseResult }) {
  const byStage = new Map<string, CaseResult['stages'][number]>()
  for (const s of result.stages) byStage.set(s.stage, s)
  return (
    <div className="stage-row">
      {STAGE_ORDER.map((stage: StageName) => {
        const v = byStage.get(stage)
        const tri = toTriState(v?.success)
        const reason = v?.reason ? ` — ${v.reason}` : ''
        return (
          <TriDot key={stage} state={tri} title={`${STAGE_LABELS[stage]}: ${tri}${reason}`} />
        )
      })}
    </div>
  )
}

function statusBadge(finding: Finding | undefined, result: CaseResult) {
  return <VerdictBadge verdict={caseVerdict(result, finding)} />
}

export function RunView({ run, onBack }: { run: RunArtifacts; onBack: () => void }) {
  const { campaign, findings } = run
  const verdict = runVerdict(run)
  const counts = statusCounts(run)
  const agg = campaign.aggregate_metrics
  const findingByCase = new Map<string, Finding>()
  for (const f of findings ?? []) findingByCase.set(f.case_id, f)

  const anyUnknown =
    funnelHasUnknown(agg.funnel) || campaign.results.some(caseHasUnknownStage)

  const attemptSummary = summarizeAttempts(run.attempts)
  const ledgerSummary = summarizeLedger(run.ledger)
  const judgeActive = Boolean(agg.judge?.active ?? campaign.metadata.judge?.active)

  return (
    <div>
      <div className="crumbs">
        <button onClick={onBack}>← All runs</button> / {run.slug}
      </div>

      <div className="topbar" style={{ borderBottom: 'none', marginBottom: 6 }}>
        <div className="brand" style={{ fontSize: 22 }}>
          {run.slug}
        </div>
        <VerdictBadge verdict={verdict} />
        <div className="spacer" />
        <span className="stamp mono">
          <b>{campaign.run_id}</b>
        </span>
      </div>
      <div className="scenario" style={{ marginBottom: 4 }}>
        scenario <code className="inline">{campaign.scenario_id}</code> · target{' '}
        <code className="inline">{campaign.metadata.target ?? campaign.metadata.adapter}</code> ·
        judge {judgeActive ? 'active' : 'inactive'} · evidence channel{' '}
        {campaign.metadata.evidence_channel ?? 'none'}
      </div>

      {anyUnknown && verdict !== 'exploited' && <DoctrineBadge kind="unknown-not-safe" />}
      {anyUnknown && <DoctrineBadge kind="unknown-not-red" />}

      <div className="section">
        <h2>Metrics</h2>
        <div className="kv">
          <div className="cell">
            <div className="n">{pct(agg.end_to_end_asr ?? 0)}</div>
            <div className="l">end-to-end ASR</div>
          </div>
          <div className="cell">
            <div className="n">{agg.attempts}</div>
            <div className="l">cases (ASR denominator)</div>
          </div>
          <div className="cell">
            <div className="n">{agg.successful}</div>
            <div className="l">successful cases</div>
          </div>
          <div className="cell">
            <div className="n" style={{ color: 'var(--unk)' }}>
              {counts.inconclusive}
            </div>
            <div className="l">inconclusive cases</div>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Kill-chain funnel</h2>
        <FunnelView funnel={agg.funnel} />
      </div>

      <div className="section">
        <h2>Cases</h2>
        <table className="cases">
          <thead>
            <tr>
              <th>Case</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Stages (W·P·R·A·T·E)</th>
              <th>Mapping</th>
              <th>Actors</th>
            </tr>
          </thead>
          <tbody>
            {campaign.results.map((r) => {
              const f = findingByCase.get(r.case_id)
              const hasUnknown = caseHasUnknownStage(r)
              return (
                <tr key={r.case_id}>
                  <td className="mono" style={{ maxWidth: 220, wordBreak: 'break-all' }}>
                    {r.case_id}
                    <div className="map">{f?.title ?? r.family}</div>
                  </td>
                  <td>
                    {statusBadge(f, r)}
                    {f && (
                      <div className="map mono" style={{ marginTop: 4 }}>
                        findings.json: {f.status}
                      </div>
                    )}
                    {hasUnknown && (
                      <div className="map" style={{ color: 'var(--unk)', marginTop: 4 }}>
                        has UNKNOWN stage — not safe
                      </div>
                    )}
                  </td>
                  <td>{f ? <SeverityTag severity={f.severity} /> : <span className="map">—</span>}</td>
                  <td>
                    <StageRow result={r} />
                  </td>
                  <td className="map">
                    {f?.atlas_technique && (
                      <div>
                        {f.atlas_technique}
                        {f.atlas_tactic ? ` · ${f.atlas_tactic}` : ''}
                      </div>
                    )}
                    {f?.owasp_asi && <div>{f.owasp_asi}</div>}
                    {!f?.atlas_technique && !f?.owasp_asi && '—'}
                  </td>
                  <td className="mono map">
                    {r.attacker_user_id ?? '?'} → {r.victim_user_id ?? '?'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {attemptSummary && (
        <div className="section">
          <h2>Attempt history</h2>
          <div className="stamps">
            <span className="stamp">
              records <b>{attemptSummary.total}</b>
            </span>
            <span className="stamp">
              cases <b>{attemptSummary.distinctCases}</b>
            </span>
            <span className="stamp">
              candidates <b>{attemptSummary.distinctCandidates}</b>
            </span>
            <span className="stamp">
              transport retries <b>{attemptSummary.transportRetries}</b>
            </span>
          </div>
          <div className="stamps" style={{ marginTop: 8 }}>
            {Object.entries(attemptSummary.byOutcome).map(([outcome, n]) => (
              <span className="stamp mono" key={outcome}>
                {outcome} <b>{n}</b>
              </span>
            ))}
          </div>
          <p className="map" style={{ marginTop: 8 }}>
            Attempt records count completed <em>attempts</em>; the ASR denominator stays the{' '}
            <b>{agg.attempts}</b> completed cases from campaign.json — escalation attempts do not
            change it.
          </p>
        </div>
      )}

      {ledgerSummary && (
        <div className="section">
          <h2>Budget ledger</h2>
          <div className="stamps">
            <span className="stamp">
              operations <b>{ledgerSummary.total}</b>
            </span>
            {Object.entries(ledgerSummary.byOperation).map(([op, n]) => (
              <span className="stamp mono" key={op}>
                {op} <b>{n}</b>
              </span>
            ))}
            {ledgerSummary.blocked > 0 && (
              <span className="stamp" style={{ borderColor: 'var(--fail)' }}>
                blocked <b>{ledgerSummary.blocked}</b>
              </span>
            )}
            {ledgerSummary.unknownOutcome > 0 && (
              <span className="stamp" style={{ borderColor: 'var(--unk)' }}>
                unknown outcome <b>{ledgerSummary.unknownOutcome}</b>
              </span>
            )}
          </div>
          <p className="map" style={{ marginTop: 8 }}>
            usage known on <b>{ledgerSummary.usageKnown}</b> ops · usage unknown on{' '}
            <b>{ledgerSummary.usageUnknown}</b> ops. The ledger records{' '}
            <code className="inline">usage=null</code> as <em>unknown</em>, never as zero — no cost
            is invented.
          </p>
        </div>
      )}

      {(run.reportHtml || run.threatReportHtml) && (
        <div className="section">
          <h2>Full reports</h2>
          {run.reportHtml && <ReportFrame title="report.html" html={run.reportHtml} />}
          {run.threatReportHtml && (
            <div style={{ marginTop: 12 }}>
              <ReportFrame title="threat-report.html" html={run.threatReportHtml} />
            </div>
          )}
        </div>
      )}

      {run.warnings.length > 0 && (
        <div className="section">
          <h2>Artifact notes</h2>
          <ul className="warnings">
            {run.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
