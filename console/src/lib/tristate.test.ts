import { describe, expect, it } from 'vitest'
import {
  caseHasUnknownStage,
  caseVerdict,
  funnelFromResults,
  funnelHasUnknown,
  runVerdict,
  statusCounts,
  toTriState,
  totalUnknownStages,
} from './tristate'
import { parseRun } from './parse'
import { readFixture } from '../test/fixtures-fs'
import { STAGE_ORDER } from './types'

describe('toTriState — the doctrine mapping', () => {
  it('maps boolean|null to pass|fail|unknown, null is its own state', () => {
    expect(toTriState(true)).toBe('pass')
    expect(toTriState(false)).toBe('fail')
    expect(toTriState(null)).toBe('unknown')
    expect(toTriState(undefined)).toBe('unknown')
  })
})

describe('funnelFromResults matches campaign aggregate on real fixtures', () => {
  const cases = [
    'run-cross-user-bac-vulnerable',
    'run-cross-user-bac-protected',
    'run-tool-route-hijack-skipped',
  ]
  it.each(cases)('%s: recomputed funnel equals the stored aggregate', (slug) => {
    const run = parseRun(slug, readFixture(slug))
    const recomputed = funnelFromResults(run.campaign.results)
    // Compare per stage; the stored aggregate is authoritative and our
    // independent recompute must agree with it.
    for (const stage of STAGE_ORDER) {
      expect(recomputed[stage]).toEqual(run.campaign.aggregate_metrics.funnel[stage])
    }
  })
})

describe('UNKNOWN never folds into pass or fail', () => {
  it('an all-null stage column counts entirely as unknown', () => {
    const funnel = funnelFromResults([
      {
        case_id: 'c1',
        attack_id: 'x',
        family: 'x',
        success: null,
        stages: [{ stage: 'adoption', success: null }],
      },
      {
        case_id: 'c2',
        attack_id: 'x',
        family: 'x',
        success: null,
        stages: [{ stage: 'adoption', success: null }],
      },
    ])
    expect(funnel.adoption).toEqual({ pass: 0, fail: 0, unknown: 2, total: 2 })
  })
})

describe('verdict roll-up on real fixtures', () => {
  it('vulnerable run is EXPLOITED with no inconclusive inflation', () => {
    const run = parseRun('run-cross-user-bac-vulnerable', readFixture('run-cross-user-bac-vulnerable'))
    expect(runVerdict(run)).toBe('exploited')
    const counts = statusCounts(run)
    expect(counts.exploited).toBeGreaterThan(0)
    expect(counts.inconclusive).toBe(0)
    expect(funnelHasUnknown(run.campaign.aggregate_metrics.funnel)).toBe(false)
  })

  it('protected run is CONTROLLED — clean control, no unknowns', () => {
    const run = parseRun('run-cross-user-bac-protected', readFixture('run-cross-user-bac-protected'))
    expect(runVerdict(run)).toBe('controlled')
    expect(funnelHasUnknown(run.campaign.aggregate_metrics.funnel)).toBe(false)
    expect(run.campaign.aggregate_metrics.end_to_end_asr).toBe(0)
    const counts = statusCounts(run)
    expect(counts.controlled).toBe(run.campaign.results.length)
    expect(counts.inconclusive).toBe(0)
  })

  it('skipped run is INCONCLUSIVE — not exploited, but not safe either', () => {
    const run = parseRun('run-tool-route-hijack-skipped', readFixture('run-tool-route-hijack-skipped'))
    // ASR is 0 yet the run must NOT read as controlled: unknown stages remain.
    expect(run.campaign.aggregate_metrics.end_to_end_asr).toBe(0)
    expect(runVerdict(run)).toBe('inconclusive')
    expect(funnelHasUnknown(run.campaign.aggregate_metrics.funnel)).toBe(true)
    expect(totalUnknownStages(run.campaign.aggregate_metrics.funnel)).toBeGreaterThan(0)
    expect(run.campaign.results.some(caseHasUnknownStage)).toBe(true)
    // Doctrine: findings.json labels these NOT_EXPLOITABLE, but a case with an
    // unobserved stage must count as inconclusive, never controlled.
    expect(run.findings?.every((f) => f.status === 'NOT_EXPLOITABLE')).toBe(true)
    const counts = statusCounts(run)
    expect(counts.inconclusive).toBe(run.campaign.results.length)
    expect(counts.controlled).toBe(0)
    expect(counts.exploited).toBe(0)
  })

  it('caseVerdict promotes a NOT_EXPLOITABLE-but-unobserved case to inconclusive', () => {
    const controlledCase = {
      case_id: 'c', attack_id: 'x', family: 'x', success: false as boolean | null,
      stages: [{ stage: 'external_effect' as const, success: false }],
    }
    const unobservedCase = {
      case_id: 'c', attack_id: 'x', family: 'x', success: false as boolean | null,
      stages: [{ stage: 'adoption' as const, success: null }],
    }
    const notExploitable = { status: 'NOT_EXPLOITABLE' } as unknown as import('./types').Finding
    expect(caseVerdict(controlledCase, notExploitable)).toBe('controlled')
    expect(caseVerdict(unobservedCase, notExploitable)).toBe('inconclusive')
  })
})
