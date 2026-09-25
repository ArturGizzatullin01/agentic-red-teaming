import { describe, expect, it } from 'vitest'
import { classifyFile, ParseError, parseJsonl, parseRun } from './parse'
import { listFixtureSlugs, readFixture } from '../test/fixtures-fs'

describe('classifyFile', () => {
  it('maps basenames to artifact slots regardless of path depth', () => {
    expect(classifyFile('campaign.json')).toBe('campaign')
    expect(classifyFile('runs/demo/campaign.json')).toBe('campaign')
    expect(classifyFile('attempts.jsonl')).toBe('attempts')
    expect(classifyFile('budget-ledger.jsonl')).toBe('ledger')
    expect(classifyFile('findings.json')).toBe('findings')
    expect(classifyFile('report.html')).toBe('report')
    expect(classifyFile('threat-report.html')).toBe('threat_report')
    expect(classifyFile('baseline.json')).toBe('unknown')
  })
})

describe('parseJsonl', () => {
  it('skips blank lines and parses each remaining line', () => {
    const rows = parseJsonl<{ a: number }>('{"a":1}\n\n{"a":2}\n')
    expect(rows).toEqual([{ a: 1 }, { a: 2 }])
  })
})

describe('parseRun on real fixtures', () => {
  const slugs = listFixtureSlugs()

  it('ships at least two fixtures', () => {
    expect(slugs.length).toBeGreaterThanOrEqual(2)
  })

  it.each(slugs)('parses %s into a well-formed run', (slug) => {
    const run = parseRun(slug, readFixture(slug))
    expect(run.campaign.run_id).toMatch(/^RUN-/)
    expect(Array.isArray(run.campaign.results)).toBe(true)
    expect(run.campaign.results.length).toBeGreaterThan(0)
    // funnel is present for all six stages
    const funnel = run.campaign.aggregate_metrics.funnel
    for (const stage of ['write', 'persistence', 'retrieval', 'adoption', 'tool', 'external_effect']) {
      expect(funnel[stage as keyof typeof funnel]).toBeDefined()
    }
    // optional artifacts are loaded when present in the fixture
    expect(run.findings?.length).toBeGreaterThan(0)
    expect(run.attempts?.length).toBeGreaterThan(0)
    expect(run.ledger?.length).toBeGreaterThan(0)
    expect(run.reportHtml).toContain('<html')
  })

  it('throws a ParseError when campaign.json is missing', () => {
    expect(() => parseRun('empty', { 'attempts.jsonl': '' })).toThrow(ParseError)
  })
})
