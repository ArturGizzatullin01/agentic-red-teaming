// Test helper: read a fixture run directory off disk into the RawFiles bag the
// parser consumes. This exercises the parser against the REAL artifacts that
// ship in console/fixtures/, not hand-written stand-ins.
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { RawFiles } from '../lib/parse'

const here = dirname(fileURLToPath(import.meta.url))
export const FIXTURES_DIR = join(here, '..', '..', 'fixtures')

export function listFixtureSlugs(): string[] {
  return readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort()
}

export function readFixture(slug: string): RawFiles {
  const dir = join(FIXTURES_DIR, slug)
  const raw: RawFiles = {}
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isFile()) continue
    raw[entry.name] = readFileSync(join(dir, entry.name), 'utf-8')
  }
  return raw
}
