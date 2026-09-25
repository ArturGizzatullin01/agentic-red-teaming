// Bundled fixtures. Each subdirectory of console/fixtures/ is one real run
// produced by `memnotsafe campaign --target mock ...` — synthetic offline data
// only, no live memory and no secrets. They are loaded as raw strings and fed
// through the exact same parser the local file loader uses.

import { parseRun, type RawFiles } from './parse'
import type { RunArtifacts } from './types'

const raw = import.meta.glob('../../fixtures/**/*.{json,jsonl,html}', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>

function groupByRun(): Map<string, RawFiles> {
  const runs = new Map<string, RawFiles>()
  for (const [path, text] of Object.entries(raw)) {
    // path looks like ../../fixtures/<run-slug>/<file>
    const marker = '/fixtures/'
    const idx = path.indexOf(marker)
    if (idx === -1) continue
    const rest = path.slice(idx + marker.length) // <run-slug>/<file>
    const slash = rest.indexOf('/')
    if (slash === -1) continue
    const slug = rest.slice(0, slash)
    const file = rest.slice(slash + 1)
    if (!runs.has(slug)) runs.set(slug, {})
    runs.get(slug)![file] = text
  }
  return runs
}

let cache: RunArtifacts[] | null = null

export function loadFixtureRuns(): RunArtifacts[] {
  if (cache) return cache
  const grouped = groupByRun()
  const runs: RunArtifacts[] = []
  for (const [slug, files] of grouped) {
    try {
      runs.push(parseRun(slug, files))
    } catch (err) {
      // A broken fixture must not take the whole gallery down; surface it on
      // the console instead.
      console.error(`fixture "${slug}" failed to parse`, err)
    }
  }
  // Stable, meaningful order: exploited-looking runs first is tempting, but a
  // deterministic alphabetical order keeps the demo reproducible.
  runs.sort((a, b) => a.slug.localeCompare(b.slug))
  cache = runs
  return runs
}
