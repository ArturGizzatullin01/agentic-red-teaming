import { useMemo, useState } from 'react'
import { loadFixtureRuns } from './lib/fixtures'
import type { RunArtifacts } from './lib/types'
import { RunGallery } from './ui/RunGallery'
import { RunView } from './ui/RunView'
import { LocalLoader } from './ui/LocalLoader'

export default function App() {
  const fixtures = useMemo(() => loadFixtureRuns(), [])
  const [local, setLocal] = useState<RunArtifacts[]>([])
  const [openSlug, setOpenSlug] = useState<string | null>(null)

  // Local runs override same-slug fixtures; otherwise both are shown.
  const runs = useMemo(() => {
    const bySlug = new Map<string, RunArtifacts>()
    for (const r of fixtures) bySlug.set(r.slug, r)
    for (const r of local) bySlug.set(r.slug, r)
    return Array.from(bySlug.values()).sort((a, b) => a.slug.localeCompare(b.slug))
  }, [fixtures, local])

  const openRun = openSlug ? runs.find((r) => r.slug === openSlug) ?? null : null

  return (
    <div className="wrap">
      <header className="topbar">
        <div className="brand">
          <span className="mark">memnotsafe</span> · Mission Control
        </div>
        <div className="tagline">
          read-only viewer for run artifacts — offline, no network, no secrets
        </div>
      </header>

      {openRun ? (
        <RunView run={openRun} onBack={() => setOpenSlug(null)} />
      ) : (
        <>
          <div className="section" style={{ marginTop: 0 }}>
            <h2>Runs</h2>
            <RunGallery runs={runs} onOpen={setOpenSlug} />
          </div>
          <div className="section">
            <h2>Load your own run</h2>
            <LocalLoader
              onLoaded={(run) => {
                setLocal((prev) => [...prev.filter((r) => r.slug !== run.slug), run])
                setOpenSlug(run.slug)
              }}
            />
          </div>
        </>
      )}

      <footer className="foot">
        <p style={{ margin: '0 0 6px' }}>
          <b>Doctrine.</b> A stage verdict is pass, fail, or <span style={{ color: 'var(--unk)' }}>UNKNOWN</span>.
          UNKNOWN means the stage was not observed — it is neither a passed control (
          <span style={{ color: 'var(--unk)' }}>UNKNOWN ≠ safe</span>) nor a confirmed exploit (
          <span style={{ color: 'var(--unk)' }}>UNKNOWN ≠ exploited</span>). It is never folded into ASR.
        </p>
        <p style={{ margin: 0 }}>
          Bundled runs are synthetic <code className="inline">--target mock</code> output. This
          console performs no network I/O and surfaces no credentials or live memory.
        </p>
      </footer>
    </div>
  )
}
