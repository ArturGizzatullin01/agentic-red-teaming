import { useRef, useState } from 'react'
import { ParseError, parseRun, type RawFiles } from '../lib/parse'
import type { RunArtifacts } from '../lib/types'

// Load a run from files the operator picks locally. Everything is read with
// FileReader in the browser — nothing is uploaded anywhere. This is how an
// operator views their own runs/<name>/ without rebuilding the app: pick the
// artifact files (campaign.json required; attempts.jsonl, budget-ledger.jsonl,
// findings.json, report.html optional) and it renders through the same parser.
export function LocalLoader({ onLoaded }: { onLoaded: (run: RunArtifacts) => void }) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function ingest(fileList: FileList | File[]) {
    setError(null)
    const files = Array.from(fileList)
    if (files.length === 0) return
    const raw: RawFiles = {}
    let slug = 'local-run'
    for (const file of files) {
      // Prefer the directory name when a folder was picked.
      const rel = (file as File & { webkitRelativePath?: string }).webkitRelativePath
      if (rel && rel.includes('/')) slug = rel.split('/')[0]
      const key = file.name
      raw[key] = await file.text()
    }
    try {
      const run = parseRun(slug, raw)
      onLoaded(run)
    } catch (err) {
      setError(err instanceof ParseError ? err.message : `Could not read run: ${String(err)}`)
    }
  }

  return (
    <div
      className={`dropzone ${drag ? 'drag' : ''}`}
      onDragOver={(e) => {
        e.preventDefault()
        setDrag(true)
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => {
        e.preventDefault()
        setDrag(false)
        void ingest(e.dataTransfer.files)
      }}
    >
      <p style={{ margin: '0 0 8px' }}>
        Load a local run — drop its artifact files here, or{' '}
        <button className="btn" onClick={() => inputRef.current?.click()}>
          choose files
        </button>
      </p>
      <p style={{ margin: 0, fontSize: 12 }}>
        Pick <code className="inline">campaign.json</code> (required) plus any of{' '}
        <code className="inline">attempts.jsonl</code>,{' '}
        <code className="inline">budget-ledger.jsonl</code>,{' '}
        <code className="inline">findings.json</code>, <code className="inline">report.html</code>.
        Files stay in your browser — nothing is uploaded.
      </p>
      <input
        ref={inputRef}
        type="file"
        multiple
        accept=".json,.jsonl,.html"
        style={{ display: 'none' }}
        onChange={(e) => {
          if (e.target.files) void ingest(e.target.files)
          e.target.value = ''
        }}
      />
      {error && (
        <p style={{ color: 'var(--fail)', marginTop: 10, fontSize: 12 }}>{error}</p>
      )}
    </div>
  )
}
