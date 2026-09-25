import { useMemo, useState } from 'react'

// report.html / threat-report.html are fully self-contained HTML documents.
// We render them in a sandboxed iframe via srcDoc — no scripts allowed to run,
// no same-origin access, no network. It stays a static, offline preview. An
// "open in new tab" uses a blob: URL so the operator can view the original.
export function ReportFrame({ title, html }: { title: string; html: string }) {
  const [open, setOpen] = useState(false)
  const blobUrl = useMemo(() => {
    const blob = new Blob([html], { type: 'text/html' })
    return URL.createObjectURL(blob)
  }, [html])

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
        <button className="btn" onClick={() => setOpen((v) => !v)}>
          {open ? 'Hide' : 'Preview'} {title}
        </button>
        <a className="btn" href={blobUrl} target="_blank" rel="noreferrer noopener">
          Open {title} in new tab
        </a>
      </div>
      {open && (
        <iframe
          className="report-frame"
          title={title}
          srcDoc={html}
          sandbox=""
          referrerPolicy="no-referrer"
        />
      )}
    </div>
  )
}
