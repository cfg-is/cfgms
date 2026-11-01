// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * GenerateReportForm (Story #3271) — form that POSTs a ReportRequest-shaped
 * payload to POST /api/v1/reports/generate and triggers a browser blob download.
 *
 * Format selection: the endpoint is format-aware (json/csv/pdf/xlsx/html) but
 * the REST surface has no GetSupportedFormats discovery endpoint. The form
 * defaults to JSON-only for safety. The gap is noted here as a follow-up:
 * format options should be driven by template.supported_formats once the UI
 * has a reliable source for them (the TemplateInfo shape includes the list;
 * we use it below rather than a hardcoded guess, but only the formats actually
 * returned by the template are offered).
 *
 * Download mechanics: fetch response body → Blob → createObjectURL → ephemeral
 * <a download> click → revokeObjectURL. No download library required.
 * Content-Disposition filename is read from the response header if available.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import type { TemplateInfo } from './TemplateList.tsx'
import './ReportsDashboardView.css'

const FALLBACK_FORMAT = 'json'

function CritIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 4.8v4" />
      <path d="M8 11.2v.05" />
    </svg>
  )
}

function filenameFromContentDisposition(header: string | null, fallback: string): string {
  if (header) {
    const match = /filename="?([^";]+)"?/.exec(header)
    if (match?.[1]) return match[1]
  }
  return fallback
}

export default function GenerateReportForm({
  template,
  onBack,
}: {
  template: TemplateInfo
  onBack: () => void
}) {
  const formats =
    template.supported_formats.length > 0 ? template.supported_formats : [FALLBACK_FORMAT]
  const [format, setFormat] = useState(formats.includes(FALLBACK_FORMAT) ? FALLBACK_FORMAT : formats[0])
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  async function handleGenerate() {
    setGenerating(true)
    setError(null)
    setSuccess(false)

    const now = new Date()
    const start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
    const body = {
      type: template.type,
      template: template.name,
      format,
      time_range: {
        start: start.toISOString(),
        end: now.toISOString(),
      },
    }

    try {
      const response = await apiFetch('/api/v1/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      if (!response.ok) {
        throw new Error(`POST /api/v1/reports/generate — ${response.status}`)
      }

      const blob = await response.blob()
      const disposition = response.headers.get('Content-Disposition')
      const filename = filenameFromContentDisposition(
        disposition,
        `${template.name}.${format}`,
      )

      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      document.body.appendChild(anchor)
      anchor.click()
      document.body.removeChild(anchor)
      URL.revokeObjectURL(url)

      setSuccess(true)
    } catch (cause: unknown) {
      setError(
        cause instanceof Error && cause.message
          ? cause.message
          : 'POST /api/v1/reports/generate failed',
      )
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="rdb-panel">
      <div style={{ marginBottom: 'var(--space-2)' }}>
        <button
          type="button"
          className="rdb-btn"
          onClick={onBack}
          style={{ marginBottom: 'var(--space-3)' }}
        >
          ← Back
        </button>
        <h2 style={{ marginTop: 0 }}>{template.name}</h2>
        {template.description && (
          <p className="rdb-panel-sub">{template.description}</p>
        )}
      </div>

      {error !== null && (
        <div className="rdb-notice err" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <CritIcon />
          <div className="rdb-notice-body">
            <b>Report generation failed.</b>
            <p className="rdb-notice-sub">{error}</p>
          </div>
        </div>
      )}

      {success && (
        <div
          className="rdb-notice"
          data-testid="generate-success"
          style={{ marginBottom: 'var(--space-3)', borderStyle: 'solid', borderColor: 'var(--state-ok)', background: 'var(--state-ok-bg)', color: 'var(--state-ok)' }}
        >
          <p>Report generated and download started.</p>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        <div>
          <label
            htmlFor="report-format"
            style={{ display: 'block', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--space-1)' }}
          >
            Format
          </label>
          <select
            id="report-format"
            value={format}
            onChange={(e) => setFormat(e.target.value)}
            disabled={generating}
            style={{
              font: 'inherit',
              fontSize: 'var(--text-base)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              padding: '6px var(--space-2)',
              background: 'var(--bg-surface)',
              color: 'var(--text-primary)',
              cursor: 'pointer',
            }}
          >
            {formats.map((f) => (
              <option key={f} value={f}>
                {f.toUpperCase()}
              </option>
            ))}
          </select>
        </div>

        <div>
          <button
            type="button"
            className="rdb-btn"
            onClick={handleGenerate}
            disabled={generating}
            style={{
              background: generating ? undefined : 'var(--accent)',
              color: generating ? undefined : 'var(--accent-ink)',
              borderColor: 'var(--accent)',
            }}
          >
            {generating ? 'Generating…' : 'Generate'}
          </button>
        </div>
      </div>
    </div>
  )
}
