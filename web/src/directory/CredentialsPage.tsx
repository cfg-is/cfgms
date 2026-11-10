// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Pending credentials page (Issue #5566) — the /directory/credentials route. Lists the
 * pending one-time initial-password records (resource id, created, expires) from
 * GET /api/v1/directory/credentials and opens RevealDialog for one. The list never
 * carries a value; the page holds only the record the dialog is open for.
 *
 * Security A9.1: all wire values render as JSX text, never as HTML.
 */
import { useCallback, useEffect, useState } from 'react'
import ErrorCard from '../shell/ErrorCard.tsx'
import { listCredentials, type PendingCredential } from './credentialsApi.ts'
import RevealDialog from './RevealDialog.tsx'

interface Outcome {
  key: number
  data?: PendingCredential[]
  error?: string
}

export default function CredentialsPage() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [selected, setSelected] = useState<PendingCredential | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    listCredentials()
      .then((data) => {
        if (!cancelled) setOutcome({ key: attempt, data })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key: attempt,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/directory/credentials — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [attempt])

  const current = outcome?.key === attempt ? outcome : null
  const loading = current === null && outcome === null
  const items = (current ?? outcome)?.data ?? []
  const error = current?.error ?? null

  return (
    <>
      <div className="htitle">
        <h1>Credentials</h1>
        <p>Initial passwords generated for accounts declared in configuration. Each can be revealed once.</p>
      </div>

      {loading ? (
        <div data-testid="credentials-loading" aria-label="Loading credentials">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '40%' }} />
              <span className="skel" style={{ width: '25%' }} />
              <span className="skel" style={{ width: '25%' }} />
            </div>
          ))}
        </div>
      ) : error !== null ? (
        <ErrorCard heading="Couldn't load credentials" detail={error} onRetry={retry} />
      ) : items.length === 0 ? (
        <div className="notice empty" data-testid="credentials-empty">
          <div className="ic">◍</div>
          <h3>No pending credentials</h3>
          <p>Initial passwords awaiting reveal will appear here.</p>
        </div>
      ) : (
        <section className="panel">
          <table className="tbl" data-testid="credentials-table">
            <thead>
              <tr>
                <th>Resource</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} data-testid="credential-row">
                  <td className="mono2" data-testid="credential-resource">{item.resource_id || '—'}</td>
                  <td className="mono2" data-testid="credential-created">{item.created_at || '—'}</td>
                  <td className="mono2" data-testid="credential-expires">{item.expires_at || '—'}</td>
                  <td>
                    <button
                      type="button"
                      className="wf-btn-sm"
                      onClick={() => setSelected(item)}
                      data-testid={`credential-reveal-btn-${item.id}`}
                    >
                      Reveal…
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {selected !== null && (
        <RevealDialog credential={selected} onClose={() => setSelected(null)} onRevealed={retry} />
      )}
    </>
  )
}
