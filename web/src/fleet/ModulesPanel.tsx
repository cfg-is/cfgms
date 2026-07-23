// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Modules tab panel (Story #2940) — loaded modules for one steward.
 * Fetches GET /api/v1/stewards/{id}/modules using useParams for the steward
 * ID, following the DnaDrawer self-contained panel pattern (no props required).
 *
 * A 501 MODULES_UNAVAILABLE response is a distinct UI state: the steward's
 * DNA doesn't include module data, which indicates an older steward version
 * rather than an infrastructure failure — so it renders an informational
 * notice rather than an error alert. Untrusted wire data is validated by
 * parseModulesResponse before rendering.
 */
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { apiFetch } from '../api/client.ts'

export interface StewardModule {
  name: string
}

/** Validate the modules response payload (untrusted wire data). Throws on invalid shape. */
export function parseModulesResponse(data: unknown): StewardModule[] {
  if (typeof data !== 'object' || data === null) {
    throw new Error('unexpected response shape')
  }
  const r = data as Record<string, unknown>
  if (!Array.isArray(r.modules)) {
    throw new Error('unexpected response shape')
  }
  return r.modules
    .filter((m): m is Record<string, unknown> => typeof m === 'object' && m !== null)
    .filter((m) => typeof m.name === 'string' && (m.name as string).length > 0)
    .map((m) => ({ name: m.name as string }))
}

interface FetchOutcome {
  key: string
  modules?: StewardModule[]
  error?: string
  unavailable?: true
}

export default function ModulesPanel() {
  const { id: stewardId = '' } = useParams<{ id: string }>()
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const key = `${stewardId}:${attempt}`

  useEffect(() => {
    let cancelled = false
    const path = `/api/v1/stewards/${encodeURIComponent(stewardId)}/modules`
    apiFetch(path)
      .then(async (response) => {
        if (response.status === 501) {
          if (!cancelled) setOutcome({ key, unavailable: true })
          return
        }
        if (!response.ok) {
          throw new Error(`GET ${path} — ${response.status}`)
        }
        const body: unknown = await response.json()
        const modules = parseModulesResponse((body as Record<string, unknown> | null)?.data)
        if (!cancelled) setOutcome({ key, modules })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : `GET ${path} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, stewardId])

  const current = outcome?.key === key ? outcome : null

  return (
    <div className="det">
      <div className="db">
        {current === null ? (
          <div data-testid="modules-loading" aria-label="Loading steward modules">
            {Array.from({ length: 4 }, (_, i) => (
              <div className="kv" key={i}>
                <span className="skel" style={{ width: '40%' }} />
              </div>
            ))}
          </div>
        ) : current.unavailable === true ? (
          <div className="notice" data-testid="modules-unavailable">
            <p>
              Module information isn&apos;t available for this steward. The steward may be
              running an older version that doesn&apos;t report loaded modules.
            </p>
          </div>
        ) : current.error !== undefined ? (
          <div className="notice err" role="alert" data-testid="modules-error">
            <div className="ic">!</div>
            <h3>Couldn&apos;t load modules</h3>
            <p>Module data for this steward isn&apos;t available right now.</p>
            <span className="mono2 detail">{current.error}</span>
            <button
              type="button"
              className="btn"
              onClick={() => setAttempt((n) => n + 1)}
            >
              Retry
            </button>
          </div>
        ) : current.modules !== undefined && current.modules.length === 0 ? (
          <div className="notice" data-testid="modules-empty">
            <p>No modules loaded on this steward.</p>
          </div>
        ) : (
          current.modules !== undefined && (
            <div className="module-list" data-testid="modules-list">
              <div className="grp">
                <div className="lbl">Loaded modules</div>
              </div>
              {current.modules.map((mod) => (
                <div key={mod.name} className="kv">
                  <span className="v mono2">{mod.name}</span>
                </div>
              ))}
            </div>
          )
        )}
      </div>
    </div>
  )
}
