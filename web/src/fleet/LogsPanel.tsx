// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Logs tab panel (Story #2940) — chronological log records for one steward.
 * Fetches GET /api/v1/stewards/{id}/logs using useParams for the steward ID,
 * following the DnaDrawer self-contained panel pattern (no props required).
 *
 * Each log record may be a standalone detection or a correlated
 * detection+outcome pair (ADR-012 §2). Untrusted wire data is validated
 * by parseLogsResponse before rendering; values reach the DOM as JSX text
 * nodes only — no dangerouslySetInnerHTML.
 */
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { apiFetch } from '../api/client.ts'

export interface LogEvent {
  timestamp: string
  level: string
  message: string
  component: string
}

export interface LogRecord {
  correlationId: string
  detection: LogEvent
  outcome: LogEvent | null
  pendingOutcome: boolean
}

function parseLogEvent(raw: unknown): LogEvent | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  return {
    timestamp: str(r.timestamp),
    level: str(r.level),
    message: str(r.message),
    component: str(r.component),
  }
}

/** Validate the logs response payload (untrusted wire data). Throws on invalid shape. */
export function parseLogsResponse(data: unknown): LogRecord[] {
  if (typeof data !== 'object' || data === null) {
    throw new Error('unexpected response shape')
  }
  const r = data as Record<string, unknown>
  if (!Array.isArray(r.events)) {
    throw new Error('unexpected response shape')
  }
  const records: LogRecord[] = []
  for (const item of r.events) {
    if (typeof item !== 'object' || item === null) continue
    const entry = item as Record<string, unknown>
    const detection = parseLogEvent(entry.detection)
    if (!detection) continue
    const outcome = entry.outcome != null ? parseLogEvent(entry.outcome) : null
    records.push({
      correlationId: typeof entry.correlation_id === 'string' ? entry.correlation_id : '',
      detection,
      outcome,
      pendingOutcome: entry.pending_outcome === true,
    })
  }
  return records
}

interface FetchOutcome {
  key: string
  records?: LogRecord[]
  error?: string
}

function LogEventRow({ event, label }: { event: LogEvent; label?: string }) {
  return (
    <div className="log-event">
      {label !== undefined && <span className="log-event-label">{label}</span>}
      <span className="log-ts mono2">{event.timestamp}</span>
      <span className="log-lv">{event.level}</span>
      {event.component !== '' && <span className="log-comp mono2">{event.component}</span>}
      <span className="log-msg">{event.message}</span>
    </div>
  )
}

export default function LogsPanel() {
  const { id: stewardId = '' } = useParams<{ id: string }>()
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const key = `${stewardId}:${attempt}`

  useEffect(() => {
    let cancelled = false
    const path = `/api/v1/stewards/${encodeURIComponent(stewardId)}/logs`
    apiFetch(path)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET ${path} — ${response.status}`)
        }
        const body: unknown = await response.json()
        const records = parseLogsResponse((body as Record<string, unknown> | null)?.data)
        if (!cancelled) setOutcome({ key, records })
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
          <div data-testid="logs-loading" aria-label="Loading steward logs">
            {Array.from({ length: 5 }, (_, i) => (
              <div className="log-skel" key={i}>
                <span className="skel" style={{ width: '15%' }} />
                <span className="skel" style={{ width: '5%' }} />
                <span className="skel" style={{ width: '60%' }} />
              </div>
            ))}
          </div>
        ) : current.error !== undefined ? (
          <div className="notice err" role="alert">
            <div className="ic">!</div>
            <h3>Couldn&apos;t load steward logs</h3>
            <p>Log data for this steward isn&apos;t available right now.</p>
            <span className="mono2 detail">{current.error}</span>
            <button
              type="button"
              className="btn"
              onClick={() => setAttempt((n) => n + 1)}
            >
              Retry
            </button>
          </div>
        ) : current.records !== undefined && current.records.length === 0 ? (
          <div className="notice" data-testid="logs-empty">
            <p>No log entries for this steward in the selected time range.</p>
          </div>
        ) : (
          current.records !== undefined && (
            <div className="log-list" data-testid="logs-list">
              {current.records.map((record, i) => (
                <div key={record.correlationId || i} className="log-record">
                  <LogEventRow event={record.detection} />
                  {record.pendingOutcome && (
                    <div className="log-pending" data-testid="log-pending">
                      Convergence pending
                    </div>
                  )}
                  {record.outcome !== null && (
                    <LogEventRow event={record.outcome} label="→" />
                  )}
                </div>
              ))}
            </div>
          )
        )}
      </div>
    </div>
  )
}
