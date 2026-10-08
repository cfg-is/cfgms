// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Read-only YAML mirror of the builder canvas (Issue #4619).
 *
 * The draft is POSTed to /api/v1/workflows/render-yaml after a debounce; the
 * server renderer is the authority, so the pane never composes YAML itself.
 * Only the latest response is applied — a slow earlier response cannot
 * overwrite a newer one.
 *
 * Security A9.1: server text renders as text nodes only.
 */
import { useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export const YAML_DEBOUNCE_MS = 400

type PaneState =
  | { kind: 'loading' }
  | { kind: 'ready'; text: string }
  | { kind: 'error'; message: string }

interface YamlPaneProps {
  /** The workflow draft, in the shape POST /api/v1/workflows accepts. */
  body: Record<string, unknown>
  debounceMs?: number
}

async function serverMessage(response: Response): Promise<string> {
  const parsed = (await response.json().catch(() => null)) as Record<string, unknown> | null
  const msg = parsed?.error
  return typeof msg === 'string' && msg ? msg : `Render failed — ${response.status}`
}

function indentDepth(line: string): number {
  return Math.floor((line.length - line.trimStart().length) / 2)
}

export default function YamlPane({ body, debounceMs = YAML_DEBOUNCE_MS }: YamlPaneProps) {
  const [state, setState] = useState<PaneState>({ kind: 'loading' })
  const key = JSON.stringify(body)

  useEffect(() => {
    let stale = false
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const response = await apiFetch('/api/v1/workflows/render-yaml', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: key,
          })
          const next: PaneState = response.ok
            ? { kind: 'ready', text: await response.text() }
            : { kind: 'error', message: await serverMessage(response) }
          if (!stale) setState(next)
        } catch (cause: unknown) {
          if (stale) return
          setState({
            kind: 'error',
            message: cause instanceof Error && cause.message ? cause.message : 'Render failed',
          })
        }
      })()
    }, debounceMs)
    return () => {
      clearTimeout(timer)
      // Invalidate any request already in flight for this draft.
      stale = true
    }
  }, [key, debounceMs])

  const lines = state.kind === 'ready' && state.text.trim() !== '' ? state.text.replace(/\n$/, '').split('\n') : []

  return (
    <aside className="bld-yaml" aria-label="Workflow YAML" data-testid="yaml-pane">
      <div className="bld-yaml-head"><b>workflow.yaml</b></div>
      {state.kind === 'loading' && (
        <div className="bld-yaml-note" data-testid="yaml-loading">Rendering…</div>
      )}
      {state.kind === 'error' && (
        <div className="bld-yaml-note wf-form-error" role="alert" data-testid="yaml-error">
          {state.message}
        </div>
      )}
      {state.kind === 'ready' && lines.length === 0 && (
        <div className="bld-yaml-note" data-testid="yaml-empty">Nothing to show yet.</div>
      )}
      {state.kind === 'ready' && lines.length > 0 && (
        <pre className="bld-yaml-code" data-testid="yaml-code">
          {lines.map((line, i) => (
            <div className="bld-yaml-line" key={i} data-testid="yaml-line">
              <span className="bld-yaml-ln" aria-hidden="true">{i + 1}</span>
              <span
                className="bld-yaml-text"
                style={{ ['--depth' as string]: indentDepth(line) }}
              >
                {line}
              </span>
            </div>
          ))}
        </pre>
      )}
    </aside>
  )
}
