// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Bulk action bar (Story #2939) — appears above the fleet panel when ≥1 row is
 * selected. "Edit tags" issues one authorized POST or DELETE per selected
 * steward, never a batch endpoint that would bypass per-steward tenant checks.
 * Per-item failure is surfaced per steward — never swallowed into a single
 * pass/fail result.
 *
 * Design source: docs/design/mockups/fleet-bulk.html (founder-approved
 * 2026-07-24). No decommission affordance of any kind — Section 2's follow-on
 * epic owns that.
 *
 * Security A9.1: steward IDs and tag values reach the DOM through JSX text
 * nodes only — no dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface TagOpResult {
  id: string
  ok: boolean
  status?: number
}

type Mode =
  | { kind: 'bar' }
  | { kind: 'editTags' }
  | { kind: 'results'; op: 'add' | 'remove'; tag: string; results: TagOpResult[] }

export default function BulkActionBar({
  selectedIds,
  onClear,
}: {
  selectedIds: ReadonlySet<string>
  onClear: () => void
}) {
  const count = selectedIds.size
  const [mode, setMode] = useState<Mode>({ kind: 'bar' })
  const [tag, setTag] = useState('')
  const [busy, setBusy] = useState(false)

  async function runOp(op: 'add' | 'remove') {
    const tagVal = tag.trim()
    if (!tagVal) return
    setBusy(true)
    const method = op === 'add' ? 'POST' : 'DELETE'
    const results = await Promise.all(
      [...selectedIds].map(async (id): Promise<TagOpResult> => {
        try {
          const resp = await apiFetch(
            `/api/v1/stewards/${encodeURIComponent(id)}/tags`,
            {
              method,
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ tags: [tagVal] }),
            },
          )
          return { id, ok: resp.ok, status: resp.status }
        } catch {
          return { id, ok: false }
        }
      }),
    )
    setBusy(false)
    setMode({ kind: 'results', op, tag: tagVal, results })
  }

  function backToBar() {
    setMode({ kind: 'bar' })
    setTag('')
  }

  if (mode.kind === 'results') {
    const succeeded = mode.results.filter((r) => r.ok)
    const failed = mode.results.filter((r) => !r.ok)
    return (
      <div className="bulkbar" data-testid="bulk-action-bar">
        <span className="bulk-summary" data-testid="bulk-result-summary">
          {succeeded.length} of {mode.results.length} succeeded
          {failed.length > 0 && (
            <>
              {', '}
              {failed.length} failed: {failed.map((r) => r.id).join(', ')}
            </>
          )}
        </span>
        <span className="bulkbar-grow" />
        <button type="button" className="bbtn" onClick={backToBar}>
          Done
        </button>
      </div>
    )
  }

  if (mode.kind === 'editTags') {
    return (
      <div className="bulkbar" data-testid="bulk-action-bar">
        <span className="bulk-sel">
          <span className="bulk-n">{count}</span> selected
        </span>
        <input
          type="text"
          className="bulk-tag-in"
          placeholder="tag-name"
          aria-label="Tag name"
          value={tag}
          disabled={busy}
          onChange={(e) => setTag(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              e.stopPropagation()
              backToBar()
            }
          }}
        />
        <button
          type="button"
          className="bbtn bbtn-primary"
          disabled={busy || !tag.trim()}
          onClick={() => void runOp('add')}
        >
          Add to selected
        </button>
        <button
          type="button"
          className="bbtn"
          disabled={busy || !tag.trim()}
          onClick={() => void runOp('remove')}
        >
          Remove from selected
        </button>
        <button type="button" className="bbtn-clear" disabled={busy} onClick={backToBar}>
          Cancel
        </button>
      </div>
    )
  }

  return (
    <div className="bulkbar" data-testid="bulk-action-bar">
      <span className="bulk-sel">
        <span className="bulk-n">{count}</span> selected
      </span>
      <span className="bulkbar-grow" />
      <button
        type="button"
        className="bbtn bbtn-primary"
        onClick={() => setMode({ kind: 'editTags' })}
      >
        Edit tags
      </button>
      <button type="button" className="bbtn-clear" onClick={onClear}>
        Clear
      </button>
    </div>
  )
}
