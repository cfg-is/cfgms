// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Bulk action bar (Story #2939, #2972) — appears above the fleet panel when ≥1
 * row is selected. All bulk operations issue one authorized/audited call per
 * selected steward — never a batch endpoint that would bypass per-steward
 * tenant checks. Per-item failure is surfaced per steward, never swallowed into
 * a single aggregate pass/fail result.
 *
 * Move-tenant and decommission (Story #2972) are gated behind AssuranceStrong
 * step-up via apiFetch's automatic CFGMS-StepUp 401 handling. The bulk fan-out
 * issues concurrent per-steward calls; apiFetch's concurrent-dedup mechanism
 * ensures only one step-up ceremony fires even when multiple calls land 401
 * simultaneously, then all callers retry with the elevated session.
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
  | { kind: 'moveTenant' }
  | { kind: 'confirmDecommission' }
  | { kind: 'results'; op: 'add' | 'remove'; tag: string; results: TagOpResult[] }
  | { kind: 'moveTenantResults'; results: TagOpResult[] }
  | { kind: 'decommissionResults'; results: TagOpResult[] }

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
  const [targetTenantId, setTargetTenantId] = useState('')
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

  async function runMoveTenant() {
    const tid = targetTenantId.trim()
    if (!tid) return
    setBusy(true)
    const results = await Promise.all(
      [...selectedIds].map(async (id): Promise<TagOpResult> => {
        try {
          const resp = await apiFetch(
            `/api/v1/stewards/${encodeURIComponent(id)}/move`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ new_tenant_id: tid }),
            },
          )
          return { id, ok: resp.ok, status: resp.status }
        } catch {
          return { id, ok: false }
        }
      }),
    )
    setBusy(false)
    setMode({ kind: 'moveTenantResults', results })
  }

  async function runDecommission() {
    setBusy(true)
    const results = await Promise.all(
      [...selectedIds].map(async (id): Promise<TagOpResult> => {
        try {
          const resp = await apiFetch(
            `/api/v1/stewards/${encodeURIComponent(id)}`,
            { method: 'DELETE' },
          )
          return { id, ok: resp.ok, status: resp.status }
        } catch {
          return { id, ok: false }
        }
      }),
    )
    setBusy(false)
    setMode({ kind: 'decommissionResults', results })
  }

  function backToBar() {
    setMode({ kind: 'bar' })
    setTag('')
    setTargetTenantId('')
  }

  if (
    mode.kind === 'results' ||
    mode.kind === 'moveTenantResults' ||
    mode.kind === 'decommissionResults'
  ) {
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

  if (mode.kind === 'moveTenant') {
    return (
      <div className="bulkbar" data-testid="bulk-action-bar">
        <span className="bulk-sel">
          <span className="bulk-n">{count}</span> selected
        </span>
        <input
          type="text"
          className="bulk-tenant-in"
          placeholder="tenant-id"
          aria-label="Target tenant ID"
          value={targetTenantId}
          disabled={busy}
          onChange={(e) => setTargetTenantId(e.target.value)}
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
          disabled={busy || !targetTenantId.trim()}
          onClick={() => void runMoveTenant()}
        >
          Move selected
        </button>
        <button type="button" className="bbtn-clear" disabled={busy} onClick={backToBar}>
          Cancel
        </button>
      </div>
    )
  }

  if (mode.kind === 'confirmDecommission') {
    return (
      <div className="bulkbar" data-testid="bulk-action-bar">
        <span className="bulk-sel">
          <span className="bulk-n">{count}</span> selected
        </span>
        <span className="bulk-warn">
          Decommission {count} steward{count === 1 ? '' : 's'}? This cannot be undone.
        </span>
        <button
          type="button"
          className="bbtn bbtn-danger"
          disabled={busy}
          onClick={() => void runDecommission()}
        >
          Confirm decommission
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
      <button
        type="button"
        className="bbtn"
        onClick={() => setMode({ kind: 'moveTenant' })}
      >
        Move to tenant
      </button>
      <button
        type="button"
        className="bbtn bbtn-danger"
        onClick={() => setMode({ kind: 'confirmDecommission' })}
      >
        Decommission selected
      </button>
      <button type="button" className="bbtn-clear" onClick={onClear}>
        Clear
      </button>
    </div>
  )
}
