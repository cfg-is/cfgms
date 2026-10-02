// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Per-row action menu (Story #2938, #2972) — mockup `.rowkebab` / `.pop .row`
 * pattern from `asset-live-activity.html` lines 204-205/500, applied to
 * FleetTable.
 *
 * The component is structured as an ordered MenuItemSpec list so later entries
 * can be appended without restructuring the JSX. Story #2972 adds move-tenant
 * and decommission behind CFGMS-StepUp (elevation path, AssuranceStrong);
 * step-up fires automatically via apiFetch on a 401 with WWW-Authenticate:
 * CFGMS-StepUp — no special handling is needed in this component.
 *
 * Popover lifecycle (Escape + outside-click) is a verbatim reuse of the
 * pattern established by ColumnPicker.tsx and SavedViews.tsx.
 *
 * Security: tag values from the wire are validated by parseTags before render
 * (same parse-validate-untrusted-wire discipline as useStewards / DnaDrawer).
 * All tag strings reach the DOM through JSX text nodes only.
 */
import { useEffect, useRef, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface MenuItemSpec {
  id: string
  label: string
  onActivate: () => void
}

/** Validate the tag list from untrusted wire data (security A10.2). */
export function parseTags(data: unknown): string[] {
  if (typeof data !== 'object' || data === null) return []
  const record = data as Record<string, unknown>
  if (!Array.isArray(record.tags)) return []
  return record.tags.filter((t): t is string => typeof t === 'string')
}

function TagEditor({
  stewardId,
  onBack,
}: {
  stewardId: string
  onBack: () => void
}) {
  const [tags, setTags] = useState<string[] | null>(null)
  const [input, setInput] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/v1/stewards/${encodeURIComponent(stewardId)}/tags`)
      .then(async (resp) => {
        const body: unknown = await resp.json()
        if (cancelled) return
        if (!resp.ok) {
          setError(`Failed to load tags (${resp.status})`)
          return
        }
        setTags(parseTags((body as Record<string, unknown>)?.data))
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load tags')
      })
    return () => {
      cancelled = true
    }
  }, [stewardId])

  async function add(raw: string) {
    const tag = raw.trim()
    if (!tag) return
    setBusy(true)
    setError(null)
    try {
      const resp = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}/tags`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tags: [tag] }),
        },
      )
      const body: unknown = await resp.json()
      if (!resp.ok) {
        setError(`Failed to add tag (${resp.status})`)
        return
      }
      setTags(parseTags((body as Record<string, unknown>)?.data))
      setInput('')
    } catch {
      setError('Failed to add tag')
    } finally {
      setBusy(false)
    }
  }

  async function remove(tag: string) {
    setBusy(true)
    setError(null)
    try {
      const resp = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}/tags`,
        {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tags: [tag] }),
        },
      )
      const body: unknown = await resp.json()
      if (!resp.ok) {
        setError(`Failed to remove tag (${resp.status})`)
        return
      }
      setTags(parseTags((body as Record<string, unknown>)?.data))
    } catch {
      setError('Failed to remove tag')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="row-tag-editor">
      <div className="rtag-hd">
        <button type="button" className="rtag-back" aria-label="Back to menu" onClick={onBack}>
          ←
        </button>
        <span className="rtag-title">Edit tags</span>
      </div>
      {error !== null && (
        <div className="rtag-err" role="alert">
          {error}
        </div>
      )}
      {tags === null && error === null && <div className="rtag-spin">Loading…</div>}
      {tags !== null && (
        <div className="rtag-chips">
          {tags.length === 0 && <span className="rtag-empty">No tags</span>}
          {tags.map((tag) => (
            <span key={tag} className="rtag-chip">
              {tag}
              <button
                type="button"
                className="rtag-rm"
                aria-label={`Remove tag ${tag}`}
                disabled={busy}
                onClick={() => void remove(tag)}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="rtag-row">
        <input
          type="text"
          className="rtag-in"
          placeholder="add-tag"
          value={input}
          aria-label="New tag"
          disabled={busy}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              void add(input)
            }
          }}
        />
        <button
          type="button"
          className="rtag-btn"
          disabled={busy || !input.trim()}
          onClick={() => void add(input)}
        >
          Add
        </button>
      </div>
    </div>
  )
}

function MoveTenantPanel({
  stewardId,
  onBack,
}: {
  stewardId: string
  onBack: () => void
}) {
  const [tenantId, setTenantId] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)

  async function move() {
    const tid = tenantId.trim()
    if (!tid) return
    setBusy(true)
    setError(null)
    try {
      const resp = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}/move`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ new_tenant_id: tid }),
        },
      )
      if (!resp.ok) {
        setError(`Failed to move steward (${resp.status})`)
        return
      }
      setDone(true)
    } catch {
      setError('Failed to move steward')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="row-move-panel">
      <div className="rtag-hd">
        <button type="button" className="rtag-back" aria-label="Back to menu" onClick={onBack}>
          ←
        </button>
        <span className="rtag-title">Move to tenant</span>
      </div>
      {error !== null && (
        <div className="rtag-err" role="alert">
          {error}
        </div>
      )}
      {done ? (
        <div className="rmove-ok" role="status">
          Moved successfully
        </div>
      ) : (
        <div className="rtag-row">
          <input
            type="text"
            className="rtag-in"
            placeholder="tenant-id"
            aria-label="New tenant ID"
            value={tenantId}
            disabled={busy}
            onChange={(e) => setTenantId(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                void move()
              }
            }}
          />
          <button
            type="button"
            className="rtag-btn"
            disabled={busy || !tenantId.trim()}
            onClick={() => void move()}
          >
            Move
          </button>
        </div>
      )}
    </div>
  )
}

function DecommissionPanel({
  stewardId,
  onBack,
}: {
  stewardId: string
  onBack: () => void
}) {
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)

  async function decommission() {
    setBusy(true)
    setError(null)
    try {
      const resp = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}`,
        { method: 'DELETE' },
      )
      if (!resp.ok) {
        setError(`Failed to decommission (${resp.status})`)
        return
      }
      setDone(true)
    } catch {
      setError('Failed to decommission')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="row-decommission-panel">
      <div className="rtag-hd">
        <button type="button" className="rtag-back" aria-label="Back to menu" onClick={onBack}>
          ←
        </button>
        <span className="rtag-title">Decommission</span>
      </div>
      {error !== null && (
        <div className="rtag-err" role="alert">
          {error}
        </div>
      )}
      {done ? (
        <div className="rdecom-ok" role="status">
          Decommissioned
        </div>
      ) : (
        <div className="rdecom-confirm">
          <p className="rdecom-warn">This cannot be undone.</p>
          <button
            type="button"
            className="rtag-btn rtag-btn-danger"
            disabled={busy}
            onClick={() => void decommission()}
          >
            Confirm decommission
          </button>
        </div>
      )}
    </div>
  )
}

export default function RowActionMenu({ stewardId }: { stewardId: string }) {
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<'menu' | 'tags' | 'move' | 'decommission'>('menu')
  const wrapRef = useRef<HTMLDivElement>(null)

  /* Escape and outside-click lifecycle — verbatim reuse of ColumnPicker.tsx pattern. */
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setOpen(false)
        setMode('menu')
      }
    }
    function onDown(e: MouseEvent) {
      if (!wrapRef.current?.contains(e.target as Node)) {
        setOpen(false)
        setMode('menu')
      }
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onDown)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onDown)
    }
  }, [open])

  /* Ordered spec list — append later entries here without restructuring the JSX. */
  const MENU_ITEMS: MenuItemSpec[] = [
    { id: 'tags', label: 'Edit tags', onActivate: () => setMode('tags') },
    { id: 'move', label: 'Move to tenant', onActivate: () => setMode('move') },
    { id: 'decommission', label: 'Decommission', onActivate: () => setMode('decommission') },
  ]

  return (
    <div className="ram-wrap" ref={wrapRef}>
      <button
        type="button"
        className="rowkebab"
        aria-label="Actions"
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation()
          setOpen((was) => {
            if (was) setMode('menu')
            return !was
          })
        }}
        onKeyDown={(e) => {
          /* Stop Enter/Space from bubbling to the tr's onKeyDown so it doesn't
           * fire onRowSelect while the kebab button handles the keypress. */
          if (e.key === 'Enter' || e.key === ' ') e.stopPropagation()
        }}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="5" r="1.6" fill="currentColor" />
          <circle cx="12" cy="12" r="1.6" fill="currentColor" />
          <circle cx="12" cy="19" r="1.6" fill="currentColor" />
        </svg>
      </button>
      {open && (
        <div
          className="pop right ram-pop"
          role={mode === 'menu' ? 'menu' : undefined}
        >
          {mode === 'menu' &&
            MENU_ITEMS.map((item) => (
              <button
                key={item.id}
                type="button"
                className="row"
                role="menuitem"
                onClick={(e) => {
                  e.stopPropagation()
                  item.onActivate()
                }}
              >
                {item.label}
              </button>
            ))}
          {mode === 'tags' && (
            <TagEditor stewardId={stewardId} onBack={() => setMode('menu')} />
          )}
          {mode === 'move' && (
            <MoveTenantPanel stewardId={stewardId} onBack={() => setMode('menu')} />
          )}
          {mode === 'decommission' && (
            <DecommissionPanel stewardId={stewardId} onBack={() => setMode('menu')} />
          )}
        </div>
      )}
    </div>
  )
}
