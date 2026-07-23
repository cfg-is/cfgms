// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Per-row action menu (Story #2938) — mockup `.rowkebab` / `.pop .row` pattern
 * from `asset-live-activity.html` lines 204-205/500, applied to FleetTable.
 *
 * The component is structured as an ordered MenuItemSpec list so later entries
 * can be appended without restructuring the JSX. Only tag edit is wired in
 * this story — move-tenant and decommission are out of scope (Section 2).
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

export default function RowActionMenu({ stewardId }: { stewardId: string }) {
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<'menu' | 'tags'>('menu')
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
        </div>
      )}
    </div>
  )
}
