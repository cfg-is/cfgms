// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Saved fleet views (Story #2498) — mockup `pop-views`. A view captures the
 * current fleet configuration (filter text, sort, visible column set, page
 * size) under a technician-chosen name; applying one restores that state
 * exactly. Tenant scope is session chrome (mockup), never captured.
 *
 * Views persist in localStorage under the literal key 'cfgms.fleet.views'
 * (registered in Login.test.tsx STORAGE_ALLOWLIST) as a record keyed per
 * principal: { [username]: SavedView[] }. There is no server-side
 * persistence endpoint in this epic — sharing/roaming is future work.
 * Everything read back from localStorage is UNTRUSTED input and is
 * shape- and type-validated before use (security A10.2); a view that fails
 * validation is dropped, valid siblings survive.
 */
import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'
import { COLUMNS, DEFAULT_VISIBLE, type ColumnKey } from './columns.ts'

export const PAGE_SIZES = [25, 50, 100, 250] as const
export const DEFAULT_PAGE_SIZE = 50
export const MAX_SAVED_VIEWS = 50

const MAX_NAME_LEN = 80
const MAX_FILTER_LEN = 512

export interface ViewSort {
  key: ColumnKey
  direction: 1 | -1
}

export interface ViewConfig {
  filter: string
  sort: ViewSort | null
  columns: ColumnKey[]
  pageSize: number
}

export interface SavedView {
  name: string
  config: ViewConfig
}

export const DEFAULT_CONFIG: ViewConfig = {
  filter: '',
  sort: null,
  columns: [...DEFAULT_VISIBLE],
  pageSize: DEFAULT_PAGE_SIZE,
}

const VALID_COLUMN_KEYS = new Set<string>(COLUMNS.map((c) => c.key))

/** Canonical column order (registry order) so config comparison is stable. */
export function canonicalColumns(keys: Iterable<ColumnKey>): ColumnKey[] {
  const wanted = new Set<ColumnKey>(keys)
  wanted.add('name')
  return COLUMNS.filter((c) => wanted.has(c.key)).map((c) => c.key)
}

export function sameConfig(a: ViewConfig, b: ViewConfig): boolean {
  return (
    a.filter === b.filter &&
    a.pageSize === b.pageSize &&
    (a.sort === null
      ? b.sort === null
      : b.sort !== null &&
        a.sort.key === b.sort.key &&
        a.sort.direction === b.sort.direction) &&
    canonicalColumns(a.columns).join() === canonicalColumns(b.columns).join()
  )
}

function parseSort(value: unknown): ViewSort | null | undefined {
  if (value === null) return null
  if (typeof value !== 'object') return undefined
  const record = value as Record<string, unknown>
  if (typeof record.key !== 'string' || !VALID_COLUMN_KEYS.has(record.key)) {
    return undefined
  }
  if (record.direction !== 1 && record.direction !== -1) return undefined
  return { key: record.key as ColumnKey, direction: record.direction }
}

/** Validate one stored view; null when anything about it is off-shape. */
function parseView(value: unknown): SavedView | null {
  if (typeof value !== 'object' || value === null) return null
  const record = value as Record<string, unknown>
  const { name, config } = record
  if (typeof name !== 'string' || name === '' || name.length > MAX_NAME_LEN) {
    return null
  }
  if (typeof config !== 'object' || config === null) return null
  const c = config as Record<string, unknown>
  if (typeof c.filter !== 'string' || c.filter.length > MAX_FILTER_LEN) {
    return null
  }
  const sort = parseSort(c.sort)
  if (sort === undefined) return null
  if (
    !Array.isArray(c.columns) ||
    !c.columns.every(
      (k): k is ColumnKey => typeof k === 'string' && VALID_COLUMN_KEYS.has(k),
    )
  ) {
    return null
  }
  if (
    typeof c.pageSize !== 'number' ||
    !PAGE_SIZES.some((size) => size === c.pageSize)
  ) {
    return null
  }
  return {
    name,
    config: {
      filter: c.filter,
      sort,
      columns: canonicalColumns(c.columns),
      pageSize: c.pageSize,
    },
  }
}

/**
 * Parse the whole stored record ({ [principal]: SavedView[] }) from raw
 * localStorage text. Untrusted input: anything off-shape degrades to the
 * empty record / empty list, never a crash.
 */
export function parseSavedViews(raw: string | null): Record<string, SavedView[]> {
  if (raw === null) return {}
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return {}
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return {}
  }
  const entries: [string, SavedView[]][] = []
  for (const [principal, entry] of Object.entries(parsed)) {
    if (!Array.isArray(entry)) continue
    const views: SavedView[] = []
    for (const candidate of entry) {
      const view = parseView(candidate)
      if (view !== null && !views.some((v) => v.name === view.name)) {
        views.push(view)
      }
      if (views.length >= MAX_SAVED_VIEWS) break
    }
    entries.push([principal, views])
  }
  return Object.fromEntries(entries)
}

export function loadViews(principal: string): SavedView[] {
  const record = parseSavedViews(localStorage.getItem('cfgms.fleet.views'))
  return Object.entries(record).find(([key]) => key === principal)?.[1] ?? []
}

/** Persist one principal's views, preserving every other principal's. */
export function saveViews(principal: string, views: SavedView[]): void {
  const record = parseSavedViews(localStorage.getItem('cfgms.fleet.views'))
  const next = Object.fromEntries([
    ...Object.entries(record).filter(([key]) => key !== principal),
    [principal, views.slice(0, MAX_SAVED_VIEWS)],
  ])
  localStorage.setItem('cfgms.fleet.views', JSON.stringify(next))
}

type Editing =
  | { kind: 'save' }
  | { kind: 'rename'; name: string }
  | null

export default function SavedViews({
  current,
  onApply,
}: {
  current: ViewConfig
  onApply: (config: ViewConfig) => void
}) {
  const { principal } = useAuth()
  const username = principal?.username ?? ''
  const [open, setOpen] = useState(false)
  // Loaded once per mount: a principal change always goes through the
  // signedOut/expired auth states, which unmount the shell (RequireAuth
  // swaps to the login screen), so this state can never go stale.
  const [views, setViews] = useState<SavedView[]>(() => loadViews(username))
  const [editing, setEditing] = useState<Editing>(null)
  const [draftName, setDraftName] = useState('')
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false)
    }
    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('mousedown', onPointerDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('mousedown', onPointerDown)
    }
  }, [open])

  function persist(next: SavedView[]) {
    setViews(next)
    saveViews(username, next)
  }

  function submitName() {
    const name = draftName.trim().slice(0, MAX_NAME_LEN)
    if (name === '' || editing === null) return
    if (editing.kind === 'save') {
      const next = views.filter((v) => v.name !== name)
      next.push({ name, config: { ...current, columns: canonicalColumns(current.columns) } })
      persist(next)
    } else {
      const next = views
        .filter((v) => v.name !== name || v.name === editing.name)
        .map((v) => (v.name === editing.name ? { ...v, name } : v))
      persist(next)
    }
    setEditing(null)
    setDraftName('')
  }

  function applyView(config: ViewConfig) {
    onApply({ ...config, columns: [...config.columns], sort: config.sort && { ...config.sort } })
    setOpen(false)
  }

  const activeName =
    views.find((v) => sameConfig(v.config, current))?.name ??
    (sameConfig(current, DEFAULT_CONFIG) ? 'All stewards' : 'Custom')

  return (
    <div className="viewpicker" ref={rootRef}>
      <button
        type="button"
        className="vbtn"
        aria-expanded={open}
        onClick={() => {
          setEditing(null)
          setOpen((was) => !was)
        }}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 6h16M7 12h10M10 18h4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
        </svg>
        View: <span className="viewname">{activeName}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M8 10l4 4 4-4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <div className="pop open viewpop" role="group" aria-label="Saved views">
          <h4>Saved views</h4>
          <button
            type="button"
            className={`row${activeName === 'All stewards' ? ' cur' : ''}`}
            onClick={() => applyView(DEFAULT_CONFIG)}
          >
            All stewards
          </button>
          {views.map((view) => (
            <div
              className={`row viewrow${view.name === activeName ? ' cur' : ''}`}
              key={view.name}
            >
              <button
                type="button"
                className="viewapply"
                onClick={() => applyView(view.config)}
              >
                {view.name}
              </button>
              <button
                type="button"
                className="viewact"
                aria-label={`Rename ${view.name}`}
                onClick={() => {
                  setEditing({ kind: 'rename', name: view.name })
                  setDraftName(view.name)
                }}
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M4 20l1-4L16 5l3 3L8 19l-4 1z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
                </svg>
              </button>
              <button
                type="button"
                className="viewact"
                aria-label={`Delete ${view.name}`}
                onClick={() => persist(views.filter((v) => v.name !== view.name))}
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                </svg>
              </button>
            </div>
          ))}
          <div className="sep" />
          {editing === null ? (
            <button
              type="button"
              className="row"
              onClick={() => {
                setEditing({ kind: 'save' })
                setDraftName('')
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M12 5v14M5 12h14" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
              </svg>
              Save current view…
            </button>
          ) : (
            <form
              className="viewform"
              onSubmit={(event) => {
                event.preventDefault()
                submitName()
              }}
            >
              <input
                aria-label="View name"
                autoFocus
                maxLength={MAX_NAME_LEN}
                placeholder="View name"
                value={draftName}
                onChange={(event) => setDraftName(event.target.value)}
              />
              <button type="submit" disabled={draftName.trim() === ''}>
                Save
              </button>
            </form>
          )}
        </div>
      )}
    </div>
  )
}
