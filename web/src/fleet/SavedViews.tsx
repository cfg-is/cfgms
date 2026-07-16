// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Saved-views panel (Story #2498) — mockup `pop-views` popup. A technician
 * can save the current fleet-view configuration (filter text, sort column +
 * direction, visible column set, page size) under a name, apply/rename/delete
 * views, and views survive reload.
 *
 * Storage: localStorage under the literal key 'cfgms.fleet.views' (registered
 * in the A7.2 source-scan allowlist in Login.test.tsx). The value is a JSON
 * object keyed by principal username so each user's views are independent.
 *
 * Security A10.2: configs parsed from localStorage are validated against the
 * expected shape and types before use; invalid or partial entries are silently
 * discarded and the component falls back to an empty view list.
 *
 * Tenant scope is NOT captured in a saved view — it is session chrome (the
 * scope switcher lives in the app bar, not the fleet panel).
 */
import { useEffect, useRef, useState } from 'react'
import type { ColumnKey } from './columns.ts'
import type { SortState } from './FleetTable.tsx'

export interface SavedViewConfig {
  name: string
  filter: string
  sort: SortState | null
  columns: ColumnKey[]
  pageSize: number
}

function isValidView(v: unknown): v is SavedViewConfig {
  if (typeof v !== 'object' || v === null) return false
  const rec = v as Record<string, unknown>
  if (typeof rec.name !== 'string' || rec.name === '') return false
  if (typeof rec.filter !== 'string') return false
  if (rec.sort !== null) {
    if (typeof rec.sort !== 'object' || rec.sort === null) return false
    const sort = rec.sort as Record<string, unknown>
    if (typeof sort.key !== 'string') return false
    if (sort.direction !== 1 && sort.direction !== -1) return false
  }
  if (!Array.isArray(rec.columns)) return false
  if (typeof rec.pageSize !== 'number') return false
  return true
}

// The storage key is written as a literal at each call site — required by the
// A7.2 source scan in Login.test.tsx which checks for literal string keys only.
// Key: 'cfgms.fleet.views'

function loadViews(username: string): SavedViewConfig[] {
  const raw = localStorage.getItem('cfgms.fleet.views')
  if (raw === null) return []
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return []
  const byUser = Object.entries(parsed as Record<string, unknown>).find(([k]) => k === username)?.[1]
  if (!Array.isArray(byUser)) return []
  return byUser.filter(isValidView)
}

function persistViews(username: string, views: SavedViewConfig[]): void {
  // Read and merge — preserve other users' data in the same key.
  const raw = localStorage.getItem('cfgms.fleet.views')
  let all: Record<string, unknown> = {}
  if (raw !== null) {
    try {
      const parsed = JSON.parse(raw)
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        all = parsed as Record<string, unknown>
      }
    } catch {
      // Ignore corrupt data; overwrite with our entry only.
    }
  }
  localStorage.setItem('cfgms.fleet.views', JSON.stringify({ ...all, [username]: views }))
}

export default function SavedViews({
  username,
  currentFilter,
  currentSort,
  currentColumns,
  currentPageSize,
  activeName,
  onApply,
  onRename,
}: {
  username: string
  currentFilter: string
  currentSort: SortState | null
  currentColumns: readonly ColumnKey[]
  currentPageSize: number
  activeName: string | null
  onApply: (config: SavedViewConfig) => void
  onRename?: (oldName: string, newName: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [views, setViews] = useState<SavedViewConfig[]>(() => loadViews(username))
  const [showSaveInput, setShowSaveInput] = useState(false)
  const [savingName, setSavingName] = useState('')
  const [renamingName, setRenamingName] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')
  const rootRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const renameInputRef = useRef<HTMLInputElement>(null)

  // Close on Escape + outside-click — consistent with ColumnPicker behavior.
  // When a rename is in progress, Escape cancels it without closing the popup.
  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        if (renamingName !== null) {
          setRenamingName(null)
          setRenameValue('')
          return
        }
        setOpen(false)
        setShowSaveInput(false)
        setSavingName('')
      }
    }
    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false)
        setShowSaveInput(false)
        setSavingName('')
        setRenamingName(null)
        setRenameValue('')
      }
    }
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('mousedown', onPointerDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('mousedown', onPointerDown)
    }
  }, [open, renamingName])

  // Auto-focus the name input when it appears.
  useEffect(() => {
    if (showSaveInput) inputRef.current?.focus()
  }, [showSaveInput])

  // Auto-focus the rename input when it appears.
  useEffect(() => {
    if (renamingName !== null) renameInputRef.current?.focus()
  }, [renamingName])

  function commitSave() {
    const name = savingName.trim()
    if (!name) return
    const newView: SavedViewConfig = {
      name,
      filter: currentFilter,
      sort: currentSort,
      columns: [...currentColumns],
      pageSize: currentPageSize,
    }
    // Overwrite existing view with same name; append otherwise.
    const next = [...views.filter((v) => v.name !== name), newView]
    setViews(next)
    persistViews(username, next)
    setSavingName('')
    setShowSaveInput(false)
    setOpen(false)
  }

  function handleDelete(name: string) {
    const next = views.filter((v) => v.name !== name)
    setViews(next)
    persistViews(username, next)
  }

  function handleApply(view: SavedViewConfig) {
    onApply(view)
    setOpen(false)
    setRenamingName(null)
    setRenameValue('')
  }

  function startRename(name: string) {
    setRenamingName(name)
    setRenameValue(name)
  }

  function commitRename() {
    const newName = renameValue.trim()
    const oldName = renamingName
    setRenamingName(null)
    setRenameValue('')
    if (!newName || oldName === null || newName === oldName) return
    const next = views
      .filter((v) => v.name !== newName)
      .map((v) => (v.name === oldName ? { ...v, name: newName } : v))
    setViews(next)
    persistViews(username, next)
    onRename?.(oldName, newName)
    setOpen(false)
  }

  function cancelRename() {
    setRenamingName(null)
    setRenameValue('')
  }

  return (
    <div className="colpicker" ref={rootRef}>
      <button
        type="button"
        className="colbtn"
        aria-expanded={open}
        aria-label={`Views: ${activeName ?? 'All stewards'}`}
        onClick={() => setOpen((was) => !was)}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M4 6h16M7 12h10M10 18h4"
            stroke="currentColor"
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
        {activeName ?? 'All stewards'}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M8 10l4 4 4-4"
            stroke="currentColor"
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>
      {open && (
        <div className="pop open colpop viewpop" role="group" aria-label="Saved views">
          <h4>Saved views</h4>
          {views.map((view) => (
            <div key={view.name} className={`viewrow${activeName === view.name ? ' cur' : ''}`}>
              {renamingName === view.name ? (
                <input
                  ref={renameInputRef}
                  type="text"
                  className="view-rename-input"
                  value={renameValue}
                  aria-label={`Rename "${view.name}"`}
                  onChange={(e) => setRenameValue(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitRename()
                    if (e.key === 'Escape') cancelRename()
                  }}
                />
              ) : (
                <>
                  <button
                    type="button"
                    className="view-name"
                    onClick={() => handleApply(view)}
                  >
                    {view.name}
                  </button>
                  <button
                    type="button"
                    className="view-rename"
                    aria-label={`Rename view "${view.name}"`}
                    onClick={() => startRename(view.name)}
                  >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path
                        d="M16 3l5 5L7 22H2v-5L16 3z"
                        stroke="currentColor"
                        strokeWidth="1.7"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </button>
                  <button
                    type="button"
                    className="view-del"
                    aria-label={`Delete view "${view.name}"`}
                    onClick={() => handleDelete(view.name)}
                  >
                    ×
                  </button>
                </>
              )}
            </div>
          ))}
          <div className="sep" />
          {showSaveInput ? (
            <div className="view-save-row">
              <input
                ref={inputRef}
                type="text"
                placeholder="View name"
                value={savingName}
                onChange={(e) => setSavingName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') commitSave()
                  if (e.key === 'Escape') {
                    setShowSaveInput(false)
                    setSavingName('')
                  }
                }}
                aria-label="Saved view name"
              />
              <button type="button" onClick={commitSave}>
                Save
              </button>
            </div>
          ) : (
            <div
              role="button"
              tabIndex={0}
              className="row"
              onClick={() => setShowSaveInput(true)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') setShowSaveInput(true)
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M12 5v14M5 12h14"
                  stroke="currentColor"
                  strokeWidth="1.7"
                  strokeLinecap="round"
                />
              </svg>
              Save current view…
            </div>
          )}
        </div>
      )}
    </div>
  )
}
