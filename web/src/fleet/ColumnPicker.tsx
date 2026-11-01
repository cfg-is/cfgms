// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Device-DNA column picker (Story #2497) — mockup `pop-cols`. Defaults and
 * opt-in columns are separated by a rule; Name is locked on. Popover follows
 * the shell overlay conventions: Escape and outside-click close it.
 */
import { useEffect, useRef, useState } from 'react'
import { COLUMNS, type ColumnKey } from './columns.ts'

export default function ColumnPicker({
  visible,
  onToggle,
}: {
  visible: ReadonlySet<ColumnKey>
  onToggle: (key: ColumnKey) => void
}) {
  const [open, setOpen] = useState(false)
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

  const defaults = COLUMNS.filter((c) => c.defaultVisible)
  const optIns = COLUMNS.filter((c) => !c.defaultVisible)

  return (
    <div className="colpicker" ref={rootRef}>
      <button
        type="button"
        className="colbtn"
        aria-expanded={open}
        onClick={() => setOpen((was) => !was)}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 5h16v14H4zM10 5v14M16 5v14" stroke="currentColor" strokeWidth="1.6" />
        </svg>
        Columns
      </button>
      {open && (
        <div className="pop open colpop" role="group" aria-label="Device DNA columns">
          <h4>Device DNA columns</h4>
          {defaults.map((column) => (
            <label className={`ck${column.locked ? ' dis' : ''}`} key={column.key}>
              <input
                type="checkbox"
                checked={visible.has(column.key)}
                disabled={column.locked}
                onChange={() => onToggle(column.key)}
              />
              {column.pickerLabel}
            </label>
          ))}
          <div className="sep" />
          {optIns.map((column) => (
            <label className="ck" key={column.key}>
              <input
                type="checkbox"
                checked={visible.has(column.key)}
                onChange={() => onToggle(column.key)}
              />
              {column.pickerLabel}
            </label>
          ))}
        </div>
      )}
    </div>
  )
}
