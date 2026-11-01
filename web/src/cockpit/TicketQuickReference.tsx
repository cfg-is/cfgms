// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TicketQuickReference (Story #3608) — the left-panel ticket metadata display.
 *
 * Renders all five ticket fields with per-field source badges. A field with
 * filled=false renders the .qfield--miss state with a clickable "add"
 * affordance. Clicking "add" opens an inline input; pressing Enter saves
 * (issuing PUT /api/v1/cases/{id}) and Escape cancels without a request.
 *
 * On save the full ticket is sent: all existing field values are preserved and
 * the edited field's value is set with source="operator" (founder decision,
 * 2026-08-26 — operator-entered data is a first-class provenance).
 *
 * The PUT payload shape mirrors updateCaseRequest / caseTicketInput in
 * features/controller/api/handlers_cases.go (Issue #3605):
 *   { "ticket": { "<field>": { "value": "...", "source": "operator" }, ... } }
 *
 * Object injection: all ticket field access uses explicit switch-based getters
 * rather than dynamic bracket notation (required by security/detect-object-injection).
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import type { Ticket, TicketField } from './caseTypes.ts'

type FieldKey = 'title' | 'client' | 'contact' | 'priority' | 'category'

const FIELD_ORDER: FieldKey[] = ['title', 'client', 'priority', 'contact', 'category']

/** Type-safe label accessor — avoids dynamic bracket notation. */
function getLabel(key: FieldKey): string {
  switch (key) {
    case 'title':    return 'Title'
    case 'client':   return 'Client'
    case 'contact':  return 'Contact'
    case 'priority': return 'Priority'
    case 'category': return 'Category'
  }
}

/** Type-safe field accessor — avoids dynamic bracket notation. */
function getField(ticket: Ticket, key: FieldKey): TicketField {
  switch (key) {
    case 'title':
      return ticket.title
    case 'client':
      return ticket.client
    case 'contact':
      return ticket.contact
    case 'priority':
      return ticket.priority
    case 'category':
      return ticket.category
  }
}

interface TicketQuickReferenceProps {
  caseId: string
  ticket: Ticket
  onTicketUpdated: (ticket: Ticket) => void
}

function filledCount(ticket: Ticket): number {
  return FIELD_ORDER.filter((k) => getField(ticket, k).filled).length
}

export default function TicketQuickReference({
  caseId,
  ticket,
  onTicketUpdated,
}: TicketQuickReferenceProps) {
  const [editingField, setEditingField] = useState<FieldKey | null>(null)
  const [inputValue, setInputValue] = useState('')
  const [saving, setSaving] = useState(false)

  const count = filledCount(ticket)
  const total = FIELD_ORDER.length

  function startEdit(field: FieldKey) {
    setEditingField(field)
    setInputValue('')
  }

  function cancelEdit() {
    setEditingField(null)
    setInputValue('')
  }

  async function saveEdit(field: FieldKey) {
    if (!inputValue.trim()) {
      cancelEdit()
      return
    }
    setSaving(true)
    try {
      // Build the full ticket payload — all fields sent, edited field with operator source.
      // Uses explicit per-field access to avoid object injection (security/detect-object-injection).
      const existing = (key: FieldKey) => {
        const f = getField(ticket, key)
        return { value: f.value, source: f.source }
      }
      const edited = { value: inputValue.trim(), source: 'operator' }

      const ticketPayload = {
        title:    field === 'title'    ? edited : existing('title'),
        client:   field === 'client'   ? edited : existing('client'),
        contact:  field === 'contact'  ? edited : existing('contact'),
        priority: field === 'priority' ? edited : existing('priority'),
        category: field === 'category' ? edited : existing('category'),
      }

      const response = await apiFetch(`/api/v1/cases/${encodeURIComponent(caseId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket: ticketPayload }),
      })
      if (response.ok) {
        const body = (await response.json()) as { data: { ticket: Ticket } }
        onTicketUpdated(body.data.ticket)
      }
    } finally {
      setSaving(false)
      setEditingField(null)
      setInputValue('')
    }
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLInputElement>, field: FieldKey) {
    if (event.key === 'Enter') {
      event.preventDefault()
      void saveEdit(field)
    } else if (event.key === 'Escape') {
      cancelEdit()
    }
  }

  return (
    <aside className="qref">
      <div className="qref__head">
        <b>Ticket</b>
        <span className="qref__count">
          {count} / {total}
        </span>
      </div>
      <div className="qref__fields">
        {FIELD_ORDER.map((key) => {
          const field = getField(ticket, key)
          const isEditing = editingField === key
          const label = getLabel(key)

          if (isEditing) {
            return (
              <div key={key} className="qfield qfield--miss">
                <span className="qfield__lbl">{label}</span>
                <input
                  className="qfield__inline-input"
                  type="text"
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={(e) => onKeyDown(e, key)}
                  onBlur={() => {
                    // Blur without confirm = cancel.
                    if (!saving) cancelEdit()
                  }}
                  aria-label={`Enter ${label}`}
                  autoFocus
                />
              </div>
            )
          }

          if (!field.filled) {
            return (
              <div key={key} className="qfield qfield--miss">
                <span className="qfield__lbl">{label}</span>
                <span className="qfield__val">
                  {'— '}
                  <button
                    type="button"
                    className="add-btn"
                    aria-label={`add ${label}`}
                    onClick={() => startEdit(key)}
                  >
                    add
                  </button>
                </span>
              </div>
            )
          }

          const srcClass = field.source ? 'src src--ok' : 'src'
          return (
            <div key={key} className="qfield">
              <span className="qfield__lbl">{label}</span>
              <span className="qfield__val">
                {field.value}
                {field.source && <span className={srcClass}>{field.source}</span>}
              </span>
            </div>
          )
        })}
      </div>
    </aside>
  )
}
