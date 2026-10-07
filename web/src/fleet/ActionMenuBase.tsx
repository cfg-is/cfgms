// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Shared row action menu for Live Activity (Story #4629): kebab button, keyboard-
 * navigable popover, a confirm step that shows exactly what the passkey will sign
 * and requires a justification, and a status line that stays visible until
 * dismissed (no outcome vanishes). The verb/target/steward text is built from the
 * same ActionSpec that is prepared, signed and sent.
 *
 * All text reaches the DOM through JSX text nodes only.
 */
import { useEffect, useRef, useState } from 'react'
import type { ActionOutcome, StewardControl } from './useStewardControl.ts'
import { verbFor, type ActionSpec } from './signAction.ts'

export interface ActionItem {
  id: string
  label: string
  disabled?: boolean
  /** Runs immediately (e.g. Copy PID); mutually exclusive with spec. */
  onSelect?: () => void
  /** Signed action: opens the confirm step. */
  spec?: ActionSpec
  /** Human name of the action in the confirm text ("End task"). */
  title?: string
}

const MAX_JUSTIFICATION = 1024

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\x00-\x1f\x7f]/

function outcomeText(o: ActionOutcome, title: string): { text: string; pending?: boolean } {
  switch (o.kind) {
    case 'result':
      switch (o.code) {
        case 'ok':
          return { text: `${title}: done` }
        case 'self_protect':
          return { text: `${title}: blocked. The steward does not act on its own process.` }
        case 'process_changed':
          return { text: `${title}: not run, the process changed since it was selected` }
        case 'unsupported':
          return { text: `${title}: not supported on this device` }
        case 'expired':
          return { text: `${title}: expired, not run` }
        case 'no_result':
          return { text: `${title}: sent, no result reported` }
        default:
          return { text: `${title}: failed` }
      }
    case 'pending':
      return { text: `${title}: still pending`, pending: true }
    case 'denied':
      return { text: `${title}: denied. You do not have permission to do this.` }
    case 'cancelled':
      return { text: `${title}: cancelled, nothing was sent` }
    case 'no_passkey':
      return {
        text: `${title}: not run. Your account has no passkey. Register one in your security settings; every device action is signed with a passkey.`,
      }
    case 'error':
      return { text: `${title}: ${o.message}` }
  }
}

type Phase =
  | { kind: 'menu' }
  | { kind: 'confirm'; item: ActionItem }
  | { kind: 'working'; item: ActionItem; stage: 'signing' | 'pending' }

interface ActionMenuBaseProps {
  stewardId: string
  /** Names the row for assistive tech, e.g. "PID 4242" or "nginx". */
  rowLabel: string
  /** Lines describing the target in the confirm text, e.g. "Process sshd (PID 4242)". */
  targetText: string
  items: ActionItem[]
  control: StewardControl
  /** Called with each finished outcome so the host can adjust its items (e.g. blocked). */
  onOutcome?: (item: ActionItem, outcome: ActionOutcome) => void
}

export default function ActionMenuBase({
  stewardId,
  rowLabel,
  targetText,
  items,
  control,
  onOutcome,
}: ActionMenuBaseProps) {
  const [open, setOpen] = useState(false)
  const [phase, setPhase] = useState<Phase>({ kind: 'menu' })
  const [justification, setJustification] = useState('')
  const [outcome, setOutcome] = useState<{ item: ActionItem; outcome: ActionOutcome } | null>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const kebabRef = useRef<HTMLButtonElement>(null)
  const busy = phase.kind === 'working'

  function close() {
    setOpen(false)
    setPhase({ kind: 'menu' })
    setJustification('')
    kebabRef.current?.focus()
  }

  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && !busy) close()
    }
    function onDown(e: MouseEvent) {
      if (!busy && !wrapRef.current?.contains(e.target as Node)) {
        setOpen(false)
        setPhase({ kind: 'menu' })
        setJustification('')
      }
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onDown)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onDown)
    }
  }, [open, busy])

  // Focus the first enabled item when the menu opens.
  useEffect(() => {
    if (open && phase.kind === 'menu') {
      wrapRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]:not([disabled])')?.focus()
    }
  }, [open, phase.kind])

  function onMenuKey(e: React.KeyboardEvent) {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    const els = Array.from(
      wrapRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not([disabled])') ?? [],
    )
    if (els.length === 0) return
    e.preventDefault()
    const idx = els.indexOf(document.activeElement as HTMLButtonElement)
    const next = e.key === 'ArrowDown' ? (idx + 1) % els.length : (idx - 1 + els.length) % els.length
    els.at(next)?.focus()
  }

  function activate(item: ActionItem) {
    if (item.spec) {
      setPhase({ kind: 'confirm', item })
      return
    }
    item.onSelect?.()
    close()
  }

  function finish(item: ActionItem, o: ActionOutcome) {
    setOutcome({ item, outcome: o })
    setPhase({ kind: 'menu' })
    setJustification('')
    setOpen(false)
    onOutcome?.(item, o)
  }

  async function confirm(item: ActionItem) {
    const spec = item.spec
    if (!spec) return
    setPhase({ kind: 'working', item, stage: 'signing' })
    const o = await control.perform(spec, justification.trim(), () =>
      setPhase({ kind: 'working', item, stage: 'pending' }),
    )
    finish(item, o)
  }

  async function refresh(item: ActionItem, runId: string) {
    setOutcome({ item, outcome: { kind: 'pending', runId } })
    const o = await control.refresh(runId)
    finish(item, o)
  }

  const trimmed = justification.trim()
  const justificationValid =
    trimmed.length > 0 && trimmed.length <= MAX_JUSTIFICATION && !CONTROL_CHARS.test(trimmed)

  const working = phase.kind === 'working' ? phase : null
  const status = working
    ? {
        text:
          working.stage === 'signing'
            ? `${working.item.title ?? working.item.label}: waiting for passkey`
            : `${working.item.title ?? working.item.label}: pending`,
        pending: true,
      }
    : outcome
      ? outcomeText(outcome.outcome, outcome.item.title ?? outcome.item.label)
      : null

  return (
    <div className="ram-wrap act-wrap" ref={wrapRef}>
      <button
        ref={kebabRef}
        type="button"
        className="rowkebab"
        aria-label={`Actions for ${rowLabel}`}
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={busy}
        onClick={() => setOpen((was) => !was)}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="5" r="1.6" fill="currentColor" />
          <circle cx="12" cy="12" r="1.6" fill="currentColor" />
          <circle cx="12" cy="19" r="1.6" fill="currentColor" />
        </svg>
      </button>
      {status && (
        <span className="act-status" role="status">
          <span className="act-status-text">{status.text}</span>
          {outcome?.outcome.kind === 'pending' && !working && (
            <button
              type="button"
              className="live-btn act-link"
              onClick={() => void refresh(outcome.item, (outcome.outcome as { runId: string }).runId)}
            >
              Refresh
            </button>
          )}
          {!working && !(outcome?.outcome.kind === 'pending') && (
            <button type="button" className="live-btn act-link" onClick={() => setOutcome(null)}>
              Dismiss
            </button>
          )}
        </span>
      )}
      {open && (
        <div className="pop right ram-pop act-pop" role={phase.kind === 'menu' ? 'menu' : undefined} onKeyDown={onMenuKey}>
          {phase.kind === 'menu' &&
            items.map((item) => (
              <button
                key={item.id}
                type="button"
                className="row"
                role="menuitem"
                disabled={item.disabled}
                onClick={() => activate(item)}
              >
                {item.label}
              </button>
            ))}
          {phase.kind !== 'menu' && phase.item.spec && (
            <form
              className="act-confirm"
              aria-label={`Confirm ${phase.item.title ?? phase.item.label}`}
              onSubmit={(e) => {
                e.preventDefault()
                if (phase.kind === 'confirm' && justificationValid) void confirm(phase.item)
              }}
            >
              <div className="act-confirm-hd">Confirm and sign</div>
              <dl className="act-confirm-kv">
                <dt>Action</dt>
                <dd>
                  {phase.item.title ?? phase.item.label} <span className="mono2">({verbFor(phase.item.spec)})</span>
                </dd>
                <dt>Target</dt>
                <dd>{targetText}</dd>
                <dt>Steward</dt>
                <dd className="mono2">{stewardId}</dd>
              </dl>
              <label className="act-confirm-lbl" htmlFor={`act-just-${stewardId}-${rowLabel}`}>
                Justification (required)
              </label>
              <input
                id={`act-just-${stewardId}-${rowLabel}`}
                type="text"
                className="live-filter act-just"
                value={justification}
                maxLength={MAX_JUSTIFICATION}
                disabled={busy}
                autoFocus
                onChange={(e) => setJustification(e.target.value)}
              />
              <p className="act-confirm-note">
                You will be asked to approve this exact action with your passkey.
              </p>
              <div className="act-confirm-btns">
                <button type="submit" className="live-btn" disabled={busy || !justificationValid}>
                  Sign with passkey
                </button>
                <button type="button" className="live-btn" disabled={busy} onClick={close}>
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  )
}
