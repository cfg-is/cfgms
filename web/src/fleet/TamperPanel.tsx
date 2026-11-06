// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tampered-steward panel (Story #5668), mounted on StewardAssetPage.
 *
 * Design source: docs/design/mockups/tamper-restore-ban.html. For a tampered steward
 * it shows the banner (stored tamper codes, reported reasons, the hands-on line or
 * the reason hands-on tools are unavailable), the repair progress, and the three
 * actions: Restore, Repair and restore, Ban. Each action opens a confirm dialog that
 * lists the tamper codes on record first, then runs the verb; the passkey tap is the
 * central step-up ceremony apiFetch runs on the verb's 401 (see tamper.ts).
 *
 * Steward-supplied strings (codes, reasons, host name) are untrusted and are rendered
 * as text only; the host name is shown with control and bidi characters escaped.
 */
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import type { HealthReason } from './health.ts'
import {
  type RepairState,
  type TamperOutcome,
  banNameMatches,
  banSteward,
  escapeHidden,
  getRepairState,
  hasAnchorUntrusted,
  hasHiddenChars,
  isRepairActive,
  lockedToolsReasons,
  lossCodesOf,
  lossText,
  repairOutcomeText,
  repairSteward,
  restoreSteward,
  tamperCodeLabel,
} from './tamper.ts'
import './TamperPanel.css'

export const REPAIR_POLL_MS = 5_000

export interface TamperSteward {
  id: string
  status: string
  /** Host name from the controller's record of the steward; '' when unknown. */
  hostname: string
  /** 'connected' | 'disconnected' | ''. */
  connectionState: string
  reasons: HealthReason[]
  /** Stored tamper codes (kept after a healthy heartbeat replaces the live reasons). */
  tamperCodes: string[]
}

export type HandsOnTab = 'shell' | 'live' | 'logs'

interface Props {
  steward: TamperSteward
  /** Re-reads the steward after a verb or a repair state change. */
  onChanged: () => void
  onSelectTab?: (tab: HandsOnTab) => void
}

type DialogKind = 'restore' | 'repair' | 'ban' | null

/** A failure line shown inside a dialog; nothing changed on the steward in any of these. */
function failureText(out: TamperOutcome<unknown>): string | null {
  switch (out.kind) {
    case 'cancelled':
      return 'Passkey cancelled. Nothing changed. You can try again.'
    case 'denied':
      return 'You need permission to manage this steward. Nothing changed.'
    case 'not_found':
      return 'This steward was not found. Nothing changed.'
    case 'session_expired':
      return 'Your session ended. Sign in again, then retry. Nothing changed.'
    case 'error':
      return `${out.message} Nothing changed.`
    default:
      return null
  }
}

function Dialog(props: {
  title: ReactNode
  subtitle?: ReactNode
  tone: 'ok' | 'acc' | 'crit'
  labelId: string
  busy: boolean
  onClose: () => void
  children: ReactNode
  footer: ReactNode
  testId: string
}) {
  const { busy, onClose } = props
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && !busy) onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [busy, onClose])
  return (
    <div className="tp-overlay">
      <div
        className={`tp-dlg tp-dlg-${props.tone}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={props.labelId}
        data-testid={props.testId}
      >
        <div className="tp-dlg-body">
          <h2 id={props.labelId}>{props.title}</h2>
          {props.subtitle !== undefined && <p className="tp-sub">{props.subtitle}</p>}
          {props.children}
        </div>
        <div className="tp-dlg-foot">
          <span className="tp-kbd">You confirm with your passkey.</span>
          {props.footer}
        </div>
      </div>
    </div>
  )
}

function CodeList({ codes, liveCodes }: { codes: string[]; liveCodes: Set<string> }) {
  return (
    <ul className="tp-codes" data-testid="tamper-codes">
      {codes.map((code) => {
        const label = tamperCodeLabel(code)
        const still = liveCodes.has(code)
        return (
          <li key={code}>
            <span className="tp-cl">
              {label !== '' && <b>{label}</b>}
              <code>{code}</code>
            </span>
            <span className={`tp-rep ${still ? 'on' : 'off'}`}>
              {still ? 'Still reported' : 'Not reported in the latest heartbeat'}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

function CodesOnRecord({ codes, liveCodes }: { codes: string[]; liveCodes: Set<string> }) {
  return (
    <div className="tp-blk">
      <span className="tp-lbl">Tamper codes on record</span>
      {codes.length > 0 ? (
        <CodeList codes={codes} liveCodes={liveCodes} />
      ) : (
        <p className="tp-muted">The tamper codes are no longer on record.</p>
      )}
    </div>
  )
}

/** Passkey cancelled / refusal line inside a dialog. */
function DialogMessage({ text, tone = 'neu' }: { text: string; tone?: 'neu' | 'crit' }) {
  return (
    <div className={`tp-msg tp-msg-${tone}`} role="alert">
      {text}
    </div>
  )
}

interface DialogProps {
  steward: TamperSteward
  codes: string[]
  liveCodes: Set<string>
  onClose: () => void
  /** The verb succeeded. */
  onDone: (note: string) => void
  /** The steward was changed by someone else; the page must reload. */
  onReload: () => void
}

function RestoreDialog(props: DialogProps & { onSwitchToRepair: () => void }) {
  const { steward, codes, liveCodes, onClose, onDone, onReload, onSwitchToRepair } = props
  const [busy, setBusy] = useState(false)
  const [fault, setFault] = useState<string[] | null>(null)
  const [conflict, setConflict] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  async function run() {
    setBusy(true)
    setFailure(null)
    const out = await restoreSteward(steward.id)
    setBusy(false)
    if (out.kind === 'ok') return onDone('Restored. The steward is trusted again and normal traffic resumes.')
    if (out.kind === 'fault_still_reported') return setFault(out.codes)
    if (out.kind === 'conflict') return setConflict(out.message)
    setFailure(failureText(out))
  }

  return (
    <Dialog
      testId="restore-dialog"
      labelId="tp-restore-h"
      tone="ok"
      busy={busy}
      onClose={onClose}
      title={<>Restore <span className="mono">{escapeHidden(steward.hostname || steward.id)}</span>?</>}
      subtitle="Only restore a steward that no longer reports a fault."
      footer={
        <>
          <button type="button" className="tp-btn-sec" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          {conflict !== null ? (
            <button type="button" className="tp-btn" onClick={onReload}>
              Reload
            </button>
          ) : fault !== null ? (
            <button type="button" className="tp-btn" onClick={onSwitchToRepair}>
              Repair and restore
            </button>
          ) : (
            <button type="button" className="tp-btn" disabled={busy} onClick={() => void run()}>
              {busy ? 'Waiting for passkey…' : 'Restore — tap passkey'}
            </button>
          )}
        </>
      }
    >
      <CodesOnRecord codes={codes} liveCodes={liveCodes} />
      <div className="tp-blk">
        <span className="tp-lbl">What happens</span>
        <ul className="tp-bul">
          <li>It returns to trusted.</li>
          <li>Config, jobs and secrets resume.</li>
          <li>An audit event records you, the time and the codes on record.</li>
        </ul>
      </div>
      {fault !== null && (
        <DialogMessage
          tone="crit"
          text={`The steward still reports a fault${fault.length > 0 ? ` (${fault.join(', ')})` : ''}. Nothing was changed. Restoring it would not clear the fault: repair and restore it instead.`}
        />
      )}
      {conflict !== null && (
        <DialogMessage tone="crit" text={`Someone else already changed this steward: ${conflict} Nothing was changed. Reload to see the current state.`} />
      )}
      {failure !== null && <DialogMessage text={failure} />}
    </Dialog>
  )
}

function RepairDialog(props: DialogProps & { lossCodes: string[] }) {
  const { steward, codes, liveCodes, onClose, onDone, onReload } = props
  const [lossCodes, setLossCodes] = useState(props.lossCodes)
  const [approved, setApproved] = useState(false)
  const [busy, setBusy] = useState(false)
  const [reloaded, setReloaded] = useState(false)
  const [conflict, setConflict] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const hasLoss = lossCodes.length > 0

  async function run() {
    setBusy(true)
    setFailure(null)
    setReloaded(false)
    const out = await repairSteward(steward.id, lossCodes)
    setBusy(false)
    if (out.kind === 'ok') {
      return onDone('Repair sent. The steward runs it now if connected, or when it next connects, and reports back.')
    }
    if (out.kind === 'loss_approval_required') {
      // The loss the steward reports changed: show the current list and ask again.
      setLossCodes(out.lossCodes)
      setApproved(false)
      setReloaded(true)
      return
    }
    if (out.kind === 'conflict') return setConflict(out.message)
    setFailure(failureText(out))
  }

  return (
    <Dialog
      testId="repair-dialog"
      labelId="tp-repair-h"
      tone="acc"
      busy={busy}
      onClose={onClose}
      title={<>Repair and restore <span className="mono">{escapeHidden(steward.hostname || steward.id)}</span>?</>}
      footer={
        <>
          <button type="button" className="tp-btn-sec" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          {conflict !== null ? (
            <button type="button" className="tp-btn" onClick={onReload}>
              Reload
            </button>
          ) : (
            <button
              type="button"
              className="tp-btn"
              disabled={busy || (hasLoss && !approved)}
              onClick={() => void run()}
            >
              {busy ? 'Waiting for passkey…' : 'Repair — tap passkey'}
            </button>
          )}
        </>
      }
    >
      <CodesOnRecord codes={codes} liveCodes={liveCodes} />
      <div className="tp-blk">
        <span className="tp-lbl">What the steward does</span>
        <ul className="tp-bul">
          <li>Resets the rights on its own files.</li>
          <li>Makes a new key. Its old certificate is revoked.</li>
          <li>{hasLoss ? 'Keeps its steward ID.' : 'Keeps its steward ID, local logs and action history.'}</li>
          <li>Then returns to trusted. Config, jobs and secrets resume.</li>
        </ul>
      </div>
      {hasLoss && (
        <div className="tp-msg tp-msg-warn" data-testid="repair-loss">
          <b>This repair cannot keep all local data.</b> The steward loses:
          <ul className="tp-losslist">
            {lossCodes.map((c) => (
              <li key={c}>{lossText(c)}</li>
            ))}
          </ul>
          <span>The controller&apos;s copies of logs and action history stay.</span>
        </div>
      )}
      {hasLoss && (
        <label className="tp-chk">
          <input type="checkbox" checked={approved} disabled={busy} onChange={(e) => setApproved(e.target.checked)} />
          <span>I approve losing this local data</span>
        </label>
      )}
      <div className="tp-msg tp-msg-info">
        The steward runs the repair now if it is connected, or when it next connects. It reports back when done. If the
        fault comes back after the repair, it is marked tampered again.
      </div>
      {reloaded && (
        <DialogMessage
          tone="crit"
          text="The local data at risk changed since this dialog opened. Review the list above and approve again. Nothing was changed."
        />
      )}
      {conflict !== null && (
        <DialogMessage tone="crit" text={`Someone else already changed this steward: ${conflict} Nothing was changed. Reload to see the current state.`} />
      )}
      {failure !== null && <DialogMessage text={failure} />}
    </Dialog>
  )
}

function BanDialog(props: DialogProps) {
  const { steward, codes, liveCodes, onClose, onDone, onReload } = props
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [conflict, setConflict] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  // The name to type is the controller's record of the host name. A steward with
  // no recorded name is confirmed by its ID instead.
  const expected = steward.hostname !== '' ? steward.hostname : steward.id
  const matches = banNameMatches(typed, expected)

  async function run() {
    if (!matches) return
    setBusy(true)
    setFailure(null)
    const out = await banSteward(steward.id)
    setBusy(false)
    if (out.kind === 'ok') return onDone('Banned. The certificate is revoked and the steward is refused from now on.')
    if (out.kind === 'conflict') return setConflict(out.message)
    setFailure(failureText(out))
  }

  return (
    <Dialog
      testId="ban-dialog"
      labelId="tp-ban-h"
      tone="crit"
      busy={busy}
      onClose={onClose}
      title={<>Ban <span className="mono">{escapeHidden(expected)}</span>?</>}
      subtitle={<b className="tp-crit">This cannot be undone.</b>}
      footer={
        <>
          <button type="button" className="tp-btn-sec" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          {conflict !== null ? (
            <button type="button" className="tp-btn" onClick={onReload}>
              Reload
            </button>
          ) : (
            <button type="button" className="tp-btn-danger" disabled={busy || !matches} onClick={() => void run()}>
              {busy ? 'Waiting for passkey…' : 'Ban — tap passkey'}
            </button>
          )}
        </>
      }
    >
      <CodesOnRecord codes={codes} liveCodes={liveCodes} />
      <div className="tp-blk">
        <span className="tp-lbl">What happens</span>
        <ul className="tp-bul tp-bul-crit">
          <li>Its certificate is revoked.</li>
          <li>The controller refuses it from then on.</li>
          <li>To bring it back, the device must enroll again as a new device.</li>
          <li>Its records and audit history stay.</li>
        </ul>
      </div>
      <div className="tp-field">
        <label htmlFor="tp-ban-input">
          Type <span className="mono" data-testid="ban-expected-name">{escapeHidden(expected)}</span> to confirm
        </label>
        <input
          id="tp-ban-input"
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={typed}
          disabled={busy}
          onChange={(e) => setTyped(e.target.value)}
        />
        <span className="tp-fhint">
          Steward ID <span className="mono">{escapeHidden(steward.id)}</span>.{' '}
          {hasHiddenChars(expected)
            ? 'The name has hidden characters, shown escaped; type it as shown.'
            : 'Type the host name exactly.'}
        </span>
      </div>
      {conflict !== null && (
        <DialogMessage tone="crit" text={`Someone else already changed this steward: ${conflict} Nothing was changed. Reload to see the current state.`} />
      )}
      {failure !== null && <DialogMessage text={failure} />}
    </Dialog>
  )
}

function StepList({ items }: { items: { label: string; state: 'done' | 'now' | 'next' }[] }) {
  return (
    <ul className="tp-steps">
      {items.map((s) => (
        <li key={s.label} className={`tp-st-${s.state}`}>
          {s.label}
        </li>
      ))}
    </ul>
  )
}

function RepairProgress({
  repair,
  connectionState,
  onBan,
}: {
  repair: RepairState
  connectionState: string
  onBan: () => void
}) {
  const by = repair.requestedBy !== '' ? ` by ${repair.requestedBy}` : ''
  switch (repair.state) {
    case 'waiting':
    case 'running':
      return (
        <div className="tp-sec" data-testid={`repair-${repair.state}`}>
          <div className="tp-sh">Repair sent{by} — waiting for the steward</div>
          <StepList
            items={[
              { label: 'Controller sent the repair', state: 'done' },
              { label: 'Steward resets file rights and makes a new key', state: 'now' },
              { label: 'Steward reports back, then returns to trusted', state: 'next' },
            ]}
          />
          <p className="tp-muted">{repair.state === 'running' ? 'The steward is running the repair.' : 'The repair has not started yet.'}</p>
          {repair.state === 'waiting' && connectionState === 'disconnected' && (
            <div className="tp-msg tp-msg-neu" data-testid="repair-offline">
              <b>The steward is offline.</b> The repair runs when it next connects.
            </div>
          )}
        </div>
      )
    case 'completed':
      return (
        <div className="tp-sec" data-testid="repair-completed">
          <div className="tp-sh">Repaired — waiting for a quiet period</div>
          <StepList
            items={[
              { label: 'Controller sent the repair', state: 'done' },
              { label: 'Steward reset its file rights and made a new key. Old certificate revoked.', state: 'done' },
              { label: 'Quiet period on the new certificate. No old key may be used.', state: 'now' },
            ]}
          />
          <div className="tp-msg tp-msg-info">
            It returns to trusted by itself at the end of the quiet period. If anyone uses the old keys before then, it is
            marked <b>repair contested</b>.
          </div>
        </div>
      )
    case 'restored':
      return (
        <div className="tp-msg tp-msg-ok" data-testid="repair-restored">
          <b>Repaired and restored.</b> The steward is trusted again.
        </div>
      )
    case 'failed':
    case 'refused_data_loss': {
      const why = repairOutcomeText(repair.outcomeCodes)
      return (
        <div className="tp-msg tp-msg-crit" role="alert" data-testid="repair-failed">
          <b>Repair failed.</b> {why.length > 0 ? why.join(' ') : 'The steward reported no reason.'} It stays tampered and its
          old key is still in use. Check the host, then repair again or ban it.
        </div>
      )
    }
    case 'contested':
      return (
        <div className="tp-msg tp-msg-crit" role="alert" data-testid="repair-contested">
          <b>Repair contested.</b> After the repair finished, this steward&apos;s old certificate was used. Someone else may
          hold a copy of its keys. Check the host with your security tools before you restore it, or ban it.{' '}
          <button type="button" className="tp-btn-danger-soft" onClick={onBan}>
            Ban
          </button>
        </div>
      )
    case 'cancelled':
      return (
        <div className="tp-msg tp-msg-neu" data-testid="repair-cancelled">
          The last repair request was cancelled.
        </div>
      )
  }
}

function HandsOnLine({
  reasons,
  anchorUntrusted,
  onSelectTab,
}: {
  reasons: { code: string; text: string }[]
  anchorUntrusted: boolean
  onSelectTab?: (tab: HandsOnTab) => void
}) {
  const locked = reasons.length > 0
  return (
    <>
      <div className="tp-hands" data-testid="hands-on">
        <span className="lead" data-testid="hands-on-line">
          {anchorUntrusted
            ? 'Repair cannot be trusted on this host. Ban it or re-enroll it as a new device.'
            : locked
              ? 'Hands-on tools are not available on this host while it is locked.'
              : 'You can still run commands, scripts and the shell by hand. Each is audited.'}
        </span>
        <button type="button" className="tp-lnk" disabled={locked} onClick={() => onSelectTab?.('shell')}>
          Shell
        </button>
        <button type="button" className="tp-lnk" disabled={locked} onClick={() => onSelectTab?.('live')}>
          Live activity
        </button>
        <button type="button" className="tp-lnk" onClick={() => onSelectTab?.('logs')}>
          Logs
        </button>
      </div>
      {locked && (
        <div className="tp-msg tp-msg-neu" data-testid="locked-tools">
          <b>Hands-on tools are not available on this host while it is locked.</b>
          <ul>
            {reasons.map((r) => (
              <li key={r.code} data-code={r.code}>
                {r.text}
              </li>
            ))}
          </ul>
          Inventory and logs still arrive. Repair, Restore and Ban still work
          {reasons.some((r) => r.code === 'locked_tools.no_baked_root')
            ? ', but a repair that would lose local data is not possible on this host.'
            : '.'}
        </div>
      )}
    </>
  )
}

export default function TamperPanel({ steward, onChanged, onSelectTab }: Props) {
  const tampered = steward.status === 'tampered'
  const [dialog, setDialog] = useState<DialogKind>(null)
  const [repair, setRepair] = useState<RepairState | null>(null)
  const [done, setDone] = useState<string | null>(null)
  const lastState = useRef<string | undefined>(undefined)

  const liveCodes = new Set(steward.reasons.map((r) => r.code))
  const codes = steward.tamperCodes
  const lossCodes = lossCodesOf(steward.reasons)
  const locked = lockedToolsReasons(steward.reasons)
  const repairActive = isRepairActive(repair?.state)

  // Poll the repair state while the steward is tampered or a repair is in flight.
  const polling = tampered || repairActive
  useEffect(() => {
    if (!polling) return
    let cancelled = false
    async function tick() {
      const out = await getRepairState(steward.id)
      if (cancelled || out.kind !== 'ok') return
      setRepair(out.value)
      const state = out.value?.state
      if (lastState.current !== undefined && lastState.current !== state) onChanged()
      lastState.current = state
    }
    void tick()
    const timer = setInterval(() => void tick(), REPAIR_POLL_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [polling, steward.id, onChanged])

  const closeDialog = useCallback(() => setDialog(null), [])
  function finish(note: string) {
    setDialog(null)
    setDone(note)
    onChanged()
  }
  function reload() {
    setDialog(null)
    setDone(null)
    onChanged()
  }

  if (!tampered) {
    // After a restore or a completed repair the steward is no longer tampered; keep the
    // confirmation visible and show no actions.
    if (done !== null || repair?.state === 'restored') {
      return (
        <div className="tp-msg tp-msg-ok" role="status" data-testid="tamper-done">
          {done ?? 'Repaired and restored. The steward is trusted again.'}
        </div>
      )
    }
    return null
  }

  const dialogProps: DialogProps = {
    steward,
    codes,
    liveCodes,
    onClose: closeDialog,
    onDone: finish,
    onReload: reload,
  }
  const hostLabel = steward.hostname !== '' ? steward.hostname : steward.id

  return (
    <>
      {done !== null && (
        <div className="tp-msg tp-msg-ok" role="status" data-testid="tamper-done">
          {done}
        </div>
      )}
      <section className="tp" data-testid="tampered-banner" aria-labelledby="tp-h">
        <div className="tp-head">
          <h2 id="tp-h">
            Tampered — locked down <span className="tp-pill">{escapeHidden(hostLabel)}</span>
          </h2>
          <p className="tp-since">Raised by the steward itself. It does not end by itself.</p>
        </div>
        <p className="tp-text">
          The controller still accepts heartbeats, inventory and reports from this steward. It sends it nothing new: no
          config, no automated or scheduled jobs, no secrets.
        </p>
        <HandsOnLine reasons={locked} anchorUntrusted={hasAnchorUntrusted(steward.reasons)} onSelectTab={onSelectTab} />

        {repair !== null && repair.state !== 'cancelled' && (
          <RepairProgress repair={repair} connectionState={steward.connectionState} onBan={() => setDialog('ban')} />
        )}

        <div className="tp-sec">
          <div className="tp-sh">
            Tamper codes <span className="tp-n">{codes.length} on record</span>
          </div>
          {codes.length > 0 ? (
            <CodeList codes={codes} liveCodes={liveCodes} />
          ) : (
            <div className="tp-msg tp-msg-neu" data-testid="no-codes">
              The tamper codes are no longer on record. The status stays until someone restores or bans this steward.
            </div>
          )}
          {steward.reasons.length > 0 && (
            <ul className="tp-reasons" data-testid="tamper-reasons">
              {steward.reasons.map((r, i) => (
                <li key={`${r.component}:${r.code}:${i}`}>
                  <span className="mono">{escapeHidden(r.component)}</span> <strong>{escapeHidden(r.code)}</strong>
                  {r.message ? <> — {escapeHidden(r.message)}</> : null}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="tp-actions">
          <button type="button" className="tp-btn" disabled={repairActive} onClick={() => setDialog('restore')}>
            Restore
          </button>
          <button type="button" className="tp-btn" disabled={repairActive} onClick={() => setDialog('repair')}>
            Repair and restore
          </button>
          <button type="button" className="tp-btn-danger-soft" onClick={() => setDialog('ban')}>
            Ban
          </button>
          <span className="tp-note">
            {repairActive ? 'Repair in progress. You can still ban.' : 'Each needs a passkey tap and is audited.'}
          </span>
        </div>
      </section>

      {dialog === 'restore' && <RestoreDialog {...dialogProps} onSwitchToRepair={() => setDialog('repair')} />}
      {dialog === 'repair' && <RepairDialog {...dialogProps} lossCodes={lossCodes} />}
      {dialog === 'ban' && <BanDialog {...dialogProps} />}
    </>
  )
}
