// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Email delivery page (Issue #6247, Epic #6039). Matches
 * docs/design/mockups/email-delivery.html.
 *
 * An MSP administrator sees their MSP's own sender (or "No sender: using the
 * platform sender"), sets, replaces or removes it, and sends a test with the
 * per-recipient result. Saving, removing and testing are step-up gated
 * server-side; apiFetch runs the ceremony and a cancelled one surfaces here as the
 * original 401.
 *
 * The password is write-only: the field is empty on load, goes into the PUT body
 * and nowhere else, and is cleared from state the moment the PUT settles, whether
 * it succeeded or not. After a save the page says "Password saved" and nothing
 * else about it.
 *
 * A root-scoped session needs a crossing to read an MSP (the shell raises the
 * standard crossing prompt on the 401) and then gets a read-only view: no Replace,
 * no Remove, Send test disabled, as the server refuses all three for root.
 *
 * Every server string (recipient addresses, failure reasons, host) renders as a
 * JSX text node.
 */
import { useState, type FormEvent, type ReactNode } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'
import { useTenantScope } from '../shell/TenantScopeContext.tsx'
import {
  defaultPortFor,
  removeEmailSender,
  saveEmailSender,
  testEmailSender,
  useEmailSender,
  type EmailSender,
  type EmailTestResult,
  type EmailTlsMode,
} from './useEmailSender.ts'
import { TenantApiError } from './useTenants.ts'
import './EmailDeliveryView.css'

const allowedPorts = ['587', '465'] as const

const cancelledMessage = 'The passkey check was cancelled.'

/** A bare address: one "@", no display name, no whitespace or angle brackets. */
const bareAddress = /^[^\s<>"@,;]+@[^\s<>"@,;]+$/

function tlsLabel(mode: string): string {
  if (mode === 'starttls') return 'STARTTLS'
  return mode === 'implicit_tls' ? 'Implicit TLS' : mode
}

function isCancelled(cause: unknown): boolean {
  return cause instanceof TenantApiError && cause.status === 401
}

function failureText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

function Icon({ children, size = 14, stroke = 2 }: { children: ReactNode; size?: number; stroke?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  )
}

const mailIcon = (
  <Icon size={20}>
    <rect x="2" y="4" width="20" height="16" rx="2" />
    <path d="m22 7-10 6L2 7" />
  </Icon>
)
const lockIcon = (
  <Icon size={20}>
    <rect x="3" y="11" width="18" height="11" rx="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </Icon>
)
const alertIcon = (
  <Icon>
    <circle cx="12" cy="12" r="10" />
    <path d="M12 8v4M12 16h.01" />
  </Icon>
)
const checkIcon = (
  <Icon size={11} stroke={2.6}>
    <path d="M20 6 9 17l-5-5" />
  </Icon>
)

function PasswordSavedChip() {
  return (
    <span className="ed-savedchip" data-testid="password-saved">
      {checkIcon}Password saved
    </span>
  )
}

// ── Form ──────────────────────────────────────────────────────────────────────

interface FormValues {
  host: string
  tlsMode: EmailTlsMode
  port: string
  from: string
  username: string
}

interface FieldErrors {
  host?: string
  from?: string
  password?: string
}

function initialValues(sender: EmailSender): FormValues {
  const tlsMode: EmailTlsMode = sender.tlsMode === 'implicit_tls' ? 'implicit_tls' : 'starttls'
  const port = String(sender.port)
  return {
    host: sender.host,
    tlsMode,
    port: (allowedPorts as readonly string[]).includes(port) ? port : String(defaultPortFor(tlsMode)),
    from: sender.from,
    username: sender.username,
  }
}

function validate(values: FormValues, password: string, passwordPresent: boolean, tenantId: string): FieldErrors {
  const errors: FieldErrors = {}
  const host = values.host.trim()
  if (host === '' || /[\s/]/.test(host)) errors.host = 'Enter a host name only: no spaces, no "/".'
  if (!bareAddress.test(values.from.trim())) {
    errors.from = 'Use a bare address such as ops@acme-corp.example, without a name.'
  }
  if (password === '' && !passwordPresent) {
    errors.password = `A password is required: no password is saved for ${tenantId} yet.`
  }
  return errors
}

function SenderForm({
  tenantId,
  sender,
  onSaved,
  onCancel,
}: {
  tenantId: string
  sender: EmailSender
  onSaved: (sender: EmailSender) => void
  onCancel: () => void
}) {
  const replacing = sender.configured && sender.passwordPresent
  const [values, setValues] = useState<FormValues>(() => initialValues(sender))
  // Held only until the PUT settles; see the file comment.
  const [password, setPassword] = useState('')
  const [errors, setErrors] = useState<FieldErrors>({})
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [cancelled, setCancelled] = useState(false)

  function set<K extends keyof FormValues>(key: K, value: FormValues[K]) {
    setValues((v) => ({ ...v, [key]: value }))
  }

  function chooseTls(mode: EmailTlsMode) {
    setValues((v) => ({ ...v, tlsMode: mode, port: String(defaultPortFor(mode)) }))
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    setFailure(null)
    setCancelled(false)
    const found = validate(values, password, sender.passwordPresent, tenantId)
    setErrors(found)
    if (Object.keys(found).length > 0) {
      setPassword('')
      return
    }
    setBusy(true)
    try {
      const saved = await saveEmailSender(tenantId, {
        host: values.host.trim(),
        port: Number(values.port),
        tlsMode: values.tlsMode,
        from: values.from.trim(),
        username: values.username.trim(),
        password,
      })
      onSaved(saved)
    } catch (cause: unknown) {
      if (isCancelled(cause)) setCancelled(true)
      else setFailure(failureText(cause, 'Save email sender failed'))
    } finally {
      setPassword('')
      setBusy(false)
    }
  }

  const hasErrors = Object.keys(errors).length > 0
  return (
    <section className="ed-panel" aria-labelledby="ed-form-title" data-testid="sender-form">
      <div className="ed-phead">
        <h2 id="ed-form-title">{replacing ? 'Replace sender' : 'Set sender'}</h2>
        <span className="ed-sub">Saving replaces every setting below.</span>
      </div>
      <div className="ed-pbody">
        <form className="ed-form" noValidate onSubmit={(e) => void submit(e)}>
          <div className="ed-wide ed-hp">
            <div className={`ed-field ed-host${errors.host ? ' ed-bad' : ''}`}>
              <label htmlFor="ed-host">
                Mail server <span className="ed-req">*</span>
              </label>
              <input
                id="ed-host"
                type="text"
                className="ed-mono"
                placeholder="smtp.vendor-a.example"
                autoComplete="off"
                value={values.host}
                onChange={(e) => set('host', e.target.value)}
                data-testid="host-input"
              />
              {errors.host && (
                <span className="ed-err" data-testid="host-error">
                  {errors.host}
                </span>
              )}
            </div>
            <div className="ed-field">
              <label htmlFor="ed-tls">TLS</label>
              <select
                id="ed-tls"
                value={values.tlsMode}
                onChange={(e) => chooseTls(e.target.value as EmailTlsMode)}
                data-testid="tls-select"
              >
                <option value="starttls">STARTTLS</option>
                <option value="implicit_tls">Implicit TLS</option>
              </select>
            </div>
            <div className="ed-field">
              <label htmlFor="ed-port">Port</label>
              <select id="ed-port" value={values.port} onChange={(e) => set('port', e.target.value)} data-testid="port-select">
                {allowedPorts.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className={`ed-field${errors.from ? ' ed-bad' : ''}`}>
            <label htmlFor="ed-from">
              From address <span className="ed-req">*</span>
            </label>
            <input
              id="ed-from"
              type="email"
              className="ed-mono"
              placeholder="ops@acme-corp.example"
              autoComplete="off"
              value={values.from}
              onChange={(e) => set('from', e.target.value)}
              data-testid="from-input"
            />
            {errors.from ? (
              <span className="ed-err" data-testid="from-error">
                {errors.from}
              </span>
            ) : (
              <span className="ed-hint">An address only, no display name. Tests are sent here.</span>
            )}
          </div>
          <div className="ed-field">
            <label htmlFor="ed-user">Username</label>
            <input
              id="ed-user"
              type="text"
              className="ed-mono"
              placeholder="Optional"
              autoComplete="off"
              value={values.username}
              onChange={(e) => set('username', e.target.value)}
              data-testid="username-input"
            />
          </div>
          <div className={`ed-field ed-wide${errors.password ? ' ed-bad' : ''}`}>
            <label htmlFor="ed-pw">
              Password {!replacing && <span className="ed-req">*</span>}
            </label>
            <div className="ed-pwrow">
              <input
                id="ed-pw"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                data-testid="password-input"
              />
              {replacing && <PasswordSavedChip />}
            </div>
            {errors.password ? (
              <span className="ed-err" data-testid="password-error">
                {errors.password}
              </span>
            ) : replacing ? (
              <span className="ed-hint" data-testid="password-keep-hint">
                Leave empty to keep the saved password. A saved password is never shown again; type a new one to
                replace it.
              </span>
            ) : (
              <span className="ed-hint">Required the first time. After you save, it is never shown again.</span>
            )}
          </div>
          {hasErrors && (
            <div className="ed-msg ed-msg-crit ed-wide" role="alert" data-testid="form-invalid">
              {alertIcon}
              <span>
                <b>Not saved.</b> Fix the fields marked above. Nothing was stored, and the password field has been
                cleared.
              </span>
            </div>
          )}
          {failure !== null && (
            <div className="ed-msg ed-msg-crit ed-wide" role="alert" data-testid="save-error">
              {alertIcon}
              <span>
                <b>Not saved.</b> {failure} The password field has been cleared.
              </span>
            </div>
          )}
          {cancelled && (
            <div className="ed-msg ed-msg-crit ed-wide" role="alert" data-testid="save-cancelled">
              {alertIcon}
              <span>
                <b>Not saved.</b> {cancelledMessage} Your sender has not changed. Type the password again if you want
                to replace it, then save.
              </span>
            </div>
          )}
          <div className="ed-savebar ed-wide">
            <span className="ed-hint">
              You confirm with your passkey. The change is recorded in your audit log without the password or
              username.
            </span>
            <span className="ed-sp" />
            <button
              type="button"
              className="ed-btn-sec"
              onClick={() => {
                setPassword('')
                onCancel()
              }}
              disabled={busy}
              data-testid="form-cancel-btn"
            >
              Cancel
            </button>
            <button type="submit" className="ed-btn" disabled={busy} data-testid="save-btn">
              Save sender
            </button>
          </div>
        </form>
      </div>
    </section>
  )
}

// ── Current sender ────────────────────────────────────────────────────────────

function SenderPanel({
  tenantId,
  sender,
  readOnly,
  saved,
  confirming,
  removeError,
  removeBusy,
  onSet,
  onReplace,
  onAskRemove,
  onKeep,
  onRemove,
}: {
  tenantId: string
  sender: EmailSender
  readOnly: boolean
  saved: boolean
  confirming: boolean
  removeError: string | null
  removeBusy: boolean
  onSet: () => void
  onReplace: () => void
  onAskRemove: () => void
  onKeep: () => void
  onRemove: () => void
}) {
  const inUse = sender.configured && sender.passwordPresent
  return (
    <section className="ed-panel" aria-labelledby="ed-sender-title" data-testid="sender-panel">
      <div className="ed-phead">
        <h2 id="ed-sender-title">Sender</h2>
        <span className="ed-sub">
          Who operational mail for <span className="ed-mono">{tenantId}</span> comes from.
        </span>
      </div>

      {inUse ? (
        <div className="ed-status" data-testid="sender-in-use">
          <span className="ed-ic ed-ic-ok">{mailIcon}</span>
          <div className="ed-t">
            <h3>
              <span className="ed-mono">{tenantId}</span>&apos;s own sender <span className="ed-pill ed-pill-ok">In use</span>
            </h3>
            <p>
              Operational mail for <span className="ed-mono">{tenantId}</span> and its clients goes out through{' '}
              <span className="ed-mono">{sender.host}</span>. If a send fails here it is not retried on the platform
              sender.
            </p>
          </div>
          {!readOnly && !confirming && (
            <div className="ed-acts">
              <button type="button" className="ed-btn-sec" onClick={onReplace} data-testid="replace-btn">
                Replace
              </button>
              <button type="button" className="ed-btn-danger-soft" onClick={onAskRemove} data-testid="remove-btn">
                Remove
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="ed-status" data-testid="sender-none">
          <span className="ed-ic ed-ic-neutral">{mailIcon}</span>
          <div className="ed-t">
            <h3>
              No sender: using the platform sender <span className="ed-pill ed-pill-neutral">Platform</span>
            </h3>
            <p>
              Mail for <span className="ed-mono">{tenantId}</span> and its clients comes from the CFGMS platform sender.
              Set your own mail server so your clients see mail from your domain.
            </p>
          </div>
          {!readOnly && (
            <div className="ed-acts">
              <button type="button" className="ed-btn" onClick={onSet} data-testid="set-btn">
                <Icon stroke={2.2}>
                  <path d="M12 5v14M5 12h14" />
                </Icon>
                Set sender
              </button>
            </div>
          )}
        </div>
      )}

      {saved && inUse && (
        <div className="ed-msg ed-msg-ok ed-inline" role="status" data-testid="sender-saved">
          Sender saved. <PasswordSavedChip />
        </div>
      )}

      {inUse && (
        <dl className="ed-kv" data-testid="sender-details">
          <div>
            <dt>Mail server</dt>
            <dd>{sender.host}</dd>
          </div>
          <div>
            <dt>Port · TLS</dt>
            <dd>
              {sender.port} · {tlsLabel(sender.tlsMode)}
            </dd>
          </div>
          <div>
            <dt>From</dt>
            <dd>{sender.from}</dd>
          </div>
          <div>
            <dt>Username</dt>
            <dd>{sender.username === '' ? '—' : sender.username}</dd>
          </div>
          <div>
            <dt>Password</dt>
            <dd className="ed-sans">
              <PasswordSavedChip />
            </dd>
          </div>
        </dl>
      )}

      {confirming && (
        <div className="ed-confirm" data-testid="remove-confirm">
          <span className="ed-t">
            <b>
              Remove <span className="ed-mono">{tenantId}</span>&apos;s sender?
            </b>{' '}
            The settings and the stored password are deleted. Mail for <span className="ed-mono">{tenantId}</span> and
            its clients goes through the platform sender from now on.
            <span className="ed-s">You can set a sender again at any time. This is recorded in your audit log.</span>
            {removeError !== null && (
              <span className="ed-msg ed-msg-crit ed-inline-msg" role="alert" data-testid="remove-error">
                {removeError}
              </span>
            )}
          </span>
          <button type="button" className="ed-btn-sec ed-sm" onClick={onKeep} disabled={removeBusy} data-testid="remove-keep-btn">
            Keep
          </button>
          <button type="button" className="ed-btn-danger ed-sm" onClick={onRemove} disabled={removeBusy} data-testid="remove-confirm-btn">
            Remove sender
          </button>
        </div>
      )}
    </section>
  )
}

// ── Test send ─────────────────────────────────────────────────────────────────

function ResultTable({ result, at }: { result: EmailTestResult; at: string }) {
  const ok = result.delivered
  return (
    <div className={`ed-result ${ok ? 'ed-result-ok' : 'ed-result-crit'}`} data-testid={ok ? 'test-delivered' : 'test-failed'}>
      <div className="ed-rh">
        {ok ? (
          <Icon stroke={2.4}>
            <path d="M20 6 9 17l-5-5" />
          </Icon>
        ) : (
          alertIcon
        )}
        {ok ? (
          'Delivered. The mail server accepted every recipient.'
        ) : (
          <>
            Not delivered.{' '}
            <span className="ed-why" data-testid="test-failure-reason">
              {result.failureReason}
            </span>
          </>
        )}
        <span className="ed-when">{at}</span>
      </div>
      <table className="ed-tbl">
        <thead>
          <tr>
            <th>Recipient</th>
            <th>Result</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {result.recipients.map((r, i) => (
            <tr key={`${i}:${r.address}`} data-testid="test-recipient">
              <td>
                <span className="ed-addr">{r.address}</span>
              </td>
              <td>
                <span className={`ed-pill ${r.accepted ? 'ed-pill-ok' : 'ed-pill-crit'}`}>
                  {r.accepted ? 'Accepted' : 'Not sent'}
                </span>
              </td>
              <td>{r.reason === '' ? <span className="ed-muted">—</span> : <span className="ed-reason">{r.reason}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!ok && (
        <div className="ed-pbody ed-hint">
          Check the mail server, port and TLS mode, then try again. A host that resolves to a private or loopback
          address is refused before any connection is made.
        </div>
      )}
    </div>
  )
}

function TestPanel({
  tenantId,
  sender,
  readOnly,
}: {
  tenantId: string
  sender: EmailSender
  readOnly: boolean
}) {
  const inUse = sender.configured && sender.passwordPresent
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<{ value: EmailTestResult; at: string } | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function send() {
    setRunning(true)
    setError(null)
    setResult(null)
    try {
      const value = await testEmailSender(tenantId)
      setResult({ value, at: new Date().toLocaleTimeString() })
    } catch (cause: unknown) {
      setError(isCancelled(cause) ? `Test not sent. ${cancelledMessage} Try again.` : failureText(cause, 'Send test failed'))
    } finally {
      setRunning(false)
    }
  }

  const disabled = readOnly || !inUse
  return (
    <section className="ed-panel" aria-labelledby="ed-test-title" data-testid="test-panel">
      <div className="ed-phead">
        <h2 id="ed-test-title">Send a test</h2>
        <span className="ed-sub">
          One fixed message through <span className="ed-mono">{tenantId}</span>&apos;s sender. Nothing you type goes into it.
        </span>
      </div>
      <div className="ed-pbody">
        <div className="ed-testrow">
          <span className="ed-t">
            {readOnly ? (
              <>
                Only an <span className="ed-mono">{tenantId}</span> administrator can send a test.
              </>
            ) : inUse ? (
              <>
                Sends to the sender&apos;s own from address, <span className="ed-mono">{sender.from}</span>. The platform
                sender is never used for a test.
              </>
            ) : (
              'Set a sender first. A test never falls back to the platform sender.'
            )}
          </span>
          <button type="button" className="ed-btn" onClick={() => void send()} disabled={disabled || running} data-testid="test-btn">
            {running && <span className="ed-spin" aria-hidden="true" />}
            {running ? 'Sending…' : 'Send test'}
          </button>
        </div>

        {running && (
          <div className="ed-running" role="status" data-testid="test-running">
            <span className="ed-spin" aria-hidden="true" />
            <span>
              Connecting to <span className="ed-mono">{sender.host}</span> and sending. This can take up to a minute.
            </span>
          </div>
        )}
        {error !== null && (
          <div className="ed-msg ed-msg-crit ed-gap" role="alert" data-testid="test-error">
            {alertIcon}
            <span>{error}</span>
          </div>
        )}
        {result !== null && <ResultTable result={result.value} at={result.at} />}
      </div>
    </section>
  )
}

function UsesPanel({ tenantId }: { tenantId: string }) {
  return (
    <section className="ed-panel" aria-labelledby="ed-uses-title" data-testid="uses-panel">
      <div className="ed-phead">
        <h2 id="ed-uses-title">What uses this sender</h2>
      </div>
      <table className="ed-uses">
        <tbody>
          <tr>
            <td>
              Steward tamper alerts, locked-admission notices, pending script changes, repair-contested notices
            </td>
            <td>
              <span className="ed-mono">{tenantId}</span> sender, else platform
            </td>
          </tr>
          <tr>
            <td>
              Break-glass notices about root access to <span className="ed-mono">{tenantId}</span>
            </td>
            <td>Platform, always</td>
          </tr>
          <tr>
            <td>Test from this page</td>
            <td>
              <span className="ed-mono">{tenantId}</span> sender only
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

type Mode = 'view' | 'form' | 'remove'

function SenderBody({
  tenantId,
  sender,
  readOnly,
  onChange,
}: {
  tenantId: string
  sender: EmailSender
  readOnly: boolean
  onChange: (sender: EmailSender) => void
}) {
  const [mode, setMode] = useState<Mode>('view')
  const [saved, setSaved] = useState(false)
  const [removeBusy, setRemoveBusy] = useState(false)
  const [removeError, setRemoveError] = useState<string | null>(null)

  async function remove() {
    setRemoveBusy(true)
    setRemoveError(null)
    try {
      onChange(await removeEmailSender(tenantId))
      setMode('view')
      setSaved(false)
    } catch (cause: unknown) {
      setRemoveError(
        isCancelled(cause)
          ? `Not removed. ${cancelledMessage} Your sender has not changed.`
          : failureText(cause, 'Remove email sender failed'),
      )
    } finally {
      setRemoveBusy(false)
    }
  }

  return (
    <>
      {readOnly && (
        <div className="ed-msg ed-msg-info" data-testid="root-readonly">
          <Icon>
            <circle cx="12" cy="12" r="10" />
            <path d="M12 16v-4M12 8h.01" />
          </Icon>
          <span>
            <b>Read-only.</b> You are signed in at root with access to <span className="ed-mono">{tenantId}</span>. Root
            can see this sender but cannot change, remove or test it: only an <span className="ed-mono">{tenantId}</span>{' '}
            administrator can.
          </span>
        </div>
      )}

      <SenderPanel
        tenantId={tenantId}
        sender={sender}
        readOnly={readOnly}
        saved={saved}
        confirming={mode === 'remove'}
        removeError={removeError}
        removeBusy={removeBusy}
        onSet={() => setMode('form')}
        onReplace={() => {
          setSaved(false)
          setMode('form')
        }}
        onAskRemove={() => {
          setRemoveError(null)
          setMode('remove')
        }}
        onKeep={() => setMode('view')}
        onRemove={() => void remove()}
      />

      {mode === 'form' && !readOnly && (
        <SenderForm
          tenantId={tenantId}
          sender={sender}
          onCancel={() => setMode('view')}
          onSaved={(next) => {
            onChange(next)
            setSaved(true)
            setMode('view')
          }}
        />
      )}

      {/* Keyed on the stored settings so an earlier result never describes a replaced sender. */}
      <TestPanel
        key={`${sender.host}:${sender.port}:${sender.tlsMode}:${sender.from}:${sender.passwordPresent}`}
        tenantId={tenantId}
        sender={sender}
        readOnly={readOnly}
      />
      <UsesPanel tenantId={tenantId} />
    </>
  )
}

export default function EmailDeliveryView() {
  const { principal } = useAuth()
  const { scope } = useTenantScope()
  const isRoot = principal?.rootScope === true
  // An MSP administrator edits their own tenant's sender; root reads the tenant it has selected.
  const tenantId = isRoot ? scope : (principal?.tenantId ?? '')
  const { sender, loading, failure, error, refetch, setSender } = useEmailSender(tenantId === '' ? null : tenantId)

  let body: ReactNode
  if (tenantId === '') {
    body = (
      <section className="ed-panel" data-testid="no-tenant">
        <div className="ed-rootnote">
          <span className="ed-ic ed-ic-neutral">{lockIcon}</span>
          <div>
            <h3>No tenant selected</h3>
            <p>Email delivery belongs to an MSP tenant. Sign in as an administrator of that MSP.</p>
          </div>
        </div>
      </section>
    )
  } else if (loading) {
    body = (
      <section className="ed-panel" data-testid="sender-loading" aria-busy="true">
        <div className="ed-phead">
          <h2>Sender</h2>
        </div>
        <div className="ed-skwrap">
          <div className="ed-skel" style={{ width: 240, height: 16 }} />
          <div className="ed-skel" style={{ width: 420 }} />
          <div className="ed-skel" style={{ width: 360 }} />
        </div>
      </section>
    )
  } else if (failure === 'forbidden') {
    body = (
      <section className="ed-panel" data-testid="sender-forbidden">
        <div className="ed-rootnote">
          <span className="ed-ic ed-ic-neutral">{lockIcon}</span>
          <div>
            <h3>You cannot view or change this sender</h3>
            <p>
              Email delivery needs the <span className="ed-mono">notification:configure-msp</span> permission on{' '}
              <span className="ed-mono">{tenantId}</span>. MSP administrators have it. Ask an{' '}
              <span className="ed-mono">{tenantId}</span> administrator if you need it.
            </p>
          </div>
        </div>
      </section>
    )
  } else if (failure === 'crossing') {
    body = (
      <section className="ed-panel" data-testid="sender-crossing" aria-labelledby="ed-cross-title">
        <div className="ed-phead">
          <h2 id="ed-cross-title">Sender</h2>
        </div>
        <div className="ed-errcard">
          <span className="ed-ic ed-ic-neutral">{lockIcon}</span>
          <div className="ed-errtext">
            <b className="ed-neutral-title">Access to this tenant is required.</b>
            <span>
              The MSP controls access to <span className="ed-mono">{tenantId}</span>. Ask for support access, or use
              break-glass in an emergency. Even with access, root can only read this sender.
            </span>
          </div>
          <button type="button" className="ed-btn-sec" onClick={refetch} data-testid="crossing-retry-btn">
            Choose access
          </button>
        </div>
      </section>
    )
  } else if (failure === 'error' || sender === null) {
    body = (
      <section className="ed-panel" data-testid="sender-error">
        <div className="ed-errcard" role="alert">
          {alertIcon}
          <div className="ed-errtext">
            <b>Could not load the email sender.</b>
            <span>{error ?? 'The controller did not answer.'} Your sender settings have not changed.</span>
          </div>
          <button type="button" className="ed-btn-sec" onClick={refetch} data-testid="sender-retry-btn">
            Try again
          </button>
        </div>
      </section>
    )
  } else {
    body = <SenderBody tenantId={tenantId} sender={sender} readOnly={isRoot} onChange={setSender} />
  }

  return (
    <div className="ed-content">
      <div className="ed-title">
        <h1>Email delivery</h1>
        <p>
          Choose the mail server that sends operational mail about{' '}
          {tenantId === '' ? 'your MSP' : <b className="ed-mono">{tenantId}</b>} and its clients. Security notices from
          CFGMS always come from the platform sender, whatever you set here.
        </p>
      </div>
      {body}
    </div>
  )
}
