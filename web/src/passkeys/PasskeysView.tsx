// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Self-service passkeys page (Issue #2992, ADR-021 Amendment 3).
 * Accessible at /passkeys — linked from the user menu.
 *
 * Capabilities:
 *   List — fetches GET /api/v1/accounts/{username}/webauthn/credentials.
 *   Add  — POST .../register/begin → navigator.credentials.create() → POST .../register/finish.
 *          Step-up gated: apiFetch fires StepUpModal automatically on 401 CFGMS-StepUp.
 *   Remove — POST .../webauthn/revoke/{credential_id}.
 *          Step-up gated. Server returns 409 LAST_CREDENTIAL if this would be the last passkey;
 *          the UI surfaces an anti-lockout nudge (add a backup first).
 *
 * Security A9.1: all credential labels / IDs reach the DOM as JSX text nodes,
 * never dangerouslySetInnerHTML. Credential IDs are base64url opaque tokens.
 *
 * The /passkeys route is only reachable when the user is authenticated (RequireAuth
 * in App.tsx) and the enrollment-confinement middleware has already verified ≥1
 * passkey is present, so this page will never show the zero-credential state as
 * its initial condition.
 */
import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'
import { apiFetch } from '../api/client.ts'

// ── base64url helpers ──────────────────────────────────────────────────────

function b64uToBytes(b64u: string): Uint8Array<ArrayBuffer> {
  const padded = b64u + '='.repeat((4 - (b64u.length % 4)) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))
}

function bytesToB64u(buf: BufferSource): string {
  const bytes = ArrayBuffer.isView(buf)
    ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
    : new Uint8Array(buf)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

// ── types ──────────────────────────────────────────────────────────────────

interface CredentialInfo {
  id: string
  label: string
  transport: string[] | null
  registered_at: string
  last_used_at: string | null
  device_type?: string
  synced?: boolean
  sync_capable?: boolean
  current?: boolean
}

interface ListResponse {
  username: string
  credentials: CredentialInfo[]
}

type CredentialListResult =
  | { ok: true; credentials: CredentialInfo[] }
  | { ok: false; message: string }

// Plain data fetch — no setState here. Kept outside the component so it can
// be awaited directly from event handlers (immediate reload after add/revoke)
// and also driven from the mount effect's .then() chain, without either call
// site risking the react-hooks/set-state-in-effect rule (which flags any
// function reachable from an effect body that itself sets state).
async function fetchCredentialList(username: string): Promise<CredentialListResult> {
  try {
    const resp = await apiFetch(`/api/v1/accounts/${encodeURIComponent(username)}/webauthn/credentials`)
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      return {
        ok: false,
        message: (body as { error?: { message?: string } })?.error?.message ?? `HTTP ${resp.status}`,
      }
    }
    const body = (await resp.json()) as { data: ListResponse }
    return { ok: true, credentials: body.data.credentials ?? [] }
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : 'Unknown error' }
  }
}

// Server-response types for the registration begin endpoint — all binary
// values are base64url strings in the JSON API (not ArrayBuffer).
interface RegBeginRpEntity {
  name: string
  id?: string
}

interface RegBeginUserEntity {
  id: string       // base64url-encoded
  name: string
  displayName: string
}

interface RegBeginExcludeCredential {
  id: string       // base64url-encoded
  type: string
  transports?: string[]
}

interface RegBeginPublicKeyOptions {
  challenge: string   // base64url-encoded
  rp: RegBeginRpEntity
  user: RegBeginUserEntity
  pubKeyCredParams: { type: string; alg: number }[]
  timeout?: number
  excludeCredentials?: RegBeginExcludeCredential[]
  authenticatorSelection?: Record<string, unknown>
  attestation?: string
}

// ── sub-components ─────────────────────────────────────────────────────────

function formatDate(iso: string | null): string {
  if (!iso) return 'Never'
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(iso))
}

const MAX_LABEL_LENGTH = 64
const LAST_KEY_NOTE = 'You can’t remove your only passkey — you’d be locked out.'

const DEVICE_TYPE_TEXT = new Map<string, string>([
  ['platform', 'Platform passkey'],
  ['security_key', 'Security key'],
  ['phone_or_other', 'Phone or other device'],
  ['unknown', 'Unknown device'],
])

// Sync wording comes only from the stored BE/BS flags, never from transport.
function syncText(cred: CredentialInfo): string | null {
  if (cred.synced) return 'Synced'
  if (cred.sync_capable) return 'Not synced (can sync)'
  if (cred.synced === false && cred.sync_capable === false) return 'Device-bound'
  return null
}

function CredentialRow({
  cred,
  onRevoke,
  onRename,
  revoking,
  locked,
}: {
  cred: CredentialInfo
  onRevoke: (id: string) => void
  onRename: (id: string) => void
  revoking: boolean
  locked: boolean
}) {
  const label = cred.label || cred.id.slice(0, 12) + '…'
  const subline = [DEVICE_TYPE_TEXT.get(cred.device_type ?? 'unknown') ?? 'Unknown device', syncText(cred)]
    .filter(Boolean)
    .join(' · ')

  return (
    <tr data-testid="passkey-row">
      <td>
        <span className="nm">
          {label}
          {cred.current && (
            <span
              className="chip"
              title="This is the passkey that last proved this session."
              data-testid="this-device-chip"
            >
              <span aria-hidden="true">✓ </span>This device
            </span>
          )}
        </span>
        <div className="mut dev" data-testid="passkey-subline">
          {subline}
        </div>
      </td>
      <td>
        <span className="mono2">{formatDate(cred.registered_at)}</span>
      </td>
      <td>
        <span className="mono2">{formatDate(cred.last_used_at)}</span>
      </td>
      <td>
        <button
          type="button"
          className="btn"
          onClick={() => onRename(cred.id)}
          aria-label={`Rename passkey ${label}`}
          data-testid="rename-btn"
        >
          Rename
        </button>
        <button
          type="button"
          className="btn danger"
          disabled={revoking || locked}
          onClick={() => onRevoke(cred.id)}
          aria-label={`Remove passkey ${label}`}
          title={locked ? LAST_KEY_NOTE : undefined}
          data-testid="revoke-btn"
        >
          {revoking ? 'Removing…' : 'Remove'}
        </button>
        {locked && (
          <div className="mut" data-testid="last-key-note">
            {LAST_KEY_NOTE}
          </div>
        )}
      </td>
    </tr>
  )
}

// ── main view ──────────────────────────────────────────────────────────────

export default function PasskeysView() {
  const { principal } = useAuth()
  const username = principal?.username ?? ''

  const [credentials, setCredentials] = useState<CredentialInfo[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  // Derived, not a separate setState: the effect below must not call setState
  // synchronously before its first await (react-hooks/set-state-in-effect), so
  // there is no "loading start" flag to flip — the initial (pre-first-response)
  // state is exactly "neither a credential list nor an error is present yet".
  const loading = credentials === null && loadError === null

  const [addState, setAddState] = useState<'idle' | 'busy' | 'error'>('idle')
  const [addError, setAddError] = useState<string | null>(null)
  const [addLabel, setAddLabel] = useState('')

  const [revokingId, setRevokingId] = useState<string | null>(null)
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const [lastCredAlert, setLastCredAlert] = useState(false)

  const [confirmId, setConfirmId] = useState<string | null>(null)

  const [renameId, setRenameId] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')
  const [renameBusy, setRenameBusy] = useState(false)
  const [renameError, setRenameError] = useState<string | null>(null)

  const loadCredentials = useCallback(async () => {
    if (!username) return
    const result = await fetchCredentialList(username)
    if (result.ok) {
      setLoadError(null)
      setCredentials(result.credentials)
    } else {
      setLoadError(result.message)
    }
  }, [username])

  // Mount / username-change load. Inlined (not calling loadCredentials) so
  // the state updates happen inside a .then() callback rather than
  // synchronously in the effect body — required by react-hooks/set-state-in-effect.
  // Reloads triggered by user actions (add/revoke/retry, below) call
  // loadCredentials directly instead, so those stay immediate and awaitable.
  useEffect(() => {
    if (!username) return
    let cancelled = false
    fetchCredentialList(username).then((result) => {
      if (cancelled) return
      if (result.ok) {
        setLoadError(null)
        setCredentials(result.credentials)
      } else {
        setLoadError(result.message)
      }
    })
    return () => {
      cancelled = true
    }
  }, [username])

  async function handleAdd() {
    if (!username) return
    setAddState('busy')
    setAddError(null)
    const label = addLabel.trim().slice(0, MAX_LABEL_LENGTH)
    try {
      // Begin: server issues a creation challenge (step-up gated via apiFetch interceptor).
      const beginResp = await apiFetch(
        `/api/v1/accounts/${encodeURIComponent(username)}/webauthn/register/begin`,
        { method: 'POST' },
      )
      if (!beginResp.ok) {
        const body = await beginResp.json().catch(() => ({}))
        setAddError((body as { error?: { message?: string } })?.error?.message ?? `HTTP ${beginResp.status}`)
        setAddState('error')
        return
      }
      const beginBody = (await beginResp.json()) as { data: { publicKey: RegBeginPublicKeyOptions } }
      const opts = beginBody.data.publicKey

      // Convert the server's JSON (base64url strings) to the binary format the
      // browser WebAuthn API expects.
      const createOptions: PublicKeyCredentialCreationOptions = {
        challenge: b64uToBytes(opts.challenge),
        rp: opts.rp,
        user: {
          id: b64uToBytes(opts.user.id),
          name: opts.user.name,
          displayName: opts.user.displayName,
        },
        pubKeyCredParams: opts.pubKeyCredParams.map((p) => ({
          type: 'public-key' as const,
          alg: p.alg,
        })),
        timeout: opts.timeout,
        excludeCredentials: opts.excludeCredentials?.map((ec) => ({
          id: b64uToBytes(ec.id),
          type: 'public-key' as const,
          transports: ec.transports as AuthenticatorTransport[] | undefined,
        })),
        attestation: opts.attestation as AttestationConveyancePreference | undefined,
      }

      // Authenticator interaction — may throw if the user cancels or the
      // platform has no suitable authenticator.
      const credential = (await navigator.credentials.create({
        publicKey: createOptions,
      })) as PublicKeyCredential | null

      if (!credential) {
        setAddError('No credential returned by the authenticator')
        setAddState('error')
        return
      }

      const attestation = credential.response as AuthenticatorAttestationResponse
      const payload = {
        id: credential.id,
        rawId: bytesToB64u(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bytesToB64u(attestation.clientDataJSON),
          attestationObject: bytesToB64u(attestation.attestationObject),
        },
      }

      const finishResp = await apiFetch(
        `/api/v1/accounts/${encodeURIComponent(username)}/webauthn/register/finish${label ? `?label=${encodeURIComponent(label)}` : ''}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        },
      )
      if (!finishResp.ok) {
        const body = await finishResp.json().catch(() => ({}))
        setAddError((body as { error?: { message?: string } })?.error?.message ?? `HTTP ${finishResp.status}`)
        setAddState('error')
        return
      }
      setAddState('idle')
      setAddLabel('')
      await loadCredentials()
    } catch (e) {
      // NotAllowedError = user cancelled or timed out (not a server error).
      if (e instanceof Error && e.name === 'NotAllowedError') {
        setAddState('idle')
        return
      }
      setAddError(e instanceof Error ? e.message : 'Unknown error')
      setAddState('error')
    }
  }

  async function handleRevoke(credId: string) {
    if (!username) return
    setRevokingId(credId)
    setRevokeError(null)
    setLastCredAlert(false)
    try {
      const resp = await apiFetch(
        `/api/v1/accounts/${encodeURIComponent(username)}/webauthn/revoke/${encodeURIComponent(credId)}`,
        { method: 'POST' },
      )
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        const code = (body as { error?: { code?: string } })?.error?.code
        if (code === 'LAST_CREDENTIAL') {
          setLastCredAlert(true)
          setConfirmId(null) // dismiss the confirm row so the passkey row is visible again
        } else {
          setRevokeError((body as { error?: { message?: string } })?.error?.message ?? `HTTP ${resp.status}`)
        }
        return
      }
      setConfirmId(null)
      await loadCredentials()
    } catch (e) {
      setRevokeError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setRevokingId(null)
    }
  }

  // Step-up challenges are handled inside apiFetch (StepUpModal); a cancelled or
  // failed ceremony comes back as a non-ok response, leaving the old label.
  async function handleRename() {
    if (!username || renameId === null) return
    const label = renameValue.trim().slice(0, MAX_LABEL_LENGTH)
    if (!label) return
    setRenameBusy(true)
    setRenameError(null)
    try {
      const resp = await apiFetch(
        `/api/v1/accounts/${encodeURIComponent(username)}/webauthn/credentials/${encodeURIComponent(renameId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ label }),
        },
      )
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        setRenameError((body as { error?: { message?: string } })?.error?.message ?? `HTTP ${resp.status}`)
        setRenameId(null)
        return
      }
      setRenameId(null)
      await loadCredentials()
    } catch (e) {
      setRenameError(e instanceof Error ? e.message : 'Unknown error')
      setRenameId(null)
    } finally {
      setRenameBusy(false)
    }
  }

  const credList = credentials ?? []
  const lastKey = credList.length === 1

  return (
    <div className="view-root" data-testid="passkeys-view">
      <div className="view-header">
        <h1>My Passkeys</h1>
        <p className="mut">
          Manage your registered passkeys. Adding a backup passkey on a second device protects your
          account if you lose access to your primary device.
        </p>
      </div>

      {lastCredAlert && (
        <div className="notice warn" role="alert" data-testid="last-cred-alert">
          <div className="ic">!</div>
          <h3>Cannot remove the last passkey</h3>
          <p>
            Add a backup passkey on another device first, then remove this one. If you have lost
            access to all your passkeys, contact an administrator to reset your account.
          </p>
          <button
            type="button"
            className="btn"
            onClick={() => setLastCredAlert(false)}
          >
            Dismiss
          </button>
        </div>
      )}

      {revokeError && (
        <div className="notice err" role="alert" data-testid="revoke-error">
          <div className="ic">!</div>
          <h3>Removal failed</h3>
          <p>{revokeError}</p>
          <button type="button" className="btn" onClick={() => setRevokeError(null)}>
            Dismiss
          </button>
        </div>
      )}

      {renameError && (
        <div className="notice err" role="alert" data-testid="rename-error">
          <div className="ic">!</div>
          <h3>Rename failed</h3>
          <p>{renameError}</p>
          <button type="button" className="btn" onClick={() => setRenameError(null)}>
            Dismiss
          </button>
        </div>
      )}

      {addError && (
        <div className="notice err" role="alert" data-testid="add-error">
          <div className="ic">!</div>
          <h3>Add passkey failed</h3>
          <p>{addError}</p>
          <button type="button" className="btn" onClick={() => setAddError(null)}>
            Dismiss
          </button>
        </div>
      )}

      {loadError && (
        <div className="notice err" role="alert" data-testid="load-error">
          <div className="ic">!</div>
          <h3>Could not load passkeys</h3>
          <p>{loadError}</p>
          <button type="button" className="btn" onClick={() => void loadCredentials()}>
            Retry
          </button>
        </div>
      )}

      {lastKey && !loadError && (
        <div className="notice warn" data-testid="backup-nudge">
          <div className="ic">!</div>
          <h3>Add a backup passkey</h3>
          <p>
            You have only one. If you lose this device you’ll need an admin reset to get back in —
            register a phone, laptop, or security key as a backup.
          </p>
        </div>
      )}

      <div className="tbar">
        <input
          type="text"
          className="input"
          value={addLabel}
          maxLength={MAX_LABEL_LENGTH}
          onChange={(e) => setAddLabel(e.target.value)}
          disabled={addState === 'busy'}
          placeholder="Label (optional), e.g. iPhone 15"
          aria-label="Passkey label"
          data-testid="add-label-input"
        />
        <button
          type="button"
          className="btn"
          disabled={addState === 'busy'}
          onClick={() => void handleAdd()}
          data-testid="add-passkey-btn"
        >
          {addState === 'busy' ? 'Registering…' : '+ Add backup passkey'}
        </button>
      </div>

      {loading && credentials === null ? (
        <div data-testid="passkeys-loading" aria-label="Loading passkeys">
          {Array.from({ length: 2 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '30%' }} />
              <span className="skel" style={{ width: '25%' }} />
              <span className="skel" style={{ width: '25%' }} />
            </div>
          ))}
        </div>
      ) : credList.length === 0 && !loadError ? (
        <div className="notice empty" data-testid="passkeys-empty">
          <div className="ic">◍</div>
          <h3>No passkeys registered</h3>
          <p>Use the button above to add your first backup passkey.</p>
        </div>
      ) : (
        <table className="tbl" data-testid="passkeys-table">
          <thead>
            <tr>
              <th>Label</th>
              <th>Registered</th>
              <th>Last used</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {credList.map((cred) => {
              if (renameId === cred.id) {
                return (
                  <tr key={cred.id} data-testid="passkey-rename-row">
                    <td colSpan={3}>
                      <input
                        type="text"
                        className="input"
                        value={renameValue}
                        maxLength={MAX_LABEL_LENGTH}
                        onChange={(e) => setRenameValue(e.target.value)}
                        disabled={renameBusy}
                        aria-label="New passkey label"
                        data-testid="rename-input"
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn"
                        disabled={renameBusy || !renameValue.trim()}
                        onClick={() => void handleRename()}
                        data-testid="rename-save-btn"
                      >
                        {renameBusy ? 'Saving…' : 'Save'}
                      </button>
                      <button
                        type="button"
                        className="btn"
                        disabled={renameBusy}
                        onClick={() => setRenameId(null)}
                        style={{ marginLeft: 8 }}
                      >
                        Cancel
                      </button>
                    </td>
                  </tr>
                )
              }
              if (confirmId === cred.id) {
                return (
                  <tr key={cred.id} data-testid="passkey-confirm-row">
                    <td colSpan={3}>
                      <span className="mut">
                        Remove <strong>{cred.label || cred.id.slice(0, 12) + '…'}</strong>? This
                        cannot be undone.
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn danger"
                        disabled={revokingId === cred.id}
                        onClick={() => void handleRevoke(cred.id)}
                        data-testid="confirm-revoke-btn"
                      >
                        {revokingId === cred.id ? 'Removing…' : 'Confirm remove'}
                      </button>
                      <button
                        type="button"
                        className="btn"
                        onClick={() => setConfirmId(null)}
                        style={{ marginLeft: 8 }}
                      >
                        Cancel
                      </button>
                    </td>
                  </tr>
                )
              }
              return (
                <CredentialRow
                  key={cred.id}
                  cred={cred}
                  onRevoke={() => setConfirmId(cred.id)}
                  onRename={() => {
                    setRenameError(null)
                    setRenameValue(cred.label)
                    setRenameId(cred.id)
                  }}
                  revoking={revokingId === cred.id}
                  locked={lastKey}
                />
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}
