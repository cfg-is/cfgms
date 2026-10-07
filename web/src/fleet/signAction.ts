// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Operator-signed steward actions (Story #4629).
 *
 * Every process/service action is signed by the operator's passkey over a
 * canonical envelope. The browser never builds that content: `prepare` returns
 * it, `operator-payload/sign/begin` freezes it into an envelope (nonce, expiry,
 * targets) and issues the assertion challenge, and `sign/finish` verifies the
 * assertion and returns the raw proof. The proof and the begin envelope's
 * nonce / expires_at / targets are sent back unchanged with the action request.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

export type ActionTargetKind = 'service' | 'process'

/** What the operator chose: the single source of the confirm text and the request. */
export interface ActionSpec {
  targetKind: ActionTargetKind
  /** Service name, or decimal PID for a process. */
  targetName: string
  action: 'start' | 'stop' | 'restart' | 'end' | 'suspend' | 'resume'
  /** Process image name the operator saw; required for process actions. */
  image?: string
}

export function verbFor(spec: ActionSpec): string {
  return `${spec.targetKind}.${spec.action}`
}

export interface SignedProof {
  nonce: string
  expires_at: string
  targets: string[]
  webauthn: {
    authenticator_data: string
    client_data_json: string
    signature: string
    credential_id: string
  }
}

/** An HTTP failure from prepare / sign / action; status 403 renders as denied. */
export class ControlHttpError extends Error {
  status: number
  code?: string
  constructor(status: number, code?: string) {
    super(`request failed (${status})`)
    this.status = status
    this.code = code
  }
}

/** The operator dismissed the passkey prompt. Nothing was sent. */
export class SignCancelledError extends Error {
  constructor() {
    super('passkey prompt cancelled')
  }
}

/** The account has no registered passkey, so nothing can be signed. */
export class NoPasskeyError extends Error {
  constructor() {
    super('no passkey registered')
  }
}

/** The prepared content disagrees with the action the operator confirmed. */
export class ContentMismatchError extends Error {
  constructor() {
    super('prepared content does not match the confirmed action')
  }
}

function b64uToBytes(b64u: string): Uint8Array<ArrayBuffer> {
  const padded = b64u + '='.repeat((4 - (b64u.length % 4)) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))
}

function bytesToB64u(buf: ArrayBuffer | ArrayBufferLike): string {
  const bytes = new Uint8Array(buf)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

interface AssertionOptions {
  publicKey: {
    challenge: string
    timeout?: number
    rpId?: string
    allowCredentials?: Array<{ type: 'public-key'; id: string; transports?: string[] }>
    userVerification?: UserVerificationRequirement
  }
}

interface BeginResponse {
  assertion: AssertionOptions
  envelope: { nonce: string; expires_at: string; targets: string[] }
}

interface FinishResponse {
  authenticator_data: string
  client_data_json: string
  signature: string
  credential_id: string
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const resp = await apiFetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!resp.ok) {
    let code: string | undefined
    try {
      const err = (await resp.json()) as { error?: { code?: string }; code?: string }
      code = err.error?.code ?? err.code
    } catch {
      // body is not JSON; the status alone is enough
    }
    throw new ControlHttpError(resp.status, code)
  }
  return unwrapEnvelope<T>(await resp.json())
}

/** Decodes prepare's content and confirms it is exactly the action the operator confirmed. */
function assertContentMatches(content: string, spec: ActionSpec): void {
  let parsed: { verb?: string; target_kind?: string; target_name?: string; parameters?: Record<string, string> }
  try {
    parsed = JSON.parse(atob(content))
  } catch {
    throw new ContentMismatchError()
  }
  const image = parsed.parameters?.image
  if (
    parsed.verb !== verbFor(spec) ||
    parsed.target_kind !== spec.targetKind ||
    parsed.target_name !== spec.targetName ||
    (spec.targetKind === 'process' && image !== spec.image)
  ) {
    throw new ContentMismatchError()
  }
}

/**
 * Runs prepare, then the passkey ceremony, and returns the proof to attach to the
 * action request. Throws SignCancelledError if the passkey prompt is dismissed,
 * NoPasskeyError when the account has no passkey, ControlHttpError otherwise.
 */
export async function signAction(stewardId: string, spec: ActionSpec): Promise<SignedProof> {
  const prepared = await postJson<{ content: string; shell: string }>(
    `/api/v1/stewards/${encodeURIComponent(stewardId)}/actions/prepare`,
    {
      target_kind: spec.targetKind,
      target_name: spec.targetName,
      action: spec.action,
      ...(spec.image !== undefined ? { image: spec.image } : {}),
    },
  )
  assertContentMatches(prepared.content, spec)

  let begin: BeginResponse
  try {
    begin = await postJson<BeginResponse>('/api/v1/operator-payload/sign/begin', {
      selector: `id:${stewardId}`,
      content: prepared.content,
      shell: prepared.shell,
    })
  } catch (e) {
    if (e instanceof ControlHttpError && e.code === 'NO_CREDENTIALS') throw new NoPasskeyError()
    throw e
  }

  // The envelope is frozen by the controller: refuse to prompt if it names anything
  // other than the steward the operator confirmed.
  if (begin.envelope.targets.length !== 1 || begin.envelope.targets[0] !== stewardId) {
    throw new ContentMismatchError()
  }

  const pk = begin.assertion.publicKey
  let cred: Credential | null
  try {
    cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64uToBytes(pk.challenge),
        timeout: pk.timeout,
        rpId: pk.rpId,
        userVerification: pk.userVerification,
        allowCredentials: pk.allowCredentials?.map((c) => ({
          type: 'public-key' as const,
          id: b64uToBytes(c.id),
          transports: c.transports as AuthenticatorTransport[] | undefined,
        })),
      },
    })
  } catch {
    throw new SignCancelledError()
  }
  if (cred === null || cred.type !== 'public-key') throw new SignCancelledError()
  const pkc = cred as PublicKeyCredential
  const resp = pkc.response as AuthenticatorAssertionResponse

  const finish = await postJson<FinishResponse>('/api/v1/operator-payload/sign/finish', {
    id: pkc.id,
    rawId: bytesToB64u(pkc.rawId),
    response: {
      authenticatorData: bytesToB64u(resp.authenticatorData),
      clientDataJSON: bytesToB64u(resp.clientDataJSON),
      signature: bytesToB64u(resp.signature),
      userHandle: resp.userHandle !== null ? bytesToB64u(resp.userHandle) : null,
    },
    type: 'public-key',
    clientExtensionResults: {},
  })

  return {
    nonce: begin.envelope.nonce,
    expires_at: begin.envelope.expires_at,
    targets: begin.envelope.targets,
    webauthn: {
      authenticator_data: finish.authenticator_data,
      client_data_json: finish.client_data_json,
      signature: finish.signature,
      credential_id: finish.credential_id,
    },
  }
}
