// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Publish one stored workflow version with a passkey tap (Issue #5857, ADR-036 §4).
 *
 * publish/begin loads the stored version and issues the assertion challenge;
 * navigator.credentials.get signs it; publish/finish verifies the assertion and
 * stores the publication on that exact version. The browser never builds or sees
 * the signed content, and the controller holds no signing key. A cancelled prompt
 * sends nothing: the ceremony throws SignCancelledError before publish/finish.
 */
import {
  ContentMismatchError,
  ControlHttpError,
  NoPasskeyError,
  SignCancelledError,
  postJson,
} from '../fleet/signAction.ts'

/** What the UI shows once a version carries a publication. */
export interface PublicationInfo {
  signer_account_id: string
  signed_at: string
  content_hash: string
}

interface BeginResponse {
  assertion: {
    publicKey: {
      challenge: string
      timeout?: number
      rpId?: string
      allowCredentials?: Array<{ type: 'public-key'; id: string; transports?: string[] }>
      userVerification?: UserVerificationRequirement
    }
  }
  name: string
  version: string
  content_hash: string
}

// duplication:justified web/src/fleet/signAction.ts -- signAction.ts keeps its base64url
// helpers module-private and is outside this story's scope; these mirror b64uToBytes and
// bytesToB64u there.
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

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

/**
 * Reads the stored publication summary from a workflow's verbatim JSON. Only the
 * signer, time and hash are kept; the assertion material is never surfaced.
 * Returns null when the version has no (complete) publication.
 */
export function publicationFrom(value: unknown): PublicationInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const signer = str(r.signer_account_id)
  const signedAt = str(r.signed_at)
  if (signer === '' || signedAt === '') return null
  return { signer_account_id: signer, signed_at: signedAt, content_hash: str(r.content_hash) }
}

/**
 * Runs publish/begin, the passkey prompt and publish/finish for one stored version.
 * Throws SignCancelledError if the prompt is dismissed (nothing is finished),
 * NoPasskeyError when the account has no passkey, ContentMismatchError when the
 * controller's answers do not name the version the operator asked to publish, and
 * ControlHttpError for any refused request.
 */
export async function publishWorkflow(name: string, version: string): Promise<PublicationInfo> {
  const base = `/api/v1/workflows/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}/publish`

  let begin: BeginResponse
  try {
    begin = await postJson<BeginResponse>(`${base}/begin`, {})
  } catch (e) {
    if (e instanceof ControlHttpError && e.code === 'NO_CREDENTIALS') throw new NoPasskeyError()
    throw e
  }
  // Refuse to prompt for anything other than the version the operator asked to publish.
  if (begin.name !== name || begin.version !== version) throw new ContentMismatchError()

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

  const finish = await postJson<Record<string, unknown>>(`${base}/finish`, {
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
  const info = publicationFrom(finish)
  if (info === null || str(finish.name) !== name || str(finish.version) !== version) {
    throw new ContentMismatchError()
  }
  return info
}
