// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * publishWorkflow tests (Issue #5857) — the real helper and real apiFetch over a
 * fetch transport that speaks publish/begin and publish/finish. Only
 * navigator.credentials is shimmed: jsdom has no authenticator.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { publicationFrom, publishWorkflow } from './publishWorkflow.ts'
import { ControlHttpError, ContentMismatchError, NoPasskeyError, SignCancelledError } from '../fleet/signAction.ts'

interface Call { path: string; body: unknown }

let calls: Call[]
let credentialsGet: ReturnType<typeof vi.fn>
let beginResponse: () => Response
let finishResponse: () => Response

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function fakeCredential() {
  const buf = new Uint8Array([1, 2, 3]).buffer
  return {
    id: 'cred', type: 'public-key', rawId: buf,
    response: { authenticatorData: buf, clientDataJSON: buf, signature: buf, userHandle: new Uint8Array([9]).buffer },
  }
}

const BEGIN_OK = {
  data: {
    assertion: { publicKey: { challenge: 'AAEC', rpId: 'cfgms.test', allowCredentials: [{ type: 'public-key', id: 'AAEC' }] } },
    name: 'deploy wf',
    version: '1.2.0',
    content_hash: 'h1',
  },
}
const FINISH_OK = {
  data: { name: 'deploy wf', version: '1.2.0', content_hash: 'h1', signer_account_id: 'acct-7', signed_at: '2030-01-02T03:04:05Z' },
}

beforeEach(() => {
  calls = []
  beginResponse = () => jsonResp(200, BEGIN_OK)
  finishResponse = () => jsonResp(200, FINISH_OK)
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    calls.push({ path, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    if (path.endsWith('/publish/begin')) return beginResponse()
    if (path.endsWith('/publish/finish')) return finishResponse()
    return jsonResp(404, {})
  })
  credentialsGet = vi.fn(async () => fakeCredential())
  Object.defineProperty(navigator, 'credentials', { value: { get: credentialsGet }, configurable: true })
})

afterEach(() => vi.unstubAllGlobals())

const BEGIN_PATH = '/api/v1/workflows/deploy%20wf/versions/1.2.0/publish/begin'
const FINISH_PATH = '/api/v1/workflows/deploy%20wf/versions/1.2.0/publish/finish'

describe('publishWorkflow', () => {
  it('runs begin, the WebAuthn prompt and finish, and returns the publication', async () => {
    const pub = await publishWorkflow('deploy wf', '1.2.0')
    expect(calls.map((c) => c.path)).toEqual([BEGIN_PATH, FINISH_PATH])
    expect(credentialsGet).toHaveBeenCalledTimes(1)
    const opts = credentialsGet.mock.calls[0]![0] as { publicKey: { challenge: Uint8Array; rpId: string } }
    expect(Array.from(opts.publicKey.challenge)).toEqual([0, 1, 2])
    expect(opts.publicKey.rpId).toBe('cfgms.test')
    expect(calls[1]!.body).toMatchObject({
      id: 'cred',
      type: 'public-key',
      response: { authenticatorData: 'AQID', clientDataJSON: 'AQID', signature: 'AQID', userHandle: 'CQ' },
    })
    expect(pub).toEqual({ signer_account_id: 'acct-7', signed_at: '2030-01-02T03:04:05Z', content_hash: 'h1' })
  })

  it('sends no finish request when the passkey prompt is cancelled', async () => {
    credentialsGet.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError'))
    await expect(publishWorkflow('deploy wf', '1.2.0')).rejects.toBeInstanceOf(SignCancelledError)
    expect(calls.map((c) => c.path)).toEqual([BEGIN_PATH])
  })

  it('sends no finish request when the prompt yields no credential', async () => {
    credentialsGet.mockResolvedValue(null)
    await expect(publishWorkflow('deploy wf', '1.2.0')).rejects.toBeInstanceOf(SignCancelledError)
    expect(calls.map((c) => c.path)).toEqual([BEGIN_PATH])
  })

  it('refuses to prompt when begin names a different version', async () => {
    beginResponse = () => jsonResp(200, { data: { ...BEGIN_OK.data, version: '9.9.9' } })
    await expect(publishWorkflow('deploy wf', '1.2.0')).rejects.toBeInstanceOf(ContentMismatchError)
    expect(credentialsGet).not.toHaveBeenCalled()
    expect(calls).toHaveLength(1)
  })

  it('maps NO_CREDENTIALS from begin to NoPasskeyError without prompting', async () => {
    beginResponse = () => jsonResp(409, { error: { code: 'NO_CREDENTIALS' } })
    await expect(publishWorkflow('deploy wf', '1.2.0')).rejects.toBeInstanceOf(NoPasskeyError)
    expect(credentialsGet).not.toHaveBeenCalled()
  })

  it('surfaces a 403 from begin and never prompts', async () => {
    beginResponse = () => jsonResp(403, { error: { code: 'FORBIDDEN' } })
    const err = await publishWorkflow('deploy wf', '1.2.0').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ControlHttpError)
    expect((err as ControlHttpError).status).toBe(403)
    expect(credentialsGet).not.toHaveBeenCalled()
  })

  it('surfaces a refused finish as ControlHttpError', async () => {
    finishResponse = () => jsonResp(409, { error: { code: 'CONTENT_CHANGED' } })
    const err = await publishWorkflow('deploy wf', '1.2.0').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ControlHttpError)
    expect((err as ControlHttpError).status).toBe(409)
  })

  it('rejects a finish response that does not carry a signer and time', async () => {
    finishResponse = () => jsonResp(200, { data: { name: 'deploy wf', version: '1.2.0' } })
    await expect(publishWorkflow('deploy wf', '1.2.0')).rejects.toBeInstanceOf(ContentMismatchError)
  })
})

describe('publicationFrom', () => {
  it('reads the stored publication summary and drops the assertion material', () => {
    expect(
      publicationFrom({
        content_hash: 'h', signer_account_id: 'a', signed_at: '2030-01-01T00:00:00Z',
        signature: 'secret', nonce: 'n',
      }),
    ).toEqual({ content_hash: 'h', signer_account_id: 'a', signed_at: '2030-01-01T00:00:00Z' })
  })

  it.each([undefined, null, 'x', 7, {}, { signer_account_id: 'a' }, { signed_at: 't' }])(
    'returns null for %j',
    (v) => expect(publicationFrom(v)).toBeNull(),
  )
})
