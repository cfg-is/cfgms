// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useArtifacts (Issue #5456, Epic #5300) — installer artifact upload/delete and
 * signed steward binary publish for the Installer page.
 *
 *   PUT    /api/v1/installer/artifacts/{platform}/{arch}   raw file body, presence tap
 *   DELETE /api/v1/installer/artifacts/{platform}/{arch}   presence tap
 *   POST   /api/v1/installer/steward-binaries/{version}/{platform}/{arch}?signature=<base64>
 *                                                          raw file body, presence tap
 *
 * The File (a Blob) is passed as the body, never a stream, so the replay
 * apiFetch performs after the passkey tap re-reads the full bytes. A cancelled
 * ceremony comes back as the original 401 and surfaces as a worded message with
 * no second request.
 */
import { useCallback, useState } from 'react'
import { apiFetch } from '../api/client.ts'

/** Mirrors maxBinaryRequestBodyBytes in validation_middleware.go. */
export const MAX_BODY_BYTES = 64 * 1024 * 1024
export const MAX_BODY_LABEL = '64 MiB'

export const OVERSIZE_MESSAGE = `This file is larger than the ${MAX_BODY_LABEL} limit — nothing was sent.`

export interface PublishParams {
  version: string
  platform: string
  arch: string
  signature: string
  file: File
}

async function failure(response: Response, fallback: string): Promise<string> {
  if (response.status === 401) return 'The passkey check was cancelled — nothing was sent.'
  try {
    const body: unknown = await response.json()
    const err = (body as { error?: { message?: unknown } | unknown } | null)?.error
    const message = typeof err === 'object' && err !== null ? (err as { message?: unknown }).message : err
    if (typeof message === 'string' && message !== '') return `${fallback} — ${message}`
  } catch {
    // fall through to the status-only message
  }
  return `${fallback} — ${response.status}`
}

function artifactPath(platform: string, arch: string): string {
  return `/api/v1/installer/artifacts/${encodeURIComponent(platform)}/${encodeURIComponent(arch)}`
}

export interface UseArtifacts {
  busy: boolean
  error: string | null
  note: string | null
  upload: (platform: string, arch: string, file: File) => Promise<boolean>
  remove: (platform: string, arch: string) => Promise<boolean>
  publish: (params: PublishParams) => Promise<boolean>
}

export function useArtifacts(onChanged: () => void): UseArtifacts {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)

  const run = useCallback(
    async (fallback: string, success: string, send: () => Promise<Response>, refresh: boolean) => {
      setBusy(true)
      setError(null)
      setNote(null)
      try {
        const response = await send()
        if (!response.ok) {
          setError(await failure(response, fallback))
          return false
        }
        setNote(success)
        if (refresh) onChanged()
        return true
      } catch (cause: unknown) {
        setError(cause instanceof Error && cause.message ? cause.message : fallback)
        return false
      } finally {
        setBusy(false)
      }
    },
    [onChanged],
  )

  const upload = useCallback(
    (platform: string, arch: string, file: File) => {
      if (file.size > MAX_BODY_BYTES) {
        setNote(null)
        setError(OVERSIZE_MESSAGE)
        return Promise.resolve(false)
      }
      return run(
        'Upload failed',
        `Uploaded the ${platform}/${arch} artifact.`,
        () =>
          apiFetch(artifactPath(platform, arch), {
            method: 'PUT',
            headers: { 'Content-Type': file.type || 'application/octet-stream' },
            body: file,
          }),
        true,
      )
    },
    [run],
  )

  const remove = useCallback(
    (platform: string, arch: string) =>
      run(
        'Delete failed',
        `Deleted the ${platform}/${arch} artifact.`,
        () => apiFetch(artifactPath(platform, arch), { method: 'DELETE' }),
        true,
      ),
    [run],
  )

  const publish = useCallback(
    (p: PublishParams) => {
      if (p.version.trim() === '' || p.platform === '' || p.arch === '' || p.signature.trim() === '') {
        setNote(null)
        setError('Version, platform, architecture and signature are all required — nothing was sent.')
        return Promise.resolve(false)
      }
      if (p.file.size > MAX_BODY_BYTES) {
        setNote(null)
        setError(OVERSIZE_MESSAGE)
        return Promise.resolve(false)
      }
      const path =
        `/api/v1/installer/steward-binaries/${encodeURIComponent(p.version.trim())}` +
        `/${encodeURIComponent(p.platform)}/${encodeURIComponent(p.arch)}` +
        `?signature=${encodeURIComponent(p.signature.trim())}`
      return run(
        'Publish failed',
        `Published steward binary ${p.version.trim()} for ${p.platform}/${p.arch}.`,
        () =>
          apiFetch(path, {
            method: 'POST',
            headers: { 'Content-Type': p.file.type || 'application/octet-stream' },
            body: p.file,
          }),
        false,
      )
    },
    [run],
  )

  return { busy, error, note, upload, remove, publish }
}
