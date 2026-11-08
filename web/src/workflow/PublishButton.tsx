// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * PublishButton — publish the open workflow version with a passkey tap, and the
 * status chip that shows it published (Issue #5857, ADR-036 §4).
 *
 * Publish signs the version the controller has stored, so it is disabled with a
 * visible reason while the editor holds unsaved edits: what is signed is what is
 * stored. A dismissed passkey prompt sends nothing and shows no error.
 *
 * Security A9.1: the signer and time come from the controller and are rendered as
 * JSX text only.
 */
import { useState } from 'react'
import { ControlHttpError, NoPasskeyError, SignCancelledError } from '../fleet/signAction.ts'
import { publishWorkflow, type PublicationInfo } from './publishWorkflow.ts'

interface Props {
  name: string
  /** The stored version the open editor was loaded from; '' when nothing is stored. */
  version: string
  isNew: boolean
  /** The editor differs from (or is still saving toward) the stored version. */
  unsaved: boolean
  publication: PublicationInfo | null
  onPublished: (publication: PublicationInfo) => void
}

function disabledReason(p: Props): string | null {
  if (p.publication !== null) return null
  if (p.isNew || p.version === '') return 'Save the workflow before publishing it.'
  if (p.unsaved) return 'Save your changes before publishing — Publish signs the stored version, not the editor.'
  return null
}

function errorMessage(e: unknown): string {
  if (e instanceof NoPasskeyError) return 'Register a passkey before publishing.'
  if (e instanceof ControlHttpError) {
    if (e.status === 403) return 'You do not have permission to publish this workflow.'
    return `Publish failed — ${e.status}`
  }
  return 'Publish failed'
}

function signedAtLabel(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export default function PublishButton(props: Props) {
  const { name, version, publication, onPublished } = props
  const [publishing, setPublishing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const reason = disabledReason(props)

  async function handlePublish() {
    if (publishing || reason !== null || publication !== null) return
    setPublishing(true)
    setError(null)
    try {
      onPublished(await publishWorkflow(name, version))
    } catch (e: unknown) {
      // A dismissed prompt is the operator's choice, not a failure.
      if (!(e instanceof SignCancelledError)) setError(errorMessage(e))
    } finally {
      setPublishing(false)
    }
  }

  return (
    <>
      {publication !== null && (
        <span className="pill ok" data-testid="publish-chip">
          <span className="dot" />
          Published by {publication.signer_account_id} · {signedAtLabel(publication.signed_at)}
        </span>
      )}
      {error !== null && <span className="wf-form-error" data-testid="publish-error">{error}</span>}
      {reason !== null && (
        <span className="mut" id="publish-disabled-reason" data-testid="publish-disabled-reason">{reason}</span>
      )}
      <button
        type="button"
        className="wf-btn-secondary"
        onClick={handlePublish}
        disabled={publishing || reason !== null || publication !== null}
        aria-describedby={reason !== null ? 'publish-disabled-reason' : undefined}
        data-testid="builder-publish"
      >
        {publishing ? 'Waiting for passkey…' : 'Publish'}
      </button>
    </>
  )
}
