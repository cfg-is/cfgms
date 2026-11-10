// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * LibraryModePanel (Issue #5856, Epic #5421) — shows and changes the approval
 * mode of one content library (ADR-036 section 2). The library kind is a prop so
 * the workflow library reuses this panel unchanged (Issue #5861).
 *
 * The mode is a rarely touched setting that bounds the blast radius of a phished
 * admin, so choosing a mode only stages it: the change is sent after an explicit
 * confirm, through PUT /api/v1/automation/libraries/{kind}/mode, which is
 * presence-gated. The tap is handled centrally by apiFetch / StepUpModal. After a
 * successful change the mode is refetched and onChanged tells the caller to
 * refresh whatever depends on it.
 *
 * Security A9.1: every server value renders as JSX text only.
 */
import { useState } from 'react'
import {
  LIBRARY_MODES,
  useLibraryMode,
  type LibraryKind,
  type LibraryMode,
} from './useScriptApprovals.ts'

function modeLabel(mode: LibraryMode): string {
  switch (mode) {
    case 'signed':
      return 'Signed'
    case 'approve':
      return 'Approve'
    case 'comment':
      return 'Comment'
  }
}

function modeSummary(mode: LibraryMode, kind: LibraryKind): string {
  switch (mode) {
    case 'signed':
      return `A ${kind} version runs once it carries a signature from a trusted key. An unsigned version needs an admin's approval.`
    case 'approve':
      return `An admin approves each exact ${kind} version with a passkey tap. A changed version waits for approval again.`
    case 'comment':
      return `A ${kind} version runs on its own header declaration. Nobody signs or approves it.`
  }
}

/** The plain-language consequence line of a mode, shown in the confirm step. */
function modeConsequence(mode: LibraryMode, kind: LibraryKind): string {
  switch (mode) {
    case 'comment':
      return `Anyone who can write to this repository can then change what the ${kind} library runs, with no signature and no approval. Repository write access becomes equal to running code across the whole fleet. Endpoints that require signed content still refuse it.`
    case 'approve':
      return `Each ${kind} version needs an admin's approval before it runs. A changed version pauses until it is approved again.`
    case 'signed':
      return `Only ${kind} versions signed by a trusted key run without an approval.`
  }
}

export default function LibraryModePanel({
  kind,
  onChanged,
}: {
  kind: LibraryKind
  onChanged?: () => void
}) {
  const { mode, loading, error: loadError, retry, change } = useLibraryMode(kind)
  const [selected, setSelected] = useState<LibraryMode | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [changedTo, setChangedTo] = useState<LibraryMode | null>(null)

  const target = selected ?? mode
  const differs = mode !== null && target !== null && target !== mode

  async function handleConfirm() {
    if (target === null) return
    setBusy(true)
    setError(null)
    const result = await change(target)
    setBusy(false)
    if (!result.ok) {
      setError(result.error)
      return
    }
    setConfirming(false)
    setSelected(null)
    setChangedTo(target)
    onChanged?.()
  }

  return (
    <div className="cfg-push-panel" data-testid="library-mode-panel">
      <div className="cfg-push-form">
        <div className="cfg-push-field">
          <span className="cfg-push-label">Approval mode of the {kind} library</span>
          <span className="mut">
            Changing the mode needs a passkey tap and is recorded in the audit trail.
          </span>
        </div>

        {loading ? (
          <div className="mut" data-testid="library-mode-loading">
            Loading mode…
          </div>
        ) : loadError !== null ? (
          <div className="cfg-validation-err" data-testid="library-mode-load-error">
            {loadError}{' '}
            <button type="button" className="cfg-btn-secondary" onClick={retry}>
              Retry
            </button>
          </div>
        ) : (
          <>
            <div className="cfg-push-field" role="radiogroup" aria-label={`Approval mode of the ${kind} library`}>
              {LIBRARY_MODES.map((m) => (
                <label key={m} className="cfg-push-row">
                  <input
                    type="radio"
                    name={`library-mode-${kind}`}
                    value={m}
                    checked={target === m}
                    disabled={busy}
                    onChange={() => {
                      setSelected(m)
                      setConfirming(false)
                      setError(null)
                      setChangedTo(null)
                    }}
                    data-testid={`library-mode-${m}`}
                  />
                  <span className="nm">{modeLabel(m)}</span>
                  {m === mode && <span className="pill neutral">Current</span>}
                  <span className="mut">{modeSummary(m, kind)}</span>
                </label>
              ))}
            </div>

            {differs && !confirming && (
              <div className="cfg-push-actions">
                <button
                  type="button"
                  className="cfg-btn"
                  onClick={() => setConfirming(true)}
                  data-testid="library-mode-change-btn"
                >
                  Change mode
                </button>
              </div>
            )}

            {differs && confirming && target !== null && (
              <div
                role="alertdialog"
                aria-label="Confirm approval mode change"
                className="notice"
                data-testid="library-mode-confirm"
              >
                <h3>
                  Change the {kind} library to {modeLabel(target)} mode?
                </h3>
                <p data-testid="library-mode-consequence">{modeConsequence(target, kind)}</p>
                <div className="cfg-push-actions">
                  <button
                    type="button"
                    className="cfg-btn"
                    disabled={busy}
                    onClick={() => void handleConfirm()}
                    data-testid="library-mode-confirm-btn"
                  >
                    {busy ? 'Changing…' : 'Confirm change'}
                  </button>
                  <button
                    type="button"
                    className="cfg-btn-secondary"
                    disabled={busy}
                    onClick={() => setConfirming(false)}
                    data-testid="library-mode-cancel-btn"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </>
        )}

        {error !== null && (
          <div className="cfg-validation-err" data-testid="library-mode-error">
            {error}
          </div>
        )}
        {changedTo !== null && (
          <div className="cfg-push-status" role="status" data-testid="library-mode-changed">
            Mode changed to {modeLabel(changedTo)}
          </div>
        )}
      </div>
    </div>
  )
}
