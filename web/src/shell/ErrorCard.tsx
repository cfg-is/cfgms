// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Shared error card (Story #2945). Classifies the failure class from the
 * error detail string the client already holds:
 *   — 5xx in detail → server-side error (don't blame connectivity)
 *   anything else   → connectivity / generic fallback
 *
 * Uses the existing `notice err` CSS class so it renders consistently with
 * the app shell's error notice pattern.
 */

function isServerError(detail: string): boolean {
  return /—\s*5\d\d/.test(detail)
}

export default function ErrorCard({
  heading,
  detail,
  onRetry,
}: {
  heading: string
  detail: string
  onRetry: () => void
}) {
  const copy = isServerError(detail)
    ? 'The server returned an error. Try again in a moment.'
    : 'Check your connection and try again.'
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>{heading}</h3>
      <p>{copy}</p>
      <span className="mono2 detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}
