// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Fleet view data states (Story #2497) — mockup preview states: skeleton
 * rows while loading, an error notice with a retry affordance, and two
 * distinguishable empty states ("no stewards enrolled" vs "nothing matched
 * the filter/scope").
 */

export function LoadingRows() {
  return (
    <div data-testid="fleet-loading" aria-label="Loading stewards">
      {Array.from({ length: 6 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '75%' }} />
          <span className="skel" style={{ width: '60%' }} />
          <span className="skel" style={{ width: '70%' }} />
          <span className="skel" style={{ width: '50%' }} />
          <span className="skel" style={{ width: '55%' }} />
        </div>
      ))}
    </div>
  )
}

export function ErrorNotice({
  detail,
  onRetry,
}: {
  detail: string
  onRetry: () => void
}) {
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>Couldn&apos;t reach the controller</h3>
      <p>The fleet list request failed. Check your connection and try again.</p>
      <span className="mono detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

/** The fleet itself is empty — no steward has ever enrolled. */
export function FleetEmpty() {
  return (
    <div className="notice empty">
      <div className="ic">◍</div>
      <h3>No stewards enrolled yet</h3>
      <p>
        Once you install a steward and it registers with this controller,
        it&apos;ll appear here with live health.
      </p>
    </div>
  )
}

/** Stewards exist, but the live filter or tenant scope matched none. */
export function NoMatch({ scopeOnly }: { scopeOnly: boolean }) {
  return (
    <div className="notice empty">
      <div className="ic">◍</div>
      {scopeOnly ? (
        <>
          <h3>No stewards in this scope</h3>
          <p>The selected tenant scope contains no stewards on this page.</p>
        </>
      ) : (
        <>
          <h3>No stewards match your filter</h3>
          <p>Nothing on this page matches the current search. Clear the filter to see all rows.</p>
        </>
      )}
    </div>
  )
}
