// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Global search (Story #2496) — mockups/fleet-overview.html `.searchbox`.
 * Chrome only: a controlled input scoping to whatever view mounts under
 * the shell (fleet overview, #2497) filters client-side. No search
 * backend call is introduced here.
 */
export default function GlobalSearch({
  value,
  onChange,
}: {
  value: string
  onChange: (value: string) => void
}) {
  return (
    <div className="searchbox">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.7" />
        <path d="M20 20l-3-3" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
      <input
        role="searchbox"
        type="text"
        placeholder="Filter stewards by name, user, IP, company…"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  )
}
