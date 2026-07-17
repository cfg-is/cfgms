// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Global search (Story #2496, #2726) — sends the selector expression to
 * GET /api/v1/stewards?q= for fleet-wide, server-side filtering. The same
 * grammar as `cfg steward list`; see docs/administration/cli-selectors.md.
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
        placeholder="Search fleet: name:web* os:linux tag:prod"
        aria-describedby="search-selector-hint"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      <span
        id="search-selector-hint"
        className="search-hint"
        aria-label="Selector syntax"
        data-testid="search-syntax-hint"
      >
        id: name: os: tag: dna.&lt;key&gt;:
      </span>
    </div>
  )
}
