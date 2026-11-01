// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Alert severity marker (Issue #4584). Severity is never colour alone: the
 * icon shape differs (triangle for warning, octagon for critical) and a text
 * label is always rendered, so assistive tech and monochrome displays get the
 * same information. Shared by AlertCenter and AlertsView.
 */

export function severityLabel(severity: string): string {
  switch (severity) {
    case 'critical': return 'Critical'
    case 'warning': return 'Warning'
    case '': return 'Unknown'
    default: return severity
  }
}

function color(severity: string): string {
  switch (severity) {
    case 'critical': return 'var(--state-crit)'
    case 'warning': return 'var(--state-warn)'
    default: return 'var(--text-faint)'
  }
}

export default function AlertSeverity({ severity }: { severity: string }) {
  const label = severityLabel(severity)
  return (
    <span
      className="alert-sev"
      data-testid="alert-severity"
      data-severity={severity}
      style={{ color: color(severity) }}
    >
      <svg
        width="12"
        height="12"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
        strokeLinecap="round"
        aria-hidden="true"
      >
        {severity === 'critical' ? (
          <>
            <path d="M5.2 1.8h5.6l4 4v4.4l-4 4H5.2l-4-4V5.8z" />
            <path d="M8 5v3.5M8 10.8v.05" />
          </>
        ) : severity === 'warning' ? (
          <>
            <path d="M8 2l6.5 11.5h-13z" />
            <path d="M8 6.5v3M8 11.3v.05" />
          </>
        ) : (
          <circle cx="8" cy="8" r="5.5" />
        )}
      </svg>
      <span className="alert-sev-label">{label}</span>
    </span>
  )
}
