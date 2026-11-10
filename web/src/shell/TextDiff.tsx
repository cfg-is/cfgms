// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TextDiff (Issue #6036) — renders a unified-diff string line by line, colouring
 * added and removed lines from the state tokens. The +/- prefix stays on every
 * line, so colour is never the only signal.
 *
 * Security A9.1: diff text is untrusted-origin data. Every line is a React text
 * node; there is no HTML parsing and no dangerouslySetInnerHTML.
 */
import './TextDiff.css'

export type DiffLineKind = 'header' | 'added' | 'removed' | 'context'

export function classifyDiffLine(line: string): DiffLineKind {
  if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('@@')) return 'header'
  if (line.startsWith('+')) return 'added'
  if (line.startsWith('-')) return 'removed'
  return 'context'
}

export default function TextDiff({
  diff,
  'data-testid': testId,
}: {
  diff: string
  'data-testid'?: string
}) {
  const lines = diff.split('\n')
  const last = lines.length - 1
  return (
    <pre className="textdiff" data-testid={testId}>
      {lines.map((line, i) => (
        // The newline lives inside the line's own block so the container's
        // textContent is exactly the diff string.
        <span
          // Diff lines have no identity beyond position; the list is never reordered.
          key={i}
          className={`textdiff-line textdiff-${classifyDiffLine(line)}`}
        >
          {i < last ? `${line}\n` : line}
        </span>
      ))}
    </pre>
  )
}
