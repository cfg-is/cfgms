// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * SelectorInput (Story #2730) — the one shared selector-expression input.
 *
 * Extracted from GlobalSearch (#2726) so the fleet search box and the config
 * push panel bind the SAME widget to GET ...?q=<selector>, rather than
 * maintaining two divergent inputs. It renders the text field plus the grammar
 * hint; the caller supplies the surrounding chrome (the shell search box keeps
 * its magnifying-glass icon and `.searchbox` frame). The same selector grammar
 * as `cfg steward list`; see docs/administration/cli-selectors.md.
 *
 * `hintId`/`hintTestId` are per-instance so two SelectorInputs can coexist on
 * one page (e.g. the shell search and an open push panel) without colliding on
 * the element id `aria-describedby` points at.
 */
export default function SelectorInput({
  value,
  onChange,
  hintId,
  placeholder,
  role = 'textbox',
  ariaLabel,
  hintTestId,
  className,
}: {
  value: string
  onChange: (value: string) => void
  hintId: string
  placeholder: string
  role?: string
  ariaLabel?: string
  hintTestId?: string
  className?: string
}) {
  return (
    <>
      <input
        role={role}
        type="text"
        className={className}
        placeholder={placeholder}
        aria-label={ariaLabel}
        aria-describedby={hintId}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      <span
        id={hintId}
        className="search-hint"
        aria-label="Selector syntax"
        data-testid={hintTestId}
      >
        id: name: os: tag: dna.&lt;key&gt;:
      </span>
    </>
  )
}
