// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Service row action menu (Story #4629): Start, Stop, Restart, each
 * operator-signed (signAction.ts). Items are not hidden by service state: the
 * state strings differ per platform and the steward decides what is valid.
 */
import ActionMenuBase, { type ActionItem } from './ActionMenuBase.tsx'
import type { StewardControl } from './useStewardControl.ts'

interface ServiceActionMenuProps {
  stewardId: string
  name: string
  control: StewardControl
}

export default function ServiceActionMenu({ stewardId, name, control }: ServiceActionMenuProps) {
  const items: ActionItem[] = (
    [
      ['start', 'Start'],
      ['stop', 'Stop'],
      ['restart', 'Restart'],
    ] as const
  ).map(([action, label]) => ({
    id: action,
    label,
    title: `${label} service`,
    spec: { targetKind: 'service', targetName: name, action },
  }))

  return (
    <ActionMenuBase
      stewardId={stewardId}
      rowLabel={name}
      targetText={`Service ${name}`}
      items={items}
      control={control}
    />
  )
}
