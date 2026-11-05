// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package commands

import (
	"context"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

// NewOperatorOrigin returns ctx carrying the operator-origin marker for an
// authenticated operator principal. It is the only constructor controller code
// may use: the lockdown gate on SendCommand and FanOutCommand lets a command
// reach a locked-down steward only when its context carries this marker and its
// type is on the allow-list.
//
// Callers are the dispatcher, for an execution an operator API call created,
// and the terminal handler, for an authenticated operator session. An
// inventory test fails on any other non-test caller. Publisher methods and
// PublishCommandWithSigner never create it. The marker is never derived from
// command params: the controller does not verify the operator's end-to-end proof
// at dispatch, so params content is not an origin signal.
//
// An empty principal returns ctx unchanged, so an unauthenticated caller cannot
// obtain the marker.
func NewOperatorOrigin(ctx context.Context, principal string) context.Context {
	return controlplaneInterfaces.WithOperatorOrigin(ctx, principal)
}

// OperatorOrigin reports the operator principal carried on ctx.
func OperatorOrigin(ctx context.Context) (string, bool) {
	return controlplaneInterfaces.OperatorOriginFrom(ctx)
}
