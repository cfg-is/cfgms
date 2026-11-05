// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package egcommon holds the dialect-independent code shared by the entity
// graph database (PostgreSQL) and sqlite providers. Each provider keeps its
// real dialect differences (SQL text, placeholder style, watermark logic) and
// passes a Dialect to the helpers here.
//
// The package is internal to pkg/entitygraph/providers: it is not a provider
// and carries no state.
package egcommon

// Dialect carries the few values that differ between providers for otherwise
// identical code.
type Dialect struct {
	// Prefix starts every error string produced on the provider's behalf, for
	// example "entitygraph/sqlite". Error text stays byte-identical per provider.
	Prefix string
	// Placeholders returns a parenthesised IN-list placeholder group of length n
	// in the provider's bind-parameter style.
	Placeholders func(n int) string
}
