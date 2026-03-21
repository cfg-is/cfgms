// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

// Addr implements net.Addr for QUIC endpoints.
type Addr struct {
	network string
	address string
}

// Network returns the network name ("quic").
func (a *Addr) Network() string { return a.network }

// String returns the address string (host:port).
func (a *Addr) String() string { return a.address }

// newAddr creates a new Addr with network "quic" and the given address string.
func newAddr(address string) *Addr {
	return &Addr{network: "quic", address: address}
}
