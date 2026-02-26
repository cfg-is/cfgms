// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
)

// ChallengeSolver configures an ACME challenge solver on a lego client
type ChallengeSolver interface {
	// Configure sets up the challenge solver on the given lego client
	Configure(client *lego.Client) error
	// Cleanup releases any resources held by the challenge solver
	Cleanup() error
}

// HTTPChallengeSolver handles HTTP-01 challenges by binding to a local address
type HTTPChallengeSolver struct {
	bindAddress string
}

// NewHTTPChallengeSolver creates an HTTP-01 challenge solver
func NewHTTPChallengeSolver(bindAddress string) *HTTPChallengeSolver {
	if bindAddress == "" {
		bindAddress = ":80"
	}
	return &HTTPChallengeSolver{bindAddress: bindAddress}
}

// Configure sets up the HTTP-01 challenge provider on the lego client
func (h *HTTPChallengeSolver) Configure(client *lego.Client) error {
	server := http01.NewProviderServer("", h.portFromAddress())
	if err := client.Challenge.SetHTTP01Provider(server); err != nil {
		return fmt.Errorf("%w: %v", ErrHTTPBindFailed, err)
	}
	return nil
}

// Cleanup is a no-op for HTTP challenges; the server shuts down automatically
func (h *HTTPChallengeSolver) Cleanup() error {
	return nil
}

func (h *HTTPChallengeSolver) portFromAddress() string {
	// Extract port from bind address like ":80" or "0.0.0.0:80"
	for i := len(h.bindAddress) - 1; i >= 0; i-- {
		if h.bindAddress[i] == ':' {
			return h.bindAddress[i+1:]
		}
	}
	return "80"
}

// DNSChallengeSolver handles DNS-01 challenges using a lego DNS provider
type DNSChallengeSolver struct {
	provider challenge.Provider
}

// NewDNSChallengeSolver creates a DNS-01 challenge solver with the given provider
func NewDNSChallengeSolver(provider challenge.Provider) *DNSChallengeSolver {
	return &DNSChallengeSolver{provider: provider}
}

// Configure sets up the DNS-01 challenge provider on the lego client
func (d *DNSChallengeSolver) Configure(client *lego.Client) error {
	if err := client.Challenge.SetDNS01Provider(d.provider); err != nil {
		return fmt.Errorf("%w: failed to configure DNS-01 provider: %v", ErrChallengeFailed, err)
	}
	return nil
}

// Cleanup is a no-op for DNS challenges; cleanup happens per-challenge
func (d *DNSChallengeSolver) Cleanup() error {
	return nil
}
