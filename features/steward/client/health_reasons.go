// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"sort"
	"sync"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// HealthReasonRegistry holds the machine-readable reasons a steward is not
// healthy, keyed by component. The zero value is not usable; use
// NewHealthReasonRegistry. Safe for concurrent use.
//
// Messages must be fixed strings or sanitized errors: never secrets, file
// contents or tokens.
type HealthReasonRegistry struct {
	mu      sync.RWMutex
	reasons map[string]cpTypes.HealthReason
}

// NewHealthReasonRegistry returns an empty registry.
func NewHealthReasonRegistry() *HealthReasonRegistry {
	return &HealthReasonRegistry{reasons: make(map[string]cpTypes.HealthReason)}
}

// Set records (or replaces) the reason for component.
func (r *HealthReasonRegistry) Set(component, code, message string) {
	r.mu.Lock()
	r.reasons[component] = cpTypes.HealthReason{Component: component, Code: code, Message: message}
	r.mu.Unlock()
}

// Clear removes the reason for component, if any.
func (r *HealthReasonRegistry) Clear(component string) {
	r.mu.Lock()
	delete(r.reasons, component)
	r.mu.Unlock()
}

// ClearIfCode removes the reason for component only when it carries code, so a
// component that clears its own panic reason never erases a different reason
// recorded under the same component name.
func (r *HealthReasonRegistry) ClearIfCode(component, code string) {
	r.mu.Lock()
	if cur, ok := r.reasons[component]; ok && cur.Code == code {
		delete(r.reasons, component)
	}
	r.mu.Unlock()
}

// List returns the current reasons sorted by component.
func (r *HealthReasonRegistry) List() []cpTypes.HealthReason {
	r.mu.RLock()
	out := make([]cpTypes.HealthReason, 0, len(r.reasons))
	for _, v := range r.reasons {
		out = append(out, v)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	return out
}

// healthReasonRegistry returns the client's registry, creating it on first use.
func (c *TransportClient) healthReasonRegistry() *HealthReasonRegistry {
	c.reasonsMu.Lock()
	defer c.reasonsMu.Unlock()
	if c.reasons == nil {
		c.reasons = NewHealthReasonRegistry()
	}
	return c.reasons
}

// UseHealthReasons makes the client report the reasons held by r, so a registry
// populated before the client existed (the steward's subsystem tracker) feeds
// the heartbeat. Reasons already set on the client's previous registry are
// carried over without overriding r's entries.
func (c *TransportClient) UseHealthReasons(r *HealthReasonRegistry) {
	if r == nil {
		return
	}
	c.reasonsMu.Lock()
	prev := c.reasons
	c.reasons = r
	c.reasonsMu.Unlock()
	if prev == nil || prev == r {
		return
	}
	existing := make(map[string]struct{})
	for _, e := range r.List() {
		existing[e.Component] = struct{}{}
	}
	for _, e := range prev.List() {
		if _, ok := existing[e.Component]; !ok {
			r.Set(e.Component, e.Code, e.Message)
		}
	}
}

// SetHealthReason records why component is not healthy. The heartbeat carries
// every set reason and never reports "healthy" while any is set.
func (c *TransportClient) SetHealthReason(component, code, message string) {
	c.healthReasonRegistry().Set(component, code, message)
}

// ClearHealthReason removes the reason for component.
func (c *TransportClient) ClearHealthReason(component string) {
	c.healthReasonRegistry().Clear(component)
}

// HealthReasons returns the current reasons sorted by component.
func (c *TransportClient) HealthReasons() []cpTypes.HealthReason {
	return c.healthReasonRegistry().List()
}
