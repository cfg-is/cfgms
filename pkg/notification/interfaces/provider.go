// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces defines the contract for outbound notification delivery
// and the registry through which providers are selected by name. Business
// logic imports this package only; provider packages register themselves from
// init() and are blank-imported by the binary that wires them.
package interfaces

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Message is a plain-text notification addressed to one or more recipients.
type Message struct {
	To      []string
	Subject string
	// Body is plain text. Providers must not interpret it as markup.
	Body string
}

// RecipientResult is the delivery outcome for a single recipient.
type RecipientResult struct {
	Address  string
	Accepted bool
	// Reason is a sanitized explanation when Accepted is false. It never
	// contains credentials.
	Reason string
}

// DeliveryResult reports per-recipient outcomes, in the order of Message.To.
type DeliveryResult struct {
	Recipients []RecipientResult
}

// Accepted returns the addresses that were accepted for delivery.
func (r *DeliveryResult) Accepted() []string {
	var out []string
	for _, rr := range r.Recipients {
		if rr.Accepted {
			out = append(out, rr.Address)
		}
	}
	return out
}

// Failed returns the recipients that were not accepted.
func (r *DeliveryResult) Failed() []RecipientResult {
	var out []RecipientResult
	for _, rr := range r.Recipients {
		if !rr.Accepted {
			out = append(out, rr)
		}
	}
	return out
}

// Notifier delivers messages. Send returns a non-nil result alongside a nil
// error whenever delivery was attempted, even if some recipients failed. An
// error with a nil result means nothing was attempted or the transport failed
// as a whole; error text never contains recipients or credentials.
type Notifier interface {
	Send(ctx context.Context, msg Message) (*DeliveryResult, error)
	Name() string
}

// NotifierProvider creates Notifiers from a configuration map. Credentials in
// the map are already-resolved values; providers never read files or the
// environment themselves.
type NotifierProvider interface {
	Name() string
	Description() string
	CreateNotifier(config map[string]interface{}) (Notifier, error)
}

// ErrUnknownProvider is returned when no provider is registered under a name.
var ErrUnknownProvider = errors.New("unknown notification provider")

var (
	registryMu sync.RWMutex
	registry   = make(map[string]NotifierProvider)
)

// RegisterNotifierProvider registers a provider; called from provider init().
// Registering a nil provider, an empty name, or a duplicate name panics, since
// these are programming errors caught at startup.
func RegisterNotifierProvider(p NotifierProvider) {
	if p == nil || strings.TrimSpace(p.Name()) == "" {
		panic("notification: provider must be non-nil with a non-empty name")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[p.Name()]; dup {
		panic(fmt.Sprintf("notification: provider %q already registered", p.Name()))
	}
	registry[p.Name()] = p
}

// UnregisterNotifierProvider removes a provider (primarily for tests).
func UnregisterNotifierProvider(name string) bool {
	registryMu.Lock()
	defer registryMu.Unlock()
	_, ok := registry[name]
	delete(registry, name)
	return ok
}

// GetNotifierProvider returns the provider registered under name.
func GetNotifierProvider(name string) (NotifierProvider, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	return p, nil
}

// GetRegisteredProviderNames lists registered provider names, sorted.
func GetRegisteredProviderNames() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CreateNotifierFromConfig creates a Notifier from the named provider.
func CreateNotifierFromConfig(providerName string, config map[string]interface{}) (Notifier, error) {
	p, err := GetNotifierProvider(providerName)
	if err != nil {
		return nil, err
	}
	return p.CreateNotifier(config)
}
