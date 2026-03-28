// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import "context"

// SecurityCollector defines the interface for platform-specific security attribute collection
type SecurityCollector interface {
	// CollectUsers gathers user account information
	CollectUsers(ctx context.Context, attributes map[string]string) error

	// CollectGroups gathers group information
	CollectGroups(ctx context.Context, attributes map[string]string) error

	// CollectPermissions gathers file/directory permission information
	CollectPermissions(ctx context.Context, attributes map[string]string) error

	// CollectCertificates gathers installed certificate information
	CollectCertificates(ctx context.Context, attributes map[string]string) error
}

// NewSecurityCollector creates a platform-specific security collector
func NewSecurityCollector() SecurityCollector {
	return newPlatformSecurityCollector()
}

// GenericSecurityCollector provides basic cross-platform security collection
// This is used as a fallback when platform-specific collectors are not available
type GenericSecurityCollector struct{}

func (g *GenericSecurityCollector) CollectUsers(_ context.Context, attributes map[string]string) error {
	// Generic user collection - limited without platform-specific APIs
	attributes["user_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSecurityCollector) CollectGroups(_ context.Context, attributes map[string]string) error {
	// Generic group collection - limited without platform-specific APIs
	attributes["group_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSecurityCollector) CollectPermissions(_ context.Context, attributes map[string]string) error {
	// Generic permission collection - limited without platform-specific APIs
	attributes["permission_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSecurityCollector) CollectCertificates(_ context.Context, attributes map[string]string) error {
	// Generic certificate collection - limited without platform-specific APIs
	attributes["certificate_info"] = "generic_collector_limited"
	return nil
}

// Platform-specific collector types (implementations in separate files)

// WindowsSecurityCollector handles Windows-specific security collection
type WindowsSecurityCollector struct{}

func (w *WindowsSecurityCollector) CollectUsers(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectUsers(ctx, attributes)
}

func (w *WindowsSecurityCollector) CollectGroups(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectGroups(ctx, attributes)
}

func (w *WindowsSecurityCollector) CollectPermissions(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectPermissions(ctx, attributes)
}

func (w *WindowsSecurityCollector) CollectCertificates(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectCertificates(ctx, attributes)
}

// LinuxSecurityCollector handles Linux-specific security collection
type LinuxSecurityCollector struct{}

func (l *LinuxSecurityCollector) CollectUsers(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectUsers(ctx, attributes)
}

func (l *LinuxSecurityCollector) CollectGroups(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectGroups(ctx, attributes)
}

func (l *LinuxSecurityCollector) CollectPermissions(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectPermissions(ctx, attributes)
}

func (l *LinuxSecurityCollector) CollectCertificates(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectCertificates(ctx, attributes)
}

// DarwinSecurityCollector handles macOS-specific security collection
type DarwinSecurityCollector struct{}
