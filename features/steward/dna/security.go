// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

// SecurityCollector defines the interface for platform-specific security attribute collection
type SecurityCollector interface {
	// CollectUsers gathers user account information
	CollectUsers(attributes map[string]string) error

	// CollectGroups gathers group information
	CollectGroups(attributes map[string]string) error

	// CollectPermissions gathers file/directory permission information
	CollectPermissions(attributes map[string]string) error

	// CollectCertificates gathers installed certificate information
	CollectCertificates(attributes map[string]string) error
}

// NewSecurityCollector creates a platform-specific security collector
func NewSecurityCollector() SecurityCollector {
	return newPlatformSecurityCollector()
}

// GenericSecurityCollector provides basic cross-platform security collection
// This is used as a fallback when platform-specific collectors are not available
type GenericSecurityCollector struct{}

func (g *GenericSecurityCollector) CollectUsers(attributes map[string]string) error {
	// Generic user collection - limited without platform-specific APIs
	attributes["user_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSecurityCollector) CollectGroups(attributes map[string]string) error {
	// Generic group collection - limited without platform-specific APIs
	attributes["group_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSecurityCollector) CollectPermissions(attributes map[string]string) error {
	// Generic permission collection - limited without platform-specific APIs
	attributes["permission_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSecurityCollector) CollectCertificates(attributes map[string]string) error {
	// Generic certificate collection - limited without platform-specific APIs
	attributes["certificate_info"] = "generic_collector_limited"
	return nil
}

// Platform-specific collector types (implementations in separate files)

// WindowsSecurityCollector handles Windows-specific security collection
type WindowsSecurityCollector struct{}

func (w *WindowsSecurityCollector) CollectUsers(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectUsers(attributes)
}

func (w *WindowsSecurityCollector) CollectGroups(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectGroups(attributes)
}

func (w *WindowsSecurityCollector) CollectPermissions(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectPermissions(attributes)
}

func (w *WindowsSecurityCollector) CollectCertificates(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectCertificates(attributes)
}

// LinuxSecurityCollector handles Linux-specific security collection
type LinuxSecurityCollector struct{}

func (l *LinuxSecurityCollector) CollectUsers(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectUsers(attributes)
}

func (l *LinuxSecurityCollector) CollectGroups(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectGroups(attributes)
}

func (l *LinuxSecurityCollector) CollectPermissions(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectPermissions(attributes)
}

func (l *LinuxSecurityCollector) CollectCertificates(attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectCertificates(attributes)
}

// DarwinSecurityCollector handles macOS-specific security collection
type DarwinSecurityCollector struct{}
