// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package modules

import "fmt"

// WindowsACL declares the desired Windows NTFS ACL for a resource.
type WindowsACL struct {
	Owner   string     `yaml:"owner,omitempty"  json:"owner,omitempty"`
	Entries []ACLEntry `yaml:"entries"          json:"entries"`
}

// ACLEntry is a single Windows ACL entry.
type ACLEntry struct {
	Principal string `yaml:"principal" json:"principal"` // e.g. "BUILTIN\\Administrators"
	Access    string `yaml:"access"    json:"access"`    // FullControl|ReadAndExecute|Modify|Write|Read
}

// ValidateACLAccess returns an error when access is not one of the recognized
// levels: FullControl, ReadAndExecute, Modify, Write, Read.
// It is platform-agnostic so config-level validation can be tested without a Windows runner.
func ValidateACLAccess(access string) error {
	switch access {
	case "FullControl", "ReadAndExecute", "Modify", "Write", "Read":
		return nil
	default:
		return fmt.Errorf("unsupported access level %q: must be one of FullControl, ReadAndExecute, Modify, Write, Read", access)
	}
}
