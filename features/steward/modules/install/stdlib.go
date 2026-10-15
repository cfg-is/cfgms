// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package install

import "strings"

// stdlibPublisher is the only publisher that may install a module whose name is
// in the ADR-016 closed stdlib set.
const stdlibPublisher = "cfgms"

// stdlibModuleNames is the ADR-016 closed stdlib set, sorted. It is the only Go
// list of these names; the drift guard in stdlib_test.go holds it equal to the
// directory names under features/modules/stdlib/.
var stdlibModuleNames = []string{
	"cert_trust",
	"file",
	"firewall",
	"hostname",
	"package",
	"patch",
	"script",
	"service",
	"time",
	"user",
}

// StdlibModuleNames returns a copy of the sorted ADR-016 closed stdlib set
// (file, service, package, script, firewall, patch, user, cert_trust, time,
// hostname). The stdlib ships in the steward installer, so a fetched bundle must
// never take one of these names unless the baked-in cfgms publisher published it.
func StdlibModuleNames() []string {
	out := make([]string, len(stdlibModuleNames))
	copy(out, stdlibModuleNames)
	return out
}

// isStdlibName reports whether name is a stdlib module name. The comparison
// ignores case because a Windows or macOS volume treats two names differing only
// in case as one directory.
func isStdlibName(name string) bool {
	for _, n := range stdlibModuleNames {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}
