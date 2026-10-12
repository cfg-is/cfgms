// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package contract

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// SocketEnvVar is the contract variable the runtime sets for every module
// process: the address the module listens on. It is reserved — a manifest may
// not declare it, and a parent value of the same name is always replaced.
const SocketEnvVar = "CFGMS_MODULE_SOCKET"

// MaxDeclaredEnvNames bounds the module.yaml `env:` list.
const MaxDeclaredEnvNames = 64

// ReservedEnvPrefix is the prefix of every variable that configures the CFGMS
// steward or controller process itself (storage DSNs, secret-store key files,
// transport and certificate settings). A manifest may not pull any of them into
// a module: the module is a separate trust domain from the host process.
const ReservedEnvPrefix = "CFGMS_"

// reservedLoaderEnvNames are process-loader and interpreter-control variables.
// They change what code a child process loads or how its runtime behaves, so an
// approved manifest that could name them would turn a parent value into code
// injection. Grouped by reason; compared case-insensitively.
var reservedLoaderEnvNames = []string{
	// Dynamic-loader injection: load an attacker-chosen library into the child.
	"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
	"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
	// Go runtime control: debug knobs and crash-dump behaviour.
	"GODEBUG", "GOTRACEBACK",
	// Interpreter code-load paths and startup hooks.
	"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "NODE_OPTIONS", "NODE_PATH",
	"PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
	// JVM option injection: agents and flags picked up by every java launch.
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
	// Shell startup files executed when a child shell starts.
	"BASH_ENV", "ENV",
	// PowerShell module search path: resolves modules from attacker-chosen dirs.
	"PSModulePath",
}

// IsReservedEnvName reports whether name may not appear in a manifest `env:`
// list: the SocketEnvVar, any CFGMS_-prefixed name, or a loader/interpreter
// control variable. Matching is case-insensitive.
func IsReservedEnvName(name string) bool {
	if len(name) >= len(ReservedEnvPrefix) && strings.EqualFold(name[:len(ReservedEnvPrefix)], ReservedEnvPrefix) {
		return true
	}
	for _, r := range reservedLoaderEnvNames {
		if strings.EqualFold(name, r) {
			return true
		}
	}
	return false
}

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateEnvNames checks a module.yaml `env:` list: at most
// MaxDeclaredEnvNames entries, each a plain variable name (no wildcard, no
// prefix pattern, no "="), none duplicated, none reserved (SocketEnvVar, CFGMS_* names, loader and interpreter control
// variables; see IsReservedEnvName).
// Each error names the offending entry by index.
func ValidateEnvNames(names []string) error {
	if len(names) > MaxDeclaredEnvNames {
		return fmt.Errorf("env: %d names declared, at most %d are allowed", len(names), MaxDeclaredEnvNames)
	}
	seen := make(map[string]struct{}, len(names))
	for i, name := range names {
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("env[%d]: %q is not a valid variable name (must match %s; wildcards and patterns are not allowed)",
				i, name, envNamePattern.String())
		}
		if IsReservedEnvName(name) {
			return fmt.Errorf("env[%d]: %q is reserved for the module runtime", i, name)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("env[%d]: %q is declared more than once", i, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

// ModuleEnv is the result of BuildModuleEnv.
type ModuleEnv struct {
	// Env is the complete child environment in "NAME=value" form.
	Env []string
	// PassedNames is the sorted list of variable NAMES in Env. Safe to log.
	PassedNames []string
	// MissingDeclared lists declared names the parent does not have set.
	MissingDeclared []string
}

// BuildModuleEnv builds the environment for a module process from the parent
// environment (os.Environ() form), the names the module's signed manifest
// declares, and the socket address. The child gets only the per-OS baseline and
// the declared names, each only when the parent has it set, plus SocketEnvVar.
// Nothing else from the parent is passed.
//
// declared is re-validated here because a bundle's manifest may have been
// filled by a plain YAML decode that skipped ParseModuleMetadata.
func BuildModuleEnv(parent, declared []string, socketPath string) (*ModuleEnv, error) {
	if err := ValidateEnvNames(declared); err != nil {
		return nil, err
	}

	// Index the parent by match key (case-folded on Windows). The last entry
	// wins on duplicates, as in os/exec. Entries with an empty name, such as
	// Windows' hidden "=C:=C:\dir" drive entries, are skipped.
	type kv struct{ name, value string }
	parentVars := make(map[string]kv, len(parent))
	for _, entry := range parent {
		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		name := entry[:eq]
		parentVars[envMatchKey(name)] = kv{name: name, value: entry[eq+1:]}
	}

	out := &ModuleEnv{}
	added := make(map[string]struct{})
	add := func(want string) bool {
		key := envMatchKey(want)
		if _, done := added[key]; done {
			return true
		}
		v, ok := parentVars[key]
		if !ok {
			return false
		}
		added[key] = struct{}{}
		out.Env = append(out.Env, v.name+"="+v.value)
		out.PassedNames = append(out.PassedNames, v.name)
		return true
	}

	for _, name := range baselineEnvNames {
		add(name)
	}
	for _, name := range declared {
		if !add(name) {
			out.MissingDeclared = append(out.MissingDeclared, name)
		}
	}
	out.Env = append(out.Env, SocketEnvVar+"="+socketPath)
	out.PassedNames = append(out.PassedNames, SocketEnvVar)
	sort.Strings(out.PassedNames)
	sort.Strings(out.MissingDeclared)
	return out, nil
}

// BaselineEnvNames returns a copy of the per-OS baseline variable names every
// module process receives when the parent has them set.
func BaselineEnvNames() []string {
	return append([]string(nil), baselineEnvNames...)
}

// BuildModuleEnvFromProcess is BuildModuleEnv with the running process's own
// environment as the parent. The runtimes call this so that neither of them
// handles the full parent environment.
func BuildModuleEnvFromProcess(declared []string, socketPath string) (*ModuleEnv, error) {
	return BuildModuleEnv(os.Environ(), declared, socketPath)
}
