// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package modules

import (
	"fmt"
	"sort"
	"strings"
)

// ModuleDependency represents a dependency requirement for a module
type ModuleDependency struct {
	// Name is the name of the required module
	Name string `yaml:"name" json:"name"`

	// Version constraint using semantic versioning
	// Examples: ">=1.0.0", "~1.2.0", "^2.0.0", "1.2.3"
	Version string `yaml:"version" json:"version"`

	// Optional indicates if this dependency is optional
	Optional bool `yaml:"optional,omitempty" json:"optional,omitempty"`

	// Reason provides documentation for why this dependency is needed
	Reason string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// String returns a human-readable representation of the dependency
func (d ModuleDependency) String() string {
	optional := ""
	if d.Optional {
		optional = " (optional)"
	}
	return fmt.Sprintf("%s %s%s", d.Name, d.Version, optional)
}

// DependencyGraph represents the dependency relationships between modules
type DependencyGraph struct {
	// modules maps module names to their metadata
	modules map[string]*ModuleMetadata

	// adjacencyList represents the directed graph of dependencies
	// Key: module name, Value: list of modules this module depends on
	adjacencyList map[string][]string

	// reverseList represents the reverse dependency graph
	// Key: module name, Value: list of modules that depend on this module
	reverseList map[string][]string
}

// NewDependencyGraph creates a new empty dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		modules:       make(map[string]*ModuleMetadata),
		adjacencyList: make(map[string][]string),
		reverseList:   make(map[string][]string),
	}
}

// AddModule adds a module and its dependencies to the graph
func (g *DependencyGraph) AddModule(metadata *ModuleMetadata) error {
	if metadata == nil {
		return fmt.Errorf("module metadata cannot be nil")
	}

	if metadata.Name == "" {
		return fmt.Errorf("module name cannot be empty")
	}

	// Add the module to our registry
	g.modules[metadata.Name] = metadata

	// Initialize adjacency lists if they don't exist
	if g.adjacencyList[metadata.Name] == nil {
		g.adjacencyList[metadata.Name] = make([]string, 0)
	}
	if g.reverseList[metadata.Name] == nil {
		g.reverseList[metadata.Name] = make([]string, 0)
	}

	// Add dependencies to the graph
	for _, dep := range metadata.ModuleDependencies {
		// Add dependency to adjacency list
		g.adjacencyList[metadata.Name] = append(g.adjacencyList[metadata.Name], dep.Name)

		// Initialize reverse list for dependency if it doesn't exist
		if g.reverseList[dep.Name] == nil {
			g.reverseList[dep.Name] = make([]string, 0)
		}

		// Add reverse dependency
		g.reverseList[dep.Name] = append(g.reverseList[dep.Name], metadata.Name)
	}

	return nil
}

// GetModule returns the metadata for a module
func (g *DependencyGraph) GetModule(name string) (*ModuleMetadata, bool) {
	metadata, exists := g.modules[name]
	return metadata, exists
}

// GetDependencies returns the direct dependencies of a module
func (g *DependencyGraph) GetDependencies(moduleName string) []string {
	deps, exists := g.adjacencyList[moduleName]
	if !exists {
		return []string{}
	}

	// Return a copy to prevent external modification
	result := make([]string, len(deps))
	copy(result, deps)
	return result
}

// GetDependents returns the modules that depend on the given module
func (g *DependencyGraph) GetDependents(moduleName string) []string {
	dependents, exists := g.reverseList[moduleName]
	if !exists {
		return []string{}
	}

	// Return a copy to prevent external modification
	result := make([]string, len(dependents))
	copy(result, dependents)
	return result
}

// HasCycles detects if there are circular dependencies in the graph
func (g *DependencyGraph) HasCycles() (bool, []string) {
	// Use DFS with coloring to detect cycles
	// White = 0 (unvisited), Gray = 1 (visiting), Black = 2 (visited)
	color := make(map[string]int)
	var cycle []string
	var path []string

	// Initialize all nodes as white
	for module := range g.modules {
		color[module] = 0
	}

	// Check each unvisited node
	for module := range g.modules {
		if color[module] == 0 {
			if hasCycleDFS(g, module, color, &path, &cycle) {
				return true, cycle
			}
		}
	}

	return false, nil
}

// hasCycleDFS performs DFS to detect cycles
func hasCycleDFS(g *DependencyGraph, node string, color map[string]int, path *[]string, cycle *[]string) bool {
	color[node] = 1 // Mark as gray (visiting)
	*path = append(*path, node)

	// Visit all dependencies
	for _, dep := range g.adjacencyList[node] {
		if color[dep] == 1 { // Back edge found - cycle detected
			// Extract the cycle from the path
			cycleStart := -1
			for i, n := range *path {
				if n == dep {
					cycleStart = i
					break
				}
			}
			if cycleStart >= 0 {
				*cycle = append(*cycle, (*path)[cycleStart:]...)
				*cycle = append(*cycle, dep) // Close the cycle
			}
			return true
		}

		if color[dep] == 0 && hasCycleDFS(g, dep, color, path, cycle) {
			return true
		}
	}

	color[node] = 2                // Mark as black (visited)
	*path = (*path)[:len(*path)-1] // Remove from path
	return false
}

// TopologicalSort returns the modules in dependency order
// Modules with no dependencies come first, modules that depend on others come later
func (g *DependencyGraph) TopologicalSort() ([]string, error) {
	// Check for cycles first
	if hasCycles, cycle := g.HasCycles(); hasCycles {
		return nil, fmt.Errorf("circular dependency detected: %s", strings.Join(cycle, " -> "))
	}

	// Kahn's algorithm for topological sorting
	// Calculate in-degrees
	inDegree := make(map[string]int)
	for module := range g.modules {
		inDegree[module] = 0
	}

	// Count incoming edges for each module
	// In our adjacency list: adjacencyList[A] = [B, C] means A depends on B and C
	// For topological sort, we want to process dependencies first
	// So A has incoming edges (A depends on B and C)
	for module, deps := range g.adjacencyList {
		if len(deps) > 0 {
			inDegree[module] = len(deps)
		}
	}

	// Find all nodes with no incoming edges
	var queue []string
	for module, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, module)
		}
	}

	// Sort queue for deterministic output
	sort.Strings(queue)

	var result []string

	for len(queue) > 0 {
		// Remove node with no incoming edges
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		// For each module that depends on current node (i.e., current is a dependency of these modules)
		for module, deps := range g.adjacencyList {
			for _, dep := range deps {
				if dep == current {
					inDegree[module]--
					if inDegree[module] == 0 {
						// Insert in sorted position for deterministic output
						insertPos := 0
						for insertPos < len(queue) && queue[insertPos] < module {
							insertPos++
						}
						queue = append(queue[:insertPos], append([]string{module}, queue[insertPos:]...)...)
					}
				}
			}
		}
	}

	return result, nil
}

// ValidateAllDependencies validates that all dependencies are satisfied
func (g *DependencyGraph) ValidateAllDependencies() []DependencyError {
	var errors []DependencyError

	for moduleName, metadata := range g.modules {
		for _, dep := range metadata.ModuleDependencies {
			if err := g.ValidateDependency(moduleName, dep); err != nil {
				errors = append(errors, *err)
			}
		}
	}

	return errors
}

// ValidateDependency validates a single dependency
func (g *DependencyGraph) ValidateDependency(moduleName string, dep ModuleDependency) *DependencyError {
	// Check if the dependency exists
	depMetadata, exists := g.GetModule(dep.Name)
	if !exists {
		if dep.Optional {
			return nil // Optional dependency not found is OK
		}
		return &DependencyError{
			Type:       DependencyErrorMissing,
			Module:     moduleName,
			Dependency: dep.Name,
			Message:    fmt.Sprintf("required dependency '%s' not found", dep.Name),
		}
	}

	// Validate version constraint
	if dep.Version != "" {
		compatible, err := IsVersionCompatible(depMetadata.Version, dep.Version)
		if err != nil {
			return &DependencyError{
				Type:       DependencyErrorInvalidVersion,
				Module:     moduleName,
				Dependency: dep.Name,
				Message:    fmt.Sprintf("invalid version constraint '%s': %v", dep.Version, err),
			}
		}

		if !compatible {
			return &DependencyError{
				Type:       DependencyErrorVersionMismatch,
				Module:     moduleName,
				Dependency: dep.Name,
				Message:    fmt.Sprintf("version mismatch: required '%s', found '%s'", dep.Version, depMetadata.Version),
			}
		}
	}

	return nil
}

// DependencyError represents a dependency validation error
type DependencyError struct {
	Type       DependencyErrorType `json:"type"`
	Module     string              `json:"module"`
	Dependency string              `json:"dependency"`
	Message    string              `json:"message"`
}

// Error implements the error interface
func (e DependencyError) Error() string {
	return fmt.Sprintf("dependency error in module '%s': %s", e.Module, e.Message)
}

// DependencyErrorType represents the type of dependency error
type DependencyErrorType int

const (
	DependencyErrorMissing DependencyErrorType = iota
	DependencyErrorVersionMismatch
	DependencyErrorInvalidVersion
	DependencyErrorCircular
)

// String returns a human-readable representation of the error type
func (t DependencyErrorType) String() string {
	switch t {
	case DependencyErrorMissing:
		return "missing"
	case DependencyErrorVersionMismatch:
		return "version_mismatch"
	case DependencyErrorInvalidVersion:
		return "invalid_version"
	case DependencyErrorCircular:
		return "circular"
	default:
		return "unknown"
	}
}
