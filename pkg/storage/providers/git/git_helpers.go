// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package git implements production-ready git-based storage provider for CFGMS
package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// initializeGitRepo ensures a git repository exists at repoPath, creating and
// configuring it if necessary. This consolidates the identical initialization
// logic shared across GitConfigStore, GitAuditStore, and GitClientTenantStore.
func initializeGitRepo(repoPath string) error {
	// Create directory if it doesn't exist
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		// #nosec G301 - Git repository directories need standard permissions for git operations
		if err := os.MkdirAll(repoPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Initialize git repository if not already one
	gitDir := filepath.Join(repoPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		cmd := exec.Command("git", "init")
		cmd.Dir = repoPath
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to initialize git repository: %w", err)
		}

		// Set up initial config required for commits
		configCmds := [][]string{
			{"git", "config", "user.name", "CFGMS Controller"},
			{"git", "config", "user.email", "controller@cfgms.local"},
			{"git", "config", "init.defaultBranch", "main"},
		}

		for _, cmdArgs := range configCmds {
			// #nosec G204 - Git repository initialization requires controlled git config commands
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			cmd.Dir = repoPath
			_ = cmd.Run() // Ignore errors for initial setup
		}
	}

	return nil
}

// gitCommitFile stages a single file and commits it to the repository at repoPath.
// filePath may be absolute (it is converted to a path relative to repoPath).
func gitCommitFile(repoPath, filePath, message string) error {
	relPath, err := filepath.Rel(repoPath, filePath)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %w", err)
	}

	// Stage the file
	// #nosec G204 - Git storage requires controlled git command execution
	cmd := exec.Command("git", "add", relPath)
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add file to git: %w", err)
	}

	// Commit
	// #nosec G204 - Git storage requires controlled git command execution
	cmd = exec.Command("git", "commit", "-m", message)
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to commit to git: %w", err)
	}

	return nil
}

// gitCommitFiles stages multiple files and commits them in a single commit.
// Each filePath may be absolute (each is converted to a path relative to repoPath).
func gitCommitFiles(repoPath string, filePaths []string, message string) error {
	// Convert absolute paths to relative paths
	relPaths := make([]string, 0, len(filePaths))
	for _, filePath := range filePaths {
		relPath, err := filepath.Rel(repoPath, filePath)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", filePath, err)
		}
		relPaths = append(relPaths, relPath)
	}

	// Stage all files
	args := append([]string{"add"}, relPaths...)
	// #nosec G204 - Git storage requires controlled git command execution with validated args
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add files to git: %w", err)
	}

	// Commit all changes in one commit
	// #nosec G204 - Git storage requires controlled git command execution
	cmd = exec.Command("git", "commit", "-m", message)
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to commit to git: %w", err)
	}

	return nil
}
