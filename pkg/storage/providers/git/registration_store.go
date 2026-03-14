// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// GitRegistrationTokenStore implements RegistrationTokenStore using git for persistence
// This stores registration tokens in JSON files within a git repository
type GitRegistrationTokenStore struct {
	repoPath  string
	remoteURL string
}

// NewGitRegistrationTokenStore creates a new git-based registration token store
func NewGitRegistrationTokenStore(repoPath, remoteURL string) (*GitRegistrationTokenStore, error) {
	store := &GitRegistrationTokenStore{
		repoPath:  repoPath,
		remoteURL: remoteURL,
	}

	// Initialize git repository if it doesn't exist
	if err := store.initializeRepo(); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}

	return store, nil
}

// initializeRepo ensures the git repository and registration directory exist
func (s *GitRegistrationTokenStore) initializeRepo() error {
	// Check if directory exists
	if _, err := os.Stat(s.repoPath); os.IsNotExist(err) {
		// Create directory
		if err := os.MkdirAll(s.repoPath, 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Create subdirectory for registration tokens
	tokensDir := filepath.Join(s.repoPath, "registration_tokens")
	if err := os.MkdirAll(tokensDir, 0750); err != nil {
		return fmt.Errorf("failed to create registration_tokens directory: %w", err)
	}

	return nil
}

// safeReadFile safely reads a file with path validation to prevent directory traversal
func (s *GitRegistrationTokenStore) safeReadFile(targetPath string) ([]byte, error) {
	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(targetPath)

	// Ensure the path is within the repo directory
	if !strings.HasPrefix(cleanPath, filepath.Clean(s.repoPath)) {
		return nil, fmt.Errorf("path outside repository: %s", targetPath)
	}

	return os.ReadFile(cleanPath)
}

// safeWriteFile safely writes a file with path validation to prevent directory traversal
func (s *GitRegistrationTokenStore) safeWriteFile(targetPath string, data []byte, perm os.FileMode) error {
	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(targetPath)

	// Ensure the path is within the repo directory
	if !strings.HasPrefix(cleanPath, filepath.Clean(s.repoPath)) {
		return fmt.Errorf("path outside repository: %s", targetPath)
	}

	return os.WriteFile(cleanPath, data, perm)
}

// tokenFilename generates a safe filename for a token
// Token format is a bare base32 string - we use the full token as filename
// but sanitize it to prevent path traversal
func (s *GitRegistrationTokenStore) tokenFilename(tokenStr string) string {
	// Replace any potentially dangerous characters
	safe := strings.ReplaceAll(tokenStr, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	return safe + ".json"
}

// Initialize implements RegistrationTokenStore.Initialize
func (s *GitRegistrationTokenStore) Initialize(ctx context.Context) error {
	return s.initializeRepo()
}

// Close implements RegistrationTokenStore.Close
func (s *GitRegistrationTokenStore) Close() error {
	return nil
}

// SaveToken implements RegistrationTokenStore.SaveToken
// Uses upsert semantics to handle both new tokens and updates to existing tokens
func (s *GitRegistrationTokenStore) SaveToken(ctx context.Context, token *interfaces.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	// Use upsert semantics: create if doesn't exist, update if exists
	// This ensures single-use token enforcement works correctly
	filePath := filepath.Join(s.repoPath, "registration_tokens", s.tokenFilename(token.Token))

	// Marshal token data
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Write token file (overwrites if exists)
	if err := s.safeWriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// GetToken implements RegistrationTokenStore.GetToken
func (s *GitRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*interfaces.RegistrationTokenData, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("token string cannot be empty")
	}

	filePath := filepath.Join(s.repoPath, "registration_tokens", s.tokenFilename(tokenStr))
	data, err := s.safeReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token interfaces.RegistrationTokenData
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return &token, nil
}

// UpdateToken implements RegistrationTokenStore.UpdateToken
func (s *GitRegistrationTokenStore) UpdateToken(ctx context.Context, token *interfaces.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	// Check if token exists
	filePath := filepath.Join(s.repoPath, "registration_tokens", s.tokenFilename(token.Token))
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("token not found")
	}

	// Marshal token data
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Write token file
	if err := s.safeWriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// DeleteToken implements RegistrationTokenStore.DeleteToken
func (s *GitRegistrationTokenStore) DeleteToken(ctx context.Context, tokenStr string) error {
	if tokenStr == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	filePath := filepath.Join(s.repoPath, "registration_tokens", s.tokenFilename(tokenStr))
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("token not found")
		}
		return fmt.Errorf("failed to delete token file: %w", err)
	}

	return nil
}

// ListTokens implements RegistrationTokenStore.ListTokens
func (s *GitRegistrationTokenStore) ListTokens(ctx context.Context, filter *interfaces.RegistrationTokenFilter) ([]*interfaces.RegistrationTokenData, error) {
	tokensDir := filepath.Join(s.repoPath, "registration_tokens")
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*interfaces.RegistrationTokenData{}, nil
		}
		return nil, fmt.Errorf("failed to read registration_tokens directory: %w", err)
	}

	var tokens []*interfaces.RegistrationTokenData
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(tokensDir, entry.Name())
		data, err := s.safeReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}

		var token interfaces.RegistrationTokenData
		if err := json.Unmarshal(data, &token); err != nil {
			continue // Skip files that can't be parsed
		}

		// Apply filters if provided
		if filter != nil {
			if filter.TenantID != "" && token.TenantID != filter.TenantID {
				continue
			}
			if filter.Group != "" && token.Group != filter.Group {
				continue
			}
			if filter.Revoked != nil && token.Revoked != *filter.Revoked {
				continue
			}
			if filter.SingleUse != nil && token.SingleUse != *filter.SingleUse {
				continue
			}
			if filter.Used != nil {
				isUsed := token.UsedAt != nil
				if isUsed != *filter.Used {
					continue
				}
			}
		}

		tokens = append(tokens, &token)
	}

	return tokens, nil
}
