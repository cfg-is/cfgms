// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package storage implements local Git repository operations
// #nosec G304 - Git storage operations require file access for configuration repository management
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"

	cfgit "github.com/cfgis/cfgms/features/config/git"
	"github.com/cfgis/cfgms/pkg/security"
)

// LocalRepositoryStore implements RepositoryStore using go-git
type LocalRepositoryStore struct {
	auth transport.AuthMethod
}

// NewLocalRepositoryStore creates a new local repository store
func NewLocalRepositoryStore(username, password string) *LocalRepositoryStore {
	var auth transport.AuthMethod
	if username != "" && password != "" {
		auth = &http.BasicAuth{
			Username: username,
			Password: password,
		}
	}

	return &LocalRepositoryStore{
		auth: auth,
	}
}

// Clone clones a repository to a local path
func (s *LocalRepositoryStore) Clone(ctx context.Context, cloneURL, localPath string) error {
	_, err := git.PlainCloneContext(ctx, localPath, false, &git.CloneOptions{
		URL:  cloneURL,
		Auth: s.auth,
	})

	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	return nil
}

// Pull pulls latest changes from remote
func (s *LocalRepositoryStore) Pull(ctx context.Context, localPath string) error {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	err = w.PullContext(ctx, &git.PullOptions{
		Auth: s.auth,
	})

	// No changes is not an error
	if err == git.NoErrAlreadyUpToDate {
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to pull changes: %w", err)
	}

	return nil
}

// Push pushes changes to remote
func (s *LocalRepositoryStore) Push(ctx context.Context, localPath string) error {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	err = repo.PushContext(ctx, &git.PushOptions{
		Auth: s.auth,
	})

	// No changes is not an error
	if err == git.NoErrAlreadyUpToDate {
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to push changes: %w", err)
	}

	return nil
}

// ReadFile reads a file from the repository
func (s *LocalRepositoryStore) ReadFile(ctx context.Context, localPath, filePath string) ([]byte, error) {
	fullPath, err := security.ValidateAndCleanPath(localPath, filePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", filePath)
		}
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

// WriteFile writes a file to the repository
func (s *LocalRepositoryStore) WriteFile(ctx context.Context, localPath, filePath string, content []byte) error {
	fullPath, err := security.ValidateAndCleanPath(localPath, filePath)
	if err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Create directory if needed
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(fullPath, content, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Stage the file
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	_, err = w.Add(filePath)
	if err != nil {
		return fmt.Errorf("failed to stage file: %w", err)
	}

	return nil
}

// DeleteFile deletes a file from the repository
func (s *LocalRepositoryStore) DeleteFile(ctx context.Context, localPath, filePath string) error {
	fullPath, err := security.ValidateAndCleanPath(localPath, filePath)
	if err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	// Delete file
	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	// Stage the deletion
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	_, err = w.Remove(filePath)
	if err != nil {
		return fmt.Errorf("failed to stage deletion: %w", err)
	}

	return nil
}

// Commit creates a commit with the staged changes
func (s *LocalRepositoryStore) Commit(ctx context.Context, localPath string, message string, author cfgit.CommitAuthor) (string, error) {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return "", fmt.Errorf("failed to open repository: %w", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree: %w", err)
	}

	// Check if there are changes to commit
	status, err := w.Status()
	if err != nil {
		return "", fmt.Errorf("failed to get status: %w", err)
	}

	if status.IsClean() {
		return "", fmt.Errorf("no changes to commit")
	}

	// Create commit
	hash, err := w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  author.Name,
			Email: author.Email,
			When:  time.Now(),
		},
	})

	if err != nil {
		return "", fmt.Errorf("failed to create commit: %w", err)
	}

	return hash.String(), nil
}

// GetHistory gets the commit history for a file
func (s *LocalRepositoryStore) GetHistory(ctx context.Context, localPath, filePath string, limit int) ([]*cfgit.Commit, error) {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Get commit iterator
	iter, err := repo.Log(&git.LogOptions{
		FileName: &filePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get log: %w", err)
	}
	defer iter.Close()

	var commits []*cfgit.Commit
	count := 0

	err = iter.ForEach(func(c *object.Commit) error {
		if limit > 0 && count >= limit {
			return io.EOF
		}

		// Get parent SHAs
		var parents []string
		for _, p := range c.ParentHashes {
			parents = append(parents, p.String())
		}

		// Get file changes
		var files []cfgit.FileChange
		if len(c.ParentHashes) > 0 {
			parent, err := repo.CommitObject(c.ParentHashes[0])
			if err == nil {
				changes, err := parent.Patch(c)
				if err == nil {
					for _, fp := range changes.FilePatches() {
						from, to := fp.Files()

						var path, oldPath, action string
						if to != nil {
							path = to.Path()
						}
						if from != nil {
							oldPath = from.Path()
						}

						if from == nil {
							action = "added"
						} else if to == nil {
							action = "deleted"
						} else if from.Path() != to.Path() {
							action = "renamed"
						} else {
							action = "modified"
						}

						files = append(files, cfgit.FileChange{
							Path:    path,
							Action:  action,
							OldPath: oldPath,
						})
					}
				}
			}
		}

		commits = append(commits, &cfgit.Commit{
			SHA:       c.Hash.String(),
			Message:   c.Message,
			Timestamp: c.Author.When,
			Parents:   parents,
			Files:     files,
			Author: cfgit.CommitAuthor{
				Name:  c.Author.Name,
				Email: c.Author.Email,
			},
		})

		count++
		return nil
	})

	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to iterate commits: %w", err)
	}

	return commits, nil
}

// GetDiff gets the diff between two commits
func (s *LocalRepositoryStore) GetDiff(ctx context.Context, localPath string, fromRef, toRef string) ([]cfgit.FileChange, error) {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Resolve references to commits
	fromHash, err := repo.ResolveRevision(plumbing.Revision(fromRef))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve from ref: %w", err)
	}

	toHash, err := repo.ResolveRevision(plumbing.Revision(toRef))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve to ref: %w", err)
	}

	fromCommit, err := repo.CommitObject(*fromHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get from commit: %w", err)
	}

	toCommit, err := repo.CommitObject(*toHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get to commit: %w", err)
	}

	// Get the patch between commits
	patch, err := fromCommit.Patch(toCommit)
	if err != nil {
		return nil, fmt.Errorf("failed to get patch: %w", err)
	}

	var changes []cfgit.FileChange
	for _, fp := range patch.FilePatches() {
		from, to := fp.Files()

		var path, oldPath, action string
		if to != nil {
			path = to.Path()
		}
		if from != nil {
			oldPath = from.Path()
		}

		if from == nil {
			action = "added"
		} else if to == nil {
			action = "deleted"
		} else if from.Path() != to.Path() {
			action = "renamed"
		} else {
			action = "modified"
		}

		changes = append(changes, cfgit.FileChange{
			Path:    path,
			Action:  action,
			OldPath: oldPath,
		})
	}

	return changes, nil
}

// CreateBranch creates a new branch
func (s *LocalRepositoryStore) CreateBranch(ctx context.Context, localPath, branchName string) error {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	// Get current HEAD
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	// Create new branch reference
	ref := plumbing.NewBranchReferenceName(branchName)
	err = repo.Storer.SetReference(plumbing.NewHashReference(ref, head.Hash()))
	if err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	return nil
}

// CheckoutBranch checks out a branch
func (s *LocalRepositoryStore) CheckoutBranch(ctx context.Context, localPath, branchName string) error {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Check if branch exists locally
	branchRef := plumbing.NewBranchReferenceName(branchName)
	_, err = repo.Reference(branchRef, false)

	if err != nil {
		// Try to create branch from remote
		remoteRef := plumbing.NewRemoteReferenceName("origin", branchName)
		ref, refErr := repo.Reference(remoteRef, true)
		if refErr != nil {
			return fmt.Errorf("branch not found: %s", branchName)
		}

		// Create local branch from remote
		err = w.Checkout(&git.CheckoutOptions{
			Branch: branchRef,
			Create: true,
			Hash:   ref.Hash(),
		})
	} else {
		// Checkout existing branch
		err = w.Checkout(&git.CheckoutOptions{
			Branch: branchRef,
		})
	}

	if err != nil {
		return fmt.Errorf("failed to checkout branch: %w", err)
	}

	return nil
}

// ListBranches lists all branches
func (s *LocalRepositoryStore) ListBranches(ctx context.Context, localPath string) ([]string, error) {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Get all branches
	iter, err := repo.Branches()
	if err != nil {
		return nil, fmt.Errorf("failed to get branches: %w", err)
	}
	defer iter.Close()

	var branches []string
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		branches = append(branches, ref.Name().Short())
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to iterate branches: %w", err)
	}

	// Also get remote branches
	remotes, err := repo.Remotes()
	if err == nil && len(remotes) > 0 {
		remote := remotes[0]
		refs, err := remote.List(&git.ListOptions{
			Auth: s.auth,
		})
		if err == nil {
			for _, ref := range refs {
				if ref.Name().IsRemote() {
					branchName := ref.Name().Short()
					// Remove "origin/" prefix
					if len(branchName) > 7 && branchName[:7] == "origin/" {
						branchName = branchName[7:]
					}
					// Check if we already have this branch
					found := false
					for _, b := range branches {
						if b == branchName {
							found = true
							break
						}
					}
					if !found && branchName != "HEAD" {
						branches = append(branches, branchName)
					}
				}
			}
		}
	}

	return branches, nil
}

// SetAuth updates the authentication method
func (s *LocalRepositoryStore) SetAuth(username, password string) {
	if username != "" && password != "" {
		s.auth = &http.BasicAuth{
			Username: username,
			Password: password,
		}
	} else {
		s.auth = nil
	}
}

// InitRepository initializes a new repository
func (s *LocalRepositoryStore) InitRepository(ctx context.Context, localPath string, bare bool) error {
	_, err := git.PlainInit(localPath, bare)
	if err != nil {
		return fmt.Errorf("failed to init repository: %w", err)
	}

	return nil
}

// AddRemote adds a remote to the repository
func (s *LocalRepositoryStore) AddRemote(ctx context.Context, localPath, name, url string) error {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: name,
		URLs: []string{url},
	})

	if err != nil {
		return fmt.Errorf("failed to add remote: %w", err)
	}

	return nil
}
