// Package providers implements Git provider abstractions for different services
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	cfgit "github.com/cfgis/cfgms/features/config/git"
)

// GitHubProvider implements the GitProvider interface for GitHub
type GitHubProvider struct {
	client     *http.Client
	baseURL    string
	token      string
	owner      string
	userAgent  string
}

// NewGitHubProvider creates a new GitHub provider
func NewGitHubProvider(token, owner string) *GitHubProvider {
	return &GitHubProvider{
		client:    &http.Client{Timeout: 30 * time.Second},
		baseURL:   "https://api.github.com",
		token:     token,
		owner:     owner,
		userAgent: "CFGMS-GitBackend/1.0",
	}
}

// CreateRepository creates a new repository on GitHub
func (p *GitHubProvider) CreateRepository(ctx context.Context, config cfgit.RepositoryConfig) (*cfgit.Repository, error) {
	payload := map[string]interface{}{
		"name":        config.Name,
		"description": config.Description,
		"private":     config.Private,
		"auto_init":   true,
	}
	
	if config.InitialBranch != "" && config.InitialBranch != "main" {
		// GitHub uses "main" as default, we'll handle other branches after creation
	}
	
	respBody, err := p.makeRequest(ctx, "POST", "/user/repos", payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}
	
	var repoResp gitHubRepository
	if err := json.Unmarshal(respBody, &repoResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Convert to our Repository type
	repo := &cfgit.Repository{
		ID:            fmt.Sprintf("github:%s/%s", p.owner, repoResp.Name),
		Type:          config.Type,
		Name:          repoResp.Name,
		Owner:         p.owner,
		Provider:      "github",
		CloneURL:      repoResp.CloneURL,
		DefaultBranch: repoResp.DefaultBranch,
		CreatedAt:     repoResp.CreatedAt,
		UpdatedAt:     repoResp.UpdatedAt,
		Metadata: map[string]interface{}{
			"github_id":  repoResp.ID,
			"full_name":  repoResp.FullName,
			"html_url":   repoResp.HTMLURL,
		},
	}
	
	// Set up branch protection for important branches
	if err := p.setupInitialBranchProtection(ctx, repo); err != nil {
		// Log but don't fail - this is not critical
		fmt.Printf("warning: failed to set up branch protection: %v\n", err)
	}
	
	return repo, nil
}

// GetRepository retrieves a repository from GitHub
func (p *GitHubProvider) GetRepository(ctx context.Context, owner, name string) (*cfgit.Repository, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, name)
	respBody, err := p.makeRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	
	var repoResp gitHubRepository
	if err := json.Unmarshal(respBody, &repoResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Determine repository type from name pattern
	repoType := cfgit.RepositoryTypeClient // default
	if strings.Contains(repoResp.Name, "global") {
		repoType = cfgit.RepositoryTypeMSPGlobal
	} else if strings.Contains(repoResp.Name, "shared") {
		repoType = cfgit.RepositoryTypeShared
	}
	
	return &cfgit.Repository{
		ID:            fmt.Sprintf("github:%s/%s", owner, repoResp.Name),
		Type:          repoType,
		Name:          repoResp.Name,
		Owner:         owner,
		Provider:      "github",
		CloneURL:      repoResp.CloneURL,
		DefaultBranch: repoResp.DefaultBranch,
		CreatedAt:     repoResp.CreatedAt,
		UpdatedAt:     repoResp.UpdatedAt,
		Metadata: map[string]interface{}{
			"github_id":  repoResp.ID,
			"full_name":  repoResp.FullName,
			"html_url":   repoResp.HTMLURL,
		},
	}, nil
}

// DeleteRepository deletes a repository from GitHub
func (p *GitHubProvider) DeleteRepository(ctx context.Context, owner, name string) error {
	path := fmt.Sprintf("/repos/%s/%s", owner, name)
	_, err := p.makeRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete repository: %w", err)
	}
	
	return nil
}

// CreateBranch creates a new branch in a repository
func (p *GitHubProvider) CreateBranch(ctx context.Context, owner, repo, branch, fromRef string) error {
	// First, get the SHA of the reference we're branching from
	refPath := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, fromRef)
	respBody, err := p.makeRequest(ctx, "GET", refPath, nil)
	if err != nil {
		return fmt.Errorf("failed to get reference SHA: %w", err)
	}
	
	var refResp gitHubReference
	if err := json.Unmarshal(respBody, &refResp); err != nil {
		return fmt.Errorf("failed to parse reference response: %w", err)
	}
	
	// Create the new branch
	payload := map[string]interface{}{
		"ref": fmt.Sprintf("refs/heads/%s", branch),
		"sha": refResp.Object.SHA,
	}
	
	path := fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo)
	_, err = p.makeRequest(ctx, "POST", path, payload)
	if err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}
	
	return nil
}

// DeleteBranch deletes a branch from a repository
func (p *GitHubProvider) DeleteBranch(ctx context.Context, owner, repo, branch string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, branch)
	_, err := p.makeRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete branch: %w", err)
	}
	
	return nil
}

// GetDefaultBranch gets the default branch of a repository
func (p *GitHubProvider) GetDefaultBranch(ctx context.Context, owner, repo string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	respBody, err := p.makeRequest(ctx, "GET", path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get repository: %w", err)
	}
	
	var repoResp gitHubRepository
	if err := json.Unmarshal(respBody, &repoResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	
	return repoResp.DefaultBranch, nil
}

// CreatePullRequest creates a pull request
func (p *GitHubProvider) CreatePullRequest(ctx context.Context, owner, repo string, config cfgit.PullRequestConfig) (string, error) {
	payload := map[string]interface{}{
		"title": config.Title,
		"body":  config.Description,
		"head":  config.SourceBranch,
		"base":  config.TargetBranch,
	}
	
	path := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)
	respBody, err := p.makeRequest(ctx, "POST", path, payload)
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}
	
	var prResp gitHubPullRequest
	if err := json.Unmarshal(respBody, &prResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Add labels if specified
	if len(config.Labels) > 0 {
		labelsPayload := map[string]interface{}{
			"labels": config.Labels,
		}
		labelsPath := fmt.Sprintf("/repos/%s/%s/issues/%d/labels", owner, repo, prResp.Number)
		_, _ = p.makeRequest(ctx, "POST", labelsPath, labelsPayload) // Non-critical
	}
	
	// Request reviewers if specified
	if len(config.Reviewers) > 0 {
		reviewersPayload := map[string]interface{}{
			"reviewers": config.Reviewers,
		}
		reviewersPath := fmt.Sprintf("/repos/%s/%s/pulls/%d/requested_reviewers", owner, repo, prResp.Number)
		_, _ = p.makeRequest(ctx, "POST", reviewersPath, reviewersPayload) // Non-critical
	}
	
	return fmt.Sprintf("%d", prResp.Number), nil
}

// MergePullRequest merges a pull request
func (p *GitHubProvider) MergePullRequest(ctx context.Context, owner, repo, prID string) error {
	payload := map[string]interface{}{
		"commit_title":   fmt.Sprintf("Merge pull request #%s", prID),
		"merge_method":   "squash", // Use squash merge for cleaner history
	}
	
	path := fmt.Sprintf("/repos/%s/%s/pulls/%s/merge", owner, repo, prID)
	_, err := p.makeRequest(ctx, "PUT", path, payload)
	if err != nil {
		return fmt.Errorf("failed to merge pull request: %w", err)
	}
	
	return nil
}

// CreateWebhook creates a webhook for a repository
func (p *GitHubProvider) CreateWebhook(ctx context.Context, owner, repo string, config cfgit.WebhookConfig) (string, error) {
	payload := map[string]interface{}{
		"name":   "web",
		"active": config.Active,
		"events": config.Events,
		"config": map[string]interface{}{
			"url":          config.URL,
			"content_type": "json",
			"secret":       config.Secret,
		},
	}
	
	path := fmt.Sprintf("/repos/%s/%s/hooks", owner, repo)
	respBody, err := p.makeRequest(ctx, "POST", path, payload)
	if err != nil {
		return "", fmt.Errorf("failed to create webhook: %w", err)
	}
	
	var hookResp gitHubWebhook
	if err := json.Unmarshal(respBody, &hookResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	
	return fmt.Sprintf("%d", hookResp.ID), nil
}

// DeleteWebhook deletes a webhook from a repository
func (p *GitHubProvider) DeleteWebhook(ctx context.Context, owner, repo, webhookID string) error {
	path := fmt.Sprintf("/repos/%s/%s/hooks/%s", owner, repo, webhookID)
	_, err := p.makeRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}
	
	return nil
}

// SetBranchProtection sets branch protection rules
func (p *GitHubProvider) SetBranchProtection(ctx context.Context, owner, repo string, rule cfgit.BranchProtectionRule) error {
	payload := map[string]interface{}{
		"required_status_checks": map[string]interface{}{
			"strict":   rule.RequireUpToDate,
			"contexts": rule.RequiredChecks,
		},
		"enforce_admins": true,
		"required_pull_request_reviews": map[string]interface{}{
			"required_approving_review_count": rule.RequiredReviewers,
			"dismiss_stale_reviews":           rule.DismissStaleReviews,
		},
		"restrictions": nil, // Open to all for now
	}
	
	if rule.RestrictPushAccess {
		payload["restrictions"] = map[string]interface{}{
			"users": rule.PushAccessUsers,
			"teams": rule.PushAccessTeams,
		}
	}
	
	path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, rule.Pattern)
	_, err := p.makeRequest(ctx, "PUT", path, payload)
	if err != nil {
		return fmt.Errorf("failed to set branch protection: %w", err)
	}
	
	return nil
}

// RemoveBranchProtection removes branch protection
func (p *GitHubProvider) RemoveBranchProtection(ctx context.Context, owner, repo, branch string) error {
	path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, branch)
	_, err := p.makeRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("failed to remove branch protection: %w", err)
	}
	
	return nil
}

// Helper methods

func (p *GitHubProvider) makeRequest(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	url := p.baseURL + path
	
	var body *bytes.Buffer
	if payload != nil {
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
		body = bytes.NewBuffer(jsonPayload)
	}
	
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, body)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Authorization", "token "+p.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", p.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
		}
	}()
	
	respBody := &bytes.Buffer{}
	if _, err := respBody.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	if resp.StatusCode >= 400 {
		var errorResp gitHubError
		if err := json.Unmarshal(respBody.Bytes(), &errorResp); err == nil {
			return nil, fmt.Errorf("GitHub API error: %s", errorResp.Message)
		}
		return nil, fmt.Errorf("GitHub API error: status %d", resp.StatusCode)
	}
	
	return respBody.Bytes(), nil
}

func (p *GitHubProvider) setupInitialBranchProtection(ctx context.Context, repo *cfgit.Repository) error {
	// Set up basic protection for main branch
	rule := cfgit.BranchProtectionRule{
		Pattern:           repo.DefaultBranch,
		RequireReview:     true,
		RequiredReviewers: 1,
		RequireUpToDate:   true,
		RequiredChecks:    []string{},
	}
	
	// For client repositories, be more restrictive
	if repo.Type == cfgit.RepositoryTypeClient {
		rule.RequiredReviewers = 2
		rule.DismissStaleReviews = true
	}
	
	parts := strings.Split(strings.TrimPrefix(repo.ID, "github:"), "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid repository ID format")
	}
	
	return p.SetBranchProtection(ctx, parts[0], parts[1], rule)
}

// GitHub API response types

type gitHubRepository struct {
	ID            int       `json:"id"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	HTMLURL       string    `json:"html_url"`
	CloneURL      string    `json:"clone_url"`
	DefaultBranch string    `json:"default_branch"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type gitHubReference struct {
	Ref    string `json:"ref"`
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
	} `json:"object"`
}

type gitHubPullRequest struct {
	ID     int    `json:"id"`
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
}

type gitHubWebhook struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type gitHubError struct {
	Message          string `json:"message"`
	DocumentationURL string `json:"documentation_url"`
}