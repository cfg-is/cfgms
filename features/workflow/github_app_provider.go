// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// Secrets provider key names for GitHub App credentials.
const (
	secretKeyGitHubAppID          = "github_app_id"
	secretKeyGitHubInstallationID = "github_app_installation_id"
	secretKeyGitHubPrivateKeyPEM  = "github_app_private_key_pem"
)

const githubAPIBase = "https://api.github.com"

// GitHubAppProvider implements APIProvider using a GitHub App.
//
// It supports a single service "runners" with operation "registration-token".
// Required parameters in APIConfig.Parameters: "owner" (org/user) and "repo".
//
// Credentials are loaded from the secrets provider under the keys
// github_app_id, github_app_installation_id, github_app_private_key_pem.
// These keys must be populated by the operator before the provider can execute.
// See docs/development/ci-runner-github-app-setup.md for the setup runbook.
//
// The three-step exchange is: App JWT (RS256) → installation access token → registration token.
// The registration token is single-use and never cached.
type GitHubAppProvider struct {
	secrets    secretsif.SecretStore
	logger     logging.Logger
	httpClient *http.Client
	baseURL    string // GitHub API root; overridable in tests, defaults to githubAPIBase
}

// NewGitHubAppProvider creates a GitHubAppProvider backed by the given secrets store.
// Pass nil for httpClient to use a default client with a 30 s timeout.
func NewGitHubAppProvider(secrets secretsif.SecretStore, logger logging.Logger, httpClient *http.Client) *GitHubAppProvider {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &GitHubAppProvider{
		secrets:    secrets,
		logger:     logger,
		httpClient: httpClient,
		baseURL:    githubAPIBase,
	}
}

func (p *GitHubAppProvider) GetName() string { return "github" }

func (p *GitHubAppProvider) GetServices() []string { return []string{"runners"} }

func (p *GitHubAppProvider) GetOperations(service string) []string {
	if service == "runners" {
		return []string{"registration-token"}
	}
	return nil
}

func (p *GitHubAppProvider) GetAuthenticationMethods() []AuthType {
	return []AuthType{AuthTypeCustom}
}

// ValidateConfig verifies the service, operation, and required parameters are present.
func (p *GitHubAppProvider) ValidateConfig(config *APIConfig) error {
	if config.Service == "" {
		return fmt.Errorf("service is required")
	}
	if config.Service != "runners" {
		return fmt.Errorf("unsupported service: %s", config.Service)
	}
	if config.Operation != "registration-token" {
		return fmt.Errorf("unsupported operation %q for service %q", config.Operation, config.Service)
	}
	if config.Parameters == nil {
		return fmt.Errorf("parameters are required: owner, repo")
	}
	if _, ok := config.Parameters["owner"]; !ok {
		return fmt.Errorf("parameter 'owner' is required")
	}
	if _, ok := config.Parameters["repo"]; !ok {
		return fmt.Errorf("parameter 'repo' is required")
	}
	return nil
}

// RefreshToken is a no-op: App JWTs are minted fresh per operation.
func (p *GitHubAppProvider) RefreshToken(_ context.Context, _ *APIConfig) error { return nil }

// ExecuteOperation mints a GitHub Actions runner registration token.
//
// Steps:
//  1. Load app_id, installation_id, private_key_pem from the secrets store.
//  2. Sign a short-lived App JWT (RS256, exp ≤ 10 min).
//  3. POST /app/installations/{id}/access_tokens to get an installation access token.
//  4. POST /repos/{owner}/{repo}/actions/runners/registration-token.
//
// Returns APIResponse.Data["token"] (the registration token) and ["expires_at"].
func (p *GitHubAppProvider) ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error) {
	if p.secrets == nil {
		return nil, fmt.Errorf("github provider: secrets store not configured; initialise with NewGitHubAppProvider")
	}

	logger := p.logger
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	client := p.httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	baseURL := p.baseURL
	if baseURL == "" {
		baseURL = githubAPIBase
	}

	appIDSecret, err := p.secrets.GetSecret(ctx, secretKeyGitHubAppID)
	if err != nil {
		return nil, fmt.Errorf("github provider: loading %s: %w", secretKeyGitHubAppID, err)
	}

	installIDSecret, err := p.secrets.GetSecret(ctx, secretKeyGitHubInstallationID)
	if err != nil {
		return nil, fmt.Errorf("github provider: loading %s: %w", secretKeyGitHubInstallationID, err)
	}

	pemSecret, err := p.secrets.GetSecret(ctx, secretKeyGitHubPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("github provider: loading %s: %w", secretKeyGitHubPrivateKeyPEM, err)
	}

	appID := appIDSecret.Value
	installationID := installIDSecret.Value
	privateKeyPEM := pemSecret.Value

	appJWT, err := generateGitHubAppJWT(appID, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("github provider: generating App JWT: %w", err)
	}

	logger.Info("github app JWT generated",
		"app_id", logging.SanitizeLogValue(appID),
		"installation_id", logging.SanitizeLogValue(installationID))

	installToken, err := mintInstallationToken(ctx, client, baseURL, installationID, appJWT)
	if err != nil {
		return nil, fmt.Errorf("github provider: minting installation token: %w", err)
	}

	owner := fmt.Sprintf("%v", config.Parameters["owner"])
	repo := fmt.Sprintf("%v", config.Parameters["repo"])

	regToken, err := mintRunnerRegistrationToken(ctx, client, baseURL, owner, repo, installToken)
	if err != nil {
		return nil, fmt.Errorf("github provider: minting registration token: %w", err)
	}

	logger.Info("github runner registration token minted",
		"owner", logging.SanitizeLogValue(owner),
		"repo", logging.SanitizeLogValue(repo))

	return &APIResponse{
		Success:    true,
		StatusCode: 201,
		Data: map[string]interface{}{
			"token":      regToken.Token,
			"expires_at": regToken.ExpiresAt,
		},
	}, nil
}

// generateGitHubAppJWT signs a short-lived JWT identifying this GitHub App.
//
// The JWT uses RS256 with the app's RSA private key (PEM-encoded PKCS#1).
// iss is set to appID; exp is 10 minutes from now; iat is 60 s in the past
// to accommodate clock skew as recommended by GitHub.
func generateGitHubAppJWT(appID, privateKeyPEM string) (string, error) {
	pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		return "", fmt.Errorf("parsing RSA private key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(pk)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}
	return signed, nil
}

type installationTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// mintInstallationToken exchanges a GitHub App JWT for an installation access token.
// baseURL is the GitHub API root (e.g. "https://api.github.com"); pass a stub server
// URL in tests.
func mintInstallationToken(ctx context.Context, client *http.Client, baseURL, installationID, appJWT string) (string, error) {
	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading installation token response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("installation token request: HTTP %d: %s", resp.StatusCode, body)
	}

	var tok installationTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decoding installation token response: %w", err)
	}
	if tok.Token == "" {
		return "", fmt.Errorf("installation token response missing 'token' field")
	}
	return tok.Token, nil
}

type registrationTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// mintRunnerRegistrationToken mints a single-use runner registration token for the
// given repo. Registration tokens are not cached; callers must mint fresh per use.
// baseURL is the GitHub API root (e.g. "https://api.github.com"); pass a stub server
// URL in tests.
func mintRunnerRegistrationToken(ctx context.Context, client *http.Client, baseURL, owner, repo, installToken string) (*registrationTokenResponse, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/runners/registration-token", baseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+installToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading registration token response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration token request: HTTP %d: %s", resp.StatusCode, body)
	}

	var tok registrationTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("decoding registration token response: %w", err)
	}
	if tok.Token == "" {
		return nil, fmt.Errorf("registration token response missing 'token' field")
	}
	return &tok, nil
}
