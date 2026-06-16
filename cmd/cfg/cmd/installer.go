// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	installerPlatform    string
	installerArch        string
	installerAPIURL      string
	installerAPIKey      string
	installerTLSCACert   string
	installerTLSInsecure bool

	// publish subcommand flags
	publishKind      string
	publishVersion   string
	publishBinary    string
	publishSignature string
	publishForce     bool
)

var validInstallerPlatforms = map[string]bool{
	"windows": true,
	"darwin":  true,
	"linux":   true,
}

var validInstallerArchs = map[string]bool{
	"amd64": true,
	"arm64": true,
}

var installerCmd = &cobra.Command{
	Use:   "installer",
	Short: "Manage installer artifacts",
	Long:  `Commands for uploading and retrieving installer artifact download URLs.`,
}

var installerUploadCmd = &cobra.Command{
	Use:   "upload <file>",
	Short: "Upload an installer artifact to the controller",
	Long: `Upload a platform-specific installer artifact to the controller.

Streams the file to PUT /api/v1/installer/artifacts/{platform}/{arch} using
the admin bundle mTLS auth. Prints the uploaded size and SHA-256 checksum on success.

Examples:
  cfg installer upload steward-windows-amd64.exe --platform windows --arch amd64
  cfg installer upload steward-darwin-arm64.pkg --platform darwin --arch arm64`,
	Args: cobra.ExactArgs(1),
	RunE: runInstallerUpload,
}

var installerPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish a versioned steward binary to the controller",
	Long: `Publish a publisher-signed steward binary to the controller blob store.

Uploads the binary to POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}
and verifies the Ed25519 publisher signature on the server before storing. Only binaries
signed by the CFGMS publisher identity are accepted.

Examples:
  cfg installer publish --kind steward --version v0.5.12 --platform linux --arch amd64 \
      --binary ./cfgms-steward --signature ./cfgms-steward.sig
  cfg installer publish --kind steward --version v1.0.0 --platform windows --arch amd64 \
      --binary cfgms-steward.exe --signature cfgms-steward.exe.sig --force`,
	RunE: runInstallerPublish,
}

var installerDownloadURLCmd = &cobra.Command{
	Use:   "download-url",
	Short: "Print the download URL for an installer artifact",
	Long: `Print the public download URL for a platform/arch installer artifact.

The URL points to GET /api/v1/installer/download/{platform}/{arch} on the controller.
No authentication is required to download from this URL; operators can use curl or
their RMM tool to retrieve the installer.

Examples:
  cfg installer download-url --platform windows --arch amd64
  cfg installer download-url --platform darwin --arch arm64`,
	RunE: runInstallerDownloadURL,
}

func init() {
	installerUploadCmd.Flags().StringVar(&installerPlatform, "platform", "", "Target platform: windows, darwin, linux (required)")
	installerUploadCmd.Flags().StringVar(&installerArch, "arch", "", "Target architecture: amd64, arm64 (required)")
	installerUploadCmd.Flags().StringVar(&installerAPIURL, "api-url", "", "Controller API URL (env: CFGMS_API_URL)")
	installerUploadCmd.Flags().StringVar(&installerAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	installerUploadCmd.Flags().StringVar(&installerTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	installerUploadCmd.Flags().BoolVar(&installerTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	_ = installerUploadCmd.MarkFlagRequired("platform")
	_ = installerUploadCmd.MarkFlagRequired("arch")

	installerDownloadURLCmd.Flags().StringVar(&installerPlatform, "platform", "", "Target platform: windows, darwin, linux (required)")
	installerDownloadURLCmd.Flags().StringVar(&installerArch, "arch", "", "Target architecture: amd64, arm64 (required)")
	installerDownloadURLCmd.Flags().StringVar(&installerAPIURL, "api-url", "", "Controller API URL (env: CFGMS_API_URL)")
	_ = installerDownloadURLCmd.MarkFlagRequired("platform")
	_ = installerDownloadURLCmd.MarkFlagRequired("arch")

	installerPublishCmd.Flags().StringVar(&publishKind, "kind", "", "Binary kind: steward (required)")
	installerPublishCmd.Flags().StringVar(&publishVersion, "version", "", "Semantic version, e.g. v0.5.12 (required)")
	installerPublishCmd.Flags().StringVar(&installerPlatform, "platform", "", "Target platform: windows, darwin, linux (required)")
	installerPublishCmd.Flags().StringVar(&installerArch, "arch", "", "Target architecture: amd64, arm64 (required)")
	installerPublishCmd.Flags().StringVar(&publishBinary, "binary", "", "Path to the binary file to publish (required)")
	installerPublishCmd.Flags().StringVar(&publishSignature, "signature", "", "Path to the Ed25519 signature file (required)")
	installerPublishCmd.Flags().BoolVar(&publishForce, "force", false, "Overwrite an existing binary with the same version/platform/arch")
	installerPublishCmd.Flags().StringVar(&installerAPIURL, "api-url", "", "Controller API URL (env: CFGMS_API_URL)")
	installerPublishCmd.Flags().StringVar(&installerAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	installerPublishCmd.Flags().StringVar(&installerTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	installerPublishCmd.Flags().BoolVar(&installerTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	_ = installerPublishCmd.MarkFlagRequired("kind")
	_ = installerPublishCmd.MarkFlagRequired("version")
	_ = installerPublishCmd.MarkFlagRequired("platform")
	_ = installerPublishCmd.MarkFlagRequired("arch")
	_ = installerPublishCmd.MarkFlagRequired("binary")
	_ = installerPublishCmd.MarkFlagRequired("signature")

	installerCmd.AddCommand(installerUploadCmd)
	installerCmd.AddCommand(installerDownloadURLCmd)
	installerCmd.AddCommand(installerPublishCmd)
}

func getInstallerClient() (*APIClient, error) {
	apiURL := installerAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	client, err := resolveBundleClient(apiURL)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	apiKey := installerAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	insecure := installerTLSInsecure
	if !insecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		insecure = true
	}

	caCertPath := installerTLSCACert
	if caCertPath == "" {
		caCertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, caCertPath, insecure)
}

func runInstallerUpload(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	if !validInstallerPlatforms[installerPlatform] {
		return fmt.Errorf("unknown platform %q; valid values: windows, darwin, linux", installerPlatform)
	}
	if !validInstallerArchs[installerArch] {
		return fmt.Errorf("unknown arch %q; valid values: amd64, arm64", installerArch)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filePath)
		}
		return fmt.Errorf("cannot access file %s: %w", filePath, err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty: %s", filePath)
	}

	// #nosec G304 - file path provided by user via CLI argument
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()

	client, err := getInstallerClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	if err := client.UploadInstallerArtifact(context.Background(), installerPlatform, installerArch, f); err != nil {
		return err
	}

	return nil
}

func runInstallerDownloadURL(cmd *cobra.Command, args []string) error {
	if !validInstallerPlatforms[installerPlatform] {
		return fmt.Errorf("unknown platform %q; valid values: windows, darwin, linux", installerPlatform)
	}
	if !validInstallerArchs[installerArch] {
		return fmt.Errorf("unknown arch %q; valid values: amd64, arm64", installerArch)
	}

	apiURL := installerAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	apiURL = strings.TrimRight(apiURL, "/")

	fmt.Printf("%s/api/v1/installer/download/%s/%s\n", apiURL, installerPlatform, installerArch)
	return nil
}

func runInstallerPublish(cmd *cobra.Command, args []string) error {
	if publishKind != "steward" {
		return fmt.Errorf("--kind must be %q; got %q", "steward", publishKind)
	}
	if !validInstallerPlatforms[installerPlatform] {
		return fmt.Errorf("unknown platform %q; valid values: windows, darwin, linux", installerPlatform)
	}
	if !validInstallerArchs[installerArch] {
		return fmt.Errorf("unknown arch %q; valid values: amd64, arm64", installerArch)
	}

	binaryInfo, err := os.Stat(publishBinary)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("binary file not found: %s", publishBinary)
		}
		return fmt.Errorf("cannot access binary file %s: %w", publishBinary, err)
	}
	if binaryInfo.Size() == 0 {
		return fmt.Errorf("binary file is empty: %s", publishBinary)
	}

	// #nosec G304 - file path provided by user via CLI flag
	sigBytes, err := os.ReadFile(publishSignature)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("signature file not found: %s", publishSignature)
		}
		return fmt.Errorf("cannot read signature file %s: %w", publishSignature, err)
	}
	if len(sigBytes) == 0 {
		return fmt.Errorf("signature file is empty: %s", publishSignature)
	}

	// #nosec G304 - file path provided by user via CLI flag
	f, err := os.Open(publishBinary)
	if err != nil {
		return fmt.Errorf("failed to open binary file %s: %w", publishBinary, err)
	}
	defer func() { _ = f.Close() }()

	client, err := getInstallerClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	return client.PublishStewardBinary(context.Background(),
		publishVersion, installerPlatform, installerArch, sigBytes, publishForce, f)
}

// stewardBinaryPublishAPIResponse mirrors the server-side stewardBinaryPublishResponse wrapped in APIResponse.
type stewardBinaryPublishAPIResponse struct {
	Data struct {
		Version         string `json:"version"`
		Platform        string `json:"platform"`
		Arch            string `json:"arch"`
		Size            int64  `json:"size"`
		SHA256          string `json:"sha256"`
		PublishedBy     string `json:"published_by"`
		Publisher       string `json:"publisher"`
		SignatureDigest string `json:"signature_digest"`
	} `json:"data"`
}

// PublishStewardBinary streams r to POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}
// with the base64-encoded signature as a query param. Prints the confirmation on success.
func (c *APIClient) PublishStewardBinary(
	ctx context.Context, version, platform, arch string, sigBytes []byte, force bool, r io.Reader,
) error {
	q := url.Values{}
	// Use URL-safe base64 without padding so the signature survives query-param sanitization.
	q.Set("signature", base64.RawURLEncoding.EncodeToString(sigBytes))
	if force {
		q.Set("force", "true")
	}
	path := "/api/v1/installer/steward-binaries/" + version + "/" + platform + "/" + arch + "?" + q.Encode()

	resp, err := c.doRequestWithContentType(ctx, "POST", path, r, "application/octet-stream")
	if err != nil {
		return fmt.Errorf("failed to publish steward binary: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	var apiResp stewardBinaryPublishAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("Published steward binary %s %s/%s (%d bytes, sha256: %s, published_by: %s)\n",
		apiResp.Data.Version,
		apiResp.Data.Platform,
		apiResp.Data.Arch,
		apiResp.Data.Size,
		strings.TrimPrefix(apiResp.Data.SHA256, "sha256:"),
		apiResp.Data.PublishedBy,
	)
	return nil
}

// installerUploadAPIResponse mirrors the server-side installerUploadResponse wrapped in APIResponse.
type installerUploadAPIResponse struct {
	Data struct {
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
		Size     int64  `json:"size"`
		Checksum string `json:"checksum"`
	} `json:"data"`
}

// UploadInstallerArtifact streams r to PUT /api/v1/installer/artifacts/{platform}/{arch}
// and prints the confirmation line to stdout on success.
func (c *APIClient) UploadInstallerArtifact(ctx context.Context, platform, arch string, r io.Reader) error {
	path := "/api/v1/installer/artifacts/" + platform + "/" + arch
	resp, err := c.doRequestWithContentType(ctx, "PUT", path, r, "application/octet-stream")
	if err != nil {
		return fmt.Errorf("failed to upload installer artifact: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	var apiResp installerUploadAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("Uploaded %s/%s installer (%d bytes, sha256: %s)\n",
		apiResp.Data.Platform,
		apiResp.Data.Arch,
		apiResp.Data.Size,
		strings.TrimPrefix(apiResp.Data.Checksum, "sha256:"),
	)
	return nil
}

// InstallerDownloadURL returns the public download URL for the given platform/arch.
func (c *APIClient) InstallerDownloadURL(platform, arch string) string {
	return strings.TrimRight(c.baseURL, "/") + "/api/v1/installer/download/" + platform + "/" + arch
}
