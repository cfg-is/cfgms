// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	installerCmd.AddCommand(installerUploadCmd)
	installerCmd.AddCommand(installerDownloadURLCmd)
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
