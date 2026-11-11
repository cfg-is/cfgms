// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/version"
)

var (
	installerPlatform    string
	installerArch        string
	installerAPIURL      string
	installerTLSCACert   string
	installerTLSInsecure bool
	installerServerName  string

	// publish subcommand flags
	publishKind      string
	publishVersion   string
	publishBinary    string
	publishSignature string
	publishForce     bool

	// approve subcommand flags
	approveKind    string
	approveVersion string
	approveBinary  string
	approveSHA256  string

	// upload subcommand flags
	uploadSignature string
	uploadVersion   string
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

The controller stores only publisher-signed installers. --signature names a file
holding the base64 signature printed by the signer, and --version is the steward
release version that signature binds. The controller refuses a version older than the
newest it accepted for this tenant, platform and arch (and a different installer at
the same version); to undo a release, re-sign the older code under a higher version:
  go run ./scripts/sign-steward-binary --installer <file> <version> <platform> <arch> > installer.sig

Examples:
  cfg installer upload steward-windows-amd64.exe --platform windows --arch amd64 --version v0.9.41 --signature installer.sig
  cfg installer upload steward-darwin-arm64.pkg --platform darwin --arch arm64 --version v0.9.41 --signature installer.sig`,
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

var installerApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a published steward binary so it can be handed to stewards",
	Long: `Approve a published steward binary.

Sends POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}/approve with
the SHA-256 of the binary you reviewed. The approval is bound to those exact bytes: the
controller recomputes the SHA-256 of the stored binary and refuses a mismatch, and a
binary re-published with different bytes must be approved again. The command needs the
installer:approve:steward permission and a passkey tap.

Give the binary itself with --binary (the SHA-256 of the file is sent), or the SHA-256
you reviewed with --sha256, for example the hash printed by cfg installer publish.

Examples:
  cfg installer approve --kind steward --version v0.5.12 --platform linux --arch amd64 \
      --binary ./cfgms-steward
  cfg installer approve --kind steward --version v0.5.12 --platform linux --arch amd64 \
      --sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`,
	RunE: runInstallerApprove,
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
	installerUploadCmd.Flags().StringVar(&uploadSignature, "signature", "", "Path to the file holding the base64 publisher signature (required)")
	installerUploadCmd.Flags().StringVar(&uploadVersion, "version", "", "Steward release version the signature binds, e.g. v0.9.41 (required)")
	installerUploadCmd.Flags().StringVar(&installerAPIURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	installerUploadCmd.Flags().StringVar(&installerTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	installerUploadCmd.Flags().BoolVar(&installerTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	installerUploadCmd.Flags().StringVar(&installerServerName, "server-name", "", "Override TLS server name for certificate verification")
	_ = installerUploadCmd.MarkFlagRequired("platform")
	_ = installerUploadCmd.MarkFlagRequired("arch")
	_ = installerUploadCmd.MarkFlagRequired("signature")
	_ = installerUploadCmd.MarkFlagRequired("version")

	installerDownloadURLCmd.Flags().StringVar(&installerPlatform, "platform", "", "Target platform: windows, darwin, linux (required)")
	installerDownloadURLCmd.Flags().StringVar(&installerArch, "arch", "", "Target architecture: amd64, arm64 (required)")
	installerDownloadURLCmd.Flags().StringVar(&installerAPIURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	_ = installerDownloadURLCmd.MarkFlagRequired("platform")
	_ = installerDownloadURLCmd.MarkFlagRequired("arch")

	installerPublishCmd.Flags().StringVar(&publishKind, "kind", "", "Binary kind: steward (required)")
	installerPublishCmd.Flags().StringVar(&publishVersion, "version", "", "Semantic version, e.g. v0.5.12 (required)")
	installerPublishCmd.Flags().StringVar(&installerPlatform, "platform", "", "Target platform: windows, darwin, linux (required)")
	installerPublishCmd.Flags().StringVar(&installerArch, "arch", "", "Target architecture: amd64, arm64 (required)")
	installerPublishCmd.Flags().StringVar(&publishBinary, "binary", "", "Path to the binary file to publish (required)")
	installerPublishCmd.Flags().StringVar(&publishSignature, "signature", "", "Path to the Ed25519 signature file (required)")
	installerPublishCmd.Flags().BoolVar(&publishForce, "force", false, "Overwrite an existing binary with the same version/platform/arch")
	installerPublishCmd.Flags().StringVar(&installerAPIURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	installerPublishCmd.Flags().StringVar(&installerTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	installerPublishCmd.Flags().BoolVar(&installerTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	installerPublishCmd.Flags().StringVar(&installerServerName, "server-name", "", "Override TLS server name for certificate verification")
	_ = installerPublishCmd.MarkFlagRequired("kind")
	_ = installerPublishCmd.MarkFlagRequired("version")
	_ = installerPublishCmd.MarkFlagRequired("platform")
	_ = installerPublishCmd.MarkFlagRequired("arch")
	_ = installerPublishCmd.MarkFlagRequired("binary")
	_ = installerPublishCmd.MarkFlagRequired("signature")

	installerApproveCmd.Flags().StringVar(&approveKind, "kind", "", "Binary kind: steward (required)")
	installerApproveCmd.Flags().StringVar(&approveVersion, "version", "", "Semantic version, e.g. v0.5.12 (required)")
	installerApproveCmd.Flags().StringVar(&installerPlatform, "platform", "", "Target platform: windows, darwin, linux (required)")
	installerApproveCmd.Flags().StringVar(&installerArch, "arch", "", "Target architecture: amd64, arm64 (required)")
	installerApproveCmd.Flags().StringVar(&approveBinary, "binary", "", "Path to the binary file reviewed; its SHA-256 is sent (one of --binary or --sha256)")
	installerApproveCmd.Flags().StringVar(&approveSHA256, "sha256", "", "Hex SHA-256 of the binary reviewed (one of --binary or --sha256)")
	installerApproveCmd.Flags().StringVar(&installerAPIURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	installerApproveCmd.Flags().StringVar(&installerTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	installerApproveCmd.Flags().BoolVar(&installerTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	installerApproveCmd.Flags().StringVar(&installerServerName, "server-name", "", "Override TLS server name for certificate verification")
	_ = installerApproveCmd.MarkFlagRequired("kind")
	_ = installerApproveCmd.MarkFlagRequired("version")
	_ = installerApproveCmd.MarkFlagRequired("platform")
	_ = installerApproveCmd.MarkFlagRequired("arch")

	installerCmd.AddCommand(installerUploadCmd)
	installerCmd.AddCommand(installerDownloadURLCmd)
	installerCmd.AddCommand(installerPublishCmd)
	installerCmd.AddCommand(installerApproveCmd)
}

func getInstallerClient() (*APIClient, error) {
	apiURL := installerAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	insecure := installerTLSInsecure
	if !insecure {
		insecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := installerServerName

	return requireSessionOrBundleClient(apiURL, insecure, serverName)
}

// validateInstallerUploadFlags checks the --platform, --arch and --version flags of
// cfg installer upload before any file is read.
func validateInstallerUploadFlags() error {
	if !validInstallerPlatforms[installerPlatform] {
		return fmt.Errorf("unknown platform %q; valid values: windows, darwin, linux", installerPlatform)
	}
	if !validInstallerArchs[installerArch] {
		return fmt.Errorf("unknown arch %q; valid values: amd64, arm64", installerArch)
	}
	if !version.IsSemantic(uploadVersion) || strings.Contains(uploadVersion, "+") {
		return fmt.Errorf("--version %q must be a semantic version such as v0.9.41 without build metadata", uploadVersion)
	}
	return nil
}

// readUploadSignature returns the trimmed base64 publisher signature held in the
// file at path.
func readUploadSignature(path string) (string, error) {
	// #nosec G304 - file path provided by user via CLI flag
	sigText, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("signature file not found: %s", path)
		}
		return "", fmt.Errorf("cannot read signature file %s: %w", path, err)
	}
	signature := strings.TrimSpace(string(sigText))
	if signature == "" {
		return "", fmt.Errorf("signature file is empty: %s", path)
	}
	return signature, nil
}

func runInstallerUpload(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	if err := validateInstallerUploadFlags(); err != nil {
		return err
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

	signature, err := readUploadSignature(uploadSignature)
	if err != nil {
		return err
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

	return client.UploadInstallerArtifact(context.Background(), installerPlatform, installerArch, uploadVersion, signature, f)
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

// runInstallerApprove approves the published steward binary named by the flags,
// sending the SHA-256 of the file or the hash given.
func runInstallerApprove(cmd *cobra.Command, args []string) error {
	if approveKind != "steward" {
		return fmt.Errorf("--kind must be %q; got %q", "steward", approveKind)
	}
	if !validInstallerPlatforms[installerPlatform] {
		return fmt.Errorf("unknown platform %q; valid values: windows, darwin, linux", installerPlatform)
	}
	if !validInstallerArchs[installerArch] {
		return fmt.Errorf("unknown arch %q; valid values: amd64, arm64", installerArch)
	}
	sum, err := approvalSHA256(approveBinary, approveSHA256)
	if err != nil {
		return err
	}
	client, err := getInstallerClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	return client.ApproveStewardBinary(context.Background(), approveVersion, installerPlatform, installerArch, sum)
}

// approvalSHA256 returns the lowercase hex SHA-256 to approve: the hash of the file
// at binaryPath, or the hash given. Exactly one of them must be set.
func approvalSHA256(binaryPath, hash string) (string, error) {
	switch {
	case binaryPath != "" && hash != "":
		return "", fmt.Errorf("give either --binary or --sha256, not both")
	case binaryPath == "" && hash == "":
		return "", fmt.Errorf("one of --binary or --sha256 is required")
	case hash != "":
		return normalizeApprovalHash(hash)
	}
	return fileSHA256(binaryPath)
}

// normalizeApprovalHash lowercases hash, drops an optional "sha256:" prefix and
// requires a 64-character hex SHA-256.
func normalizeApprovalHash(hash string) (string, error) {
	hash = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(hash), "sha256:"))
	if !approvalSHA256Re.MatchString(hash) {
		return "", fmt.Errorf("--sha256 must be a 64-character hex SHA-256")
	}
	return hash, nil
}

// fileSHA256 returns the lowercase hex SHA-256 of the non-empty file at path.
func fileSHA256(path string) (string, error) {
	// #nosec G304 - file path provided by user via CLI flag
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("binary file not found: %s", path)
		}
		return "", fmt.Errorf("cannot open binary file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", fmt.Errorf("cannot read binary file %s: %w", path, err)
	}
	if n == 0 {
		return "", fmt.Errorf("binary file is empty: %s", path)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var approvalSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// stewardBinaryApproveAPIResponse mirrors the server-side stewardBinaryApproveResponse wrapped in APIResponse.
type stewardBinaryApproveAPIResponse struct {
	Data struct {
		Version    string `json:"version"`
		Platform   string `json:"platform"`
		Arch       string `json:"arch"`
		SHA256     string `json:"sha256"`
		ApprovedBy string `json:"approved_by"`
		ApprovedAt string `json:"approved_at"`
		Created    bool   `json:"created"`
	} `json:"data"`
}

// ApproveStewardBinary posts the SHA-256 reviewed to
// POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}/approve and
// prints the approval on success. Approving bytes that are already approved succeeds
// and reports the first approval.
func (c *APIClient) ApproveStewardBinary(ctx context.Context, version, platform, arch, sha string) error {
	body, err := json.Marshal(map[string]string{"sha256": sha})
	if err != nil {
		return fmt.Errorf("failed to encode approval: %w", err)
	}
	path := "/api/v1/installer/steward-binaries/" + url.PathEscape(version) + "/" + url.PathEscape(platform) + "/" + url.PathEscape(arch) + "/approve"
	resp, err := c.doRequest(ctx, "POST", path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to approve steward binary: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}
	var apiResp stewardBinaryApproveAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	verb := "Approved"
	if !apiResp.Data.Created {
		verb = "Already approved"
	}
	fmt.Printf("%s steward binary %s %s/%s (sha256: %s, approved_by: %s, approved_at: %s)\n",
		verb, apiResp.Data.Version, apiResp.Data.Platform, apiResp.Data.Arch,
		apiResp.Data.SHA256, apiResp.Data.ApprovedBy, apiResp.Data.ApprovedAt)
	return nil
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
// with the steward release version and the URL-safe base64 publisher signature as
// the version and signature query params, and prints the confirmation line to stdout
// on success.
func (c *APIClient) UploadInstallerArtifact(ctx context.Context, platform, arch, version, signature string, r io.Reader) error {
	q := url.Values{}
	q.Set("version", version)
	q.Set("signature", signature)
	path := "/api/v1/installer/artifacts/" + platform + "/" + arch + "?" + q.Encode()
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
