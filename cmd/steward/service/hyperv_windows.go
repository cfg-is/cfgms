// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/steward" // register steward secrets provider
)

// hyperVCertParams holds the parameters for the WinRM self-signed TLS cert.
// Used by buildHyperVCertParams and inspected by tests to verify the parameters
// without executing cert generation (which requires elevation).
type hyperVCertParams struct {
	// DnsNames are the Subject Alternative Names for the cert.
	// Must include "localhost", "127.0.0.1", and the machine FQDN.
	DnsNames []string
	// NotAfter is the cert expiry. Set to 5 years to avoid the ~1yr default
	// expiry that silently breaks WinRM connections (F10).
	NotAfter time.Time
}

// buildHyperVCertParams returns the certificate parameters for the WinRM TLS cert.
// fqdn is the machine hostname from os.Hostname(). The 5-year lifetime avoids the
// ~1yr default expiry that causes silent WinRM failures.
func buildHyperVCertParams(fqdn string) hyperVCertParams {
	return hyperVCertParams{
		DnsNames: []string{"localhost", "127.0.0.1", fqdn},
		NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
	}
}

// generateHyperVCert generates a self-signed TLS cert in cert:\LocalMachine\My
// with SAN = {localhost, 127.0.0.1, fqdn} and a 5-year lifetime.
// fqdn is passed as $args[0] — never interpolated into the script block string.
// Returns the certificate thumbprint.
func generateHyperVCert(ps psRunner, fqdn string) (string, error) {
	script := `$fqdn = $args[0]
$cert = New-SelfSignedCertificate -DnsName @('localhost','127.0.0.1',$fqdn) -CertStoreLocation cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(5)
$cert.Thumbprint`
	return ps.RunPS(script, []string{fqdn}, "")
}

// setupWinRMListener deletes any existing WinRM HTTPS listener and creates a
// loopback-bound listener at 127.0.0.1:5986 (not 0.0.0.0).
// thumbprint is passed as $args[0] — never interpolated into the script block.
// Idempotent: delete-then-create.
//
// Uses `winrm create` (not `winrm set`). `winrm set` only modifies an existing
// listener; on a fresh host it silently no-ops, leaving 5986 unbound — the
// install reports "Step 3/8 Configuring WinRM HTTPS listener" success but
// nothing is actually listening, so every later WinRM call fails with
// "actively refused".
func setupWinRMListener(ps psRunner, thumbprint string) error {
	// Delete any existing HTTPS listener; non-fatal if it does not exist.
	// We try both the wildcard (Address=*) and the loopback-pinned form to
	// cover both an Enable-PSRemoting-created listener and a previous run of
	// this same install.
	_, _ = ps.RunPS(
		`& winrm delete 'winrm/config/Listener?Address=*+Transport=HTTPS' 2>$null; & winrm delete 'winrm/config/Listener?Address=IP:127.0.0.1+Transport=HTTPS' 2>$null; $true`,
		nil, "")

	// Address=IP:127.0.0.1 binds only to loopback — NOT Address=* (0.0.0.0).
	// Thumbprint is $args[0], assembled via string concat in PS to avoid interpolation.
	// Hostname='127.0.0.1' aligns the listener record with the address clients
	// actually dial (`winrm_host: 127.0.0.1` in steward config). Using
	// `localhost` here would resolve to ::1 on IPv6-first Windows and the
	// IPv4-bound listener would refuse the connection.
	script := `$thumb = $args[0]
$config = "@{Hostname='127.0.0.1';CertificateThumbprint='" + $thumb + "'}"
& winrm create 'winrm/config/Listener?Address=IP:127.0.0.1+Transport=HTTPS' $config`
	_, err := ps.RunPS(script, []string{thumbprint}, "")
	return err
}

// setupHyperVFirewall creates loopback-only allow and deny rules for WinRM port
// 5986, then removes any broader rules created by Enable-PSRemoting. Idempotent.
func setupHyperVFirewall(ps psRunner) error {
	script := `# Remove Enable-PSRemoting WinRM rules that allow broader than loopback access
Get-NetFirewallRule -DisplayName 'Windows Remote Management*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
# Allow loopback only: LocalAddress=127.0.0.1, RemoteAddress=127.0.0.1
New-NetFirewallRule -DisplayName 'CFGMS WinRM HTTPS (loopback only)' -Direction Inbound -Protocol TCP -LocalPort 5986 -LocalAddress 127.0.0.1 -RemoteAddress 127.0.0.1 -Action Allow -ErrorAction SilentlyContinue | Out-Null
# Deny all other inbound traffic on 5986 (catches non-loopback sources)
New-NetFirewallRule -DisplayName 'CFGMS WinRM HTTPS (deny non-loopback)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Block -ErrorAction SilentlyContinue | Out-Null`
	_, err := ps.RunPS(script, nil, "")
	return err
}

// createLocalUser creates or updates the local service account for WinRM access.
// username is passed as $args[0] (never embedded in the script string).
// password is passed via stdin — it does NOT appear in cmd.Args or the process list.
func createLocalUser(ps psRunner, username, password string) error {
	// $args[0] = username; password is read from stdin as plaintext, then immediately
	// converted to SecureString — it is never in $args or the script string.
	script := `$username = $args[0]
$passText = [Console]::In.ReadToEnd().TrimEnd()
$secPass = ConvertTo-SecureString -String $passText -AsPlainText -Force
try {
    New-LocalUser -Name $username -Password $secPass -PasswordNeverExpires -ErrorAction Stop
} catch {
    Set-LocalUser -Name $username -Password $secPass -PasswordNeverExpires
}`
	_, err := ps.RunPS(script, []string{username}, password)
	return err
}

// addToHyperVGroups adds the service account to Hyper-V Administrators and
// Remote Management Users. username is $args[0]. Idempotent via SilentlyContinue.
func addToHyperVGroups(ps psRunner, username string) error {
	script := `$username = $args[0]
Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member $username -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group 'Remote Management Users' -Member $username -ErrorAction SilentlyContinue`
	_, err := ps.RunPS(script, []string{username}, "")
	return err
}

// storeWinRMSecrets pre-populates hyperv/winrm_user and hyperv/winrm_pass in the
// secret store. winrmPass is never logged at any level.
func storeWinRMSecrets(store secretsif.SecretStore, winrmUser, winrmPass string) error {
	ctx := context.Background()
	if err := store.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:       "hyperv/winrm_user",
		Value:     winrmUser,
		CreatedBy: "cfgms-steward-install",
	}); err != nil {
		return fmt.Errorf("store hyperv/winrm_user: %w", err)
	}
	if err := store.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:       "hyperv/winrm_pass",
		Value:     winrmPass,
		CreatedBy: "cfgms-steward-install",
	}); err != nil {
		return fmt.Errorf("store hyperv/winrm_pass: %w", err)
	}
	return nil
}

// InstallHyperV extends the base install with WinRM HTTPS listener binding to
// loopback, firewall rules, local service account provisioning, and credential
// pre-population in the OS-native secret store. All steps are idempotent.
// Implements HyperVInstaller on *windowsManager.
func (m *windowsManager) InstallHyperV(token, caCertPEM, expectedFingerprint, winrmUser, winrmPass string) error {
	if !m.IsElevated() {
		return fmt.Errorf("InstallHyperV requires Administrator privileges: right-click the binary and select 'Run as administrator'")
	}

	ps := m.runner()

	// Step 1: Base install — binary copy, service registration, CA cert write.
	fmt.Println("Step 1/8: Running base steward install...")
	if err := m.Install(token, caCertPEM, expectedFingerprint); err != nil {
		return fmt.Errorf("hyperv install: base install: %w", err)
	}

	// Step 2: Generate self-signed TLS cert with localhost, 127.0.0.1, FQDN in SAN.
	fqdn, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("hyperv install: get hostname: %w", err)
	}
	fmt.Printf("Step 2/8: Generating WinRM TLS certificate (5yr) for %s...\n",
		logging.SanitizeLogValue(fqdn))
	thumbprint, err := generateHyperVCert(ps, fqdn)
	if err != nil {
		return fmt.Errorf("hyperv install: generate cert: %w", err)
	}
	fmt.Printf("         Certificate thumbprint: %s\n", thumbprint)

	// Step 3: Bind WinRM HTTPS listener to 127.0.0.1 (not 0.0.0.0).
	fmt.Println("Step 3/8: Configuring WinRM HTTPS listener on 127.0.0.1:5986...")
	if err := setupWinRMListener(ps, thumbprint); err != nil {
		return fmt.Errorf("hyperv install: configure WinRM listener: %w", err)
	}

	// Step 4: Firewall — loopback-only allow, deny non-loopback.
	fmt.Println("Step 4/8: Configuring firewall rules (loopback-only for port 5986)...")
	if err := setupHyperVFirewall(ps); err != nil {
		return fmt.Errorf("hyperv install: configure firewall: %w", err)
	}

	// Step 5: Create or update local service account.
	fmt.Printf("Step 5/8: Creating local service account %s...\n",
		logging.SanitizeLogValue(winrmUser))
	if err := createLocalUser(ps, winrmUser, winrmPass); err != nil {
		return fmt.Errorf("hyperv install: create local user %s: %w",
			logging.SanitizeLogValue(winrmUser), err)
	}

	// Step 6: Add to Hyper-V Administrators and Remote Management Users.
	fmt.Printf("Step 6/8: Adding %s to Hyper-V Administrators and Remote Management Users...\n",
		logging.SanitizeLogValue(winrmUser))
	if err := addToHyperVGroups(ps, winrmUser); err != nil {
		return fmt.Errorf("hyperv install: add %s to groups: %w",
			logging.SanitizeLogValue(winrmUser), err)
	}

	// Step 7: Pre-populate WinRM credentials in the OS-native secret store.
	fmt.Println("Step 7/8: Storing WinRM credentials in secret store...")
	secretsProvider, err := secretsif.GetSecretProvider("steward")
	if err != nil {
		return fmt.Errorf("hyperv install: get secrets provider: %w", err)
	}
	store, err := secretsProvider.CreateSecretStore(map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("hyperv install: create secret store: %w", err)
	}
	if err := storeWinRMSecrets(store, winrmUser, winrmPass); err != nil {
		return fmt.Errorf("hyperv install: store credentials: %w", err)
	}

	// Step 8: Print config snippet.
	fmt.Println("Step 8/8: Done.")
	fmt.Println()
	fmt.Println("Hyper-V host install complete.")
	fmt.Println("Add the following to your steward config:")
	fmt.Println()
	fmt.Println("  winrm_host: localhost")
	fmt.Println("  winrm_user_secret: hyperv/winrm_user")
	fmt.Println("  winrm_pass_secret: hyperv/winrm_pass")

	return nil
}
