// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// This file is deliberately named windows_profile.go, NOT profile_windows.go.
// A Go source file whose name ends in _windows.go (or _windows_test.go) carries
// an implicit GOOS=windows build constraint, which would exclude it from the
// GOOS=linux cross-compile and from the create-from-source orchestration that
// runs on every platform under the recording transport. The Windows answer-file
// templates and the defaultWindowsProfile factory must compile and render on all
// platforms, so the file uses the windows_ prefix (no constraint) rather than
// the _windows suffix (which does). This mirrors the rationale in
// vm_provision.go for keeping the provisioning consts platform-neutral.
package hyperv

import (
	"crypto/rand"
	"fmt"
)

// randomAdminPassword returns a 24-character random password that satisfies
// Windows password complexity (lower + upper + digit + symbol). It is generated
// per VM at render time to back the Windows autounattend's one-shot AutoLogon
// (which runs enrollment) and is never persisted or surfaced — after enrollment
// the steward manages the host. Visually-ambiguous characters (0/O, 1/l/I) are
// excluded. Uses crypto/rand; the first four positions guarantee one character
// from each class so complexity is always met.
func randomAdminPassword() (string, error) {
	const (
		lowers  = "abcdefghijkmnpqrstuvwxyz"
		uppers  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		digits  = "23456789"
		symbols = "-_#%+="
	)
	classes := []string{lowers, uppers, digits, symbols}
	all := lowers + uppers + digits + symbols
	const n = 24
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("hyperv: read random bytes: %w", err)
	}
	out := make([]byte, n)
	for i := range classes {
		out[i] = classes[i][int(buf[i])%len(classes[i])]
	}
	for i := len(classes); i < n; i++ {
		out[i] = all[int(buf[i])%len(all)]
	}
	return string(out), nil
}

// autounattendTemplate is the Windows Server autounattend.xml answer file
// rendered to the seed VHDX for an os_family: windows VM (ADR-009 §6). Windows
// Setup auto-discovers autounattend.xml from the root of attached removable
// media (the FAT32 CFGMS_SEED seed volume), so no media repack is required.
//
// Template vars (resolved by ProfileRenderer at provision time):
//   - {{ .VMName }}         host-side VM name → guest ComputerName
//   - {{ .ProductEdition }} Windows image/edition name for the install step
//   - {{ .CorrelationID }}  correlation identity baked into RegisteredOrganization;
//     the controller-side reconciler (#2050) matches the registered steward's
//     mTLS CN against this value to flip the record to ready (ADR-009 §8)
//   - {{ .AdminPassword }}  per-VM random Administrator password (generated at
//     render time) used only for the one-shot AutoLogon that runs enrollment;
//     never persisted or surfaced
//   - {{ .EnrollToken }}    tenant join token (controller-supplied via config,
//     ADR-010 §2 — NOT a SecretStore lookup; the #2077 fix)
//   - {{ .CAFingerprint }}  controller CA SHA-256 for guest-side TOFU
//
// Enrollment runs first-boot via <FirstLogonCommands>: an AutoLogon of the local
// Administrator triggers a single cmd.exe /c command that locates the FAT32
// CFGMS_SEED volume (staged with cfgms-steward.exe + controller-ca.crt next to
// autounattend.xml) and runs `cfgms-steward install --regtoken … --controller-ca …
// --fingerprint …`, which self-copies the binary to the platform path and
// registers as a service. The steward's controller URL is baked in at build
// time (ldflags). A fixed argument list with declared paths — no iex /
// Invoke-Expression, no powershell -Command "<string>", no -EncodedCommand, no
// runtime code composition (CLAUDE.md banned patterns, ADR-009 §6). The seed
// (which briefly holds the low-value token) is detached at finalizing and
// deleted on enrollment (ADR-010 §5, #2081).
const autounattendTemplate = `<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage>
        <UILanguage>en-US</UILanguage>
      </SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>EFI</Type>
              <Size>200</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>MSR</Type>
              <Size>128</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Label>System</Label>
              <Format>FAT32</Format>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>3</PartitionID>
              <Label>Windows</Label>
              <Format>NTFS</Format>
              <Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>3</PartitionID>
          </InstallTo>
          <InstallFrom>
            <MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
              <Key>/IMAGE/NAME</Key>
              <Value>{{ .ProductEdition }}</Value>
            </MetaData>
          </InstallFrom>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <Organization>{{ .CorrelationID }}</Organization>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{{ .VMName }}</ComputerName>
      <RegisteredOrganization>{{ .CorrelationID }}</RegisteredOrganization>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
          <Value>{{ .AdminPassword }}</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Password>
          <Value>{{ .AdminPassword }}</Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Username>Administrator</Username>
      </AutoLogon>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <Description>Install and enroll the CFGMS steward from the seed volume</Description>
          <CommandLine>cmd.exe /c for %i in (D E F G H I J K) do @if exist "%i:\cfgms-steward.exe" "%i:\cfgms-steward.exe" install --regtoken "{{ .EnrollToken }}" --controller-ca "%i:\controller-ca.crt" --fingerprint "{{ .CAFingerprint }}"</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
`

// defaultWindowsProfile returns the built-in Windows Server unattended-install
// profile used when an os_family: windows source declares no explicit
// profile:// reference. It carries the autounattend template that self-installs
// the steward from the seed volume (ADR-010) and mirrors the Linux analog: a
// code-resident default that operators can override with a stored profile
// (ADR-009 §7). The join token and CA fingerprint are controller-supplied via
// config (ProfileVars), not the local SecretStore (#2077 fix).
func defaultWindowsProfile() *UnattendProfile {
	return &UnattendProfile{
		Name:         defaultWindowsProfileName,
		OSFamily:     "windows",
		AnswerFormat: AnswerFormatAutounattend,
		Template:     autounattendTemplate,
		Enroll: EnrollConfig{
			RegistrationTokenSecretKey: defaultRegTokenSecretKey,
		},
	}
}

const (
	// defaultWindowsProfileName is the name of the built-in Windows profile.
	defaultWindowsProfileName = "windows-server-default"

	// defaultRegTokenSecretKey is retained as profile metadata for operators who
	// author a SecretStore-backed profile; the built-in template resolves the
	// token from controller-supplied config ({{ .EnrollToken }}), not this key.
	defaultRegTokenSecretKey = "hyperv/enroll/regtoken"

	// defaultWindowsEdition is the Windows Server image name selected by the
	// autounattend ImageInstall step when a profile/source does not specify one.
	defaultWindowsEdition = "Windows Server 2025 Standard (Desktop Experience)"
)
