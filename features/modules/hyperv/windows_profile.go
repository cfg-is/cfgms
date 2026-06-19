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
//   - {{ secret "ppkg-path-key" }} declared host path to the staged .ppkg,
//     resolved from the secrets provider at render time — never composed at
//     runtime, never embedded as a literal in the profile
//
// Enrollment runs first-boot via <FirstLogonCommands>: a cmd.exe /c copy of the
// staged .ppkg to a local temp path followed by dism.exe /online /add-package.
// Both commands use explicit, quoted, declared paths and fixed argument lists —
// no iex / Invoke-Expression, no powershell -Command "<string>", no
// -EncodedCommand, no runtime code composition (CLAUDE.md banned patterns,
// ADR-009 §6).
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
              <Type>Primary</Type>
              <Size>500</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>EFI</Type>
              <Size>100</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order>
              <Type>MSR</Type>
              <Size>128</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>4</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>4</PartitionID>
              <Label>Windows</Label>
              <Format>NTFS</Format>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>4</PartitionID>
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
          <Description>Stage CFGMS enrollment provisioning package</Description>
          <CommandLine>cmd.exe /c copy /Y "{{ secret "ppkg-path-key" }}" "C:\Windows\Temp\cfgms-enroll.ppkg"</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>2</Order>
          <Description>Apply CFGMS enrollment provisioning package</Description>
          <CommandLine>dism.exe /online /add-package /packagepath:"C:\Windows\Temp\cfgms-enroll.ppkg" /quiet /norestart</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
`

// setupCompleteTemplate is the file-staged SetupComplete.cmd enrollment fallback
// for Windows guests (ADR-009 §6). It is rendered ONLY when a profile sets
// enroll.use_setup_complete: true; the default Windows path enrolls via the
// signed .ppkg applied at first logon. The template contains a single
// declared-path cfgms-steward enroll invocation with a fixed argument list and
// no runtime composition — no iex, no powershell -Command "<string>", no
// -EncodedCommand.
//
// Template vars:
//   - {{ .EnrollToken }}   resolved registration token (supplied pre-resolved)
//   - {{ .CorrelationID }} steward enrollment label the controller matches on
//   - {{ .BundleURL }}     enrollment-bundle location the steward pulls from
const setupCompleteTemplate = `@echo off
"C:\Program Files\CFGMS\cfgms-steward.exe" enroll --token "{{ .EnrollToken }}" --bundle-url "{{ .BundleURL }}" --label "{{ .CorrelationID }}"
`

// defaultWindowsProfile returns the built-in Windows Server unattended-install
// profile used when an os_family: windows source declares no explicit
// profile:// reference. It carries the autounattend template and an enroll block
// referencing the .ppkg host-path secret key. It mirrors the Linux analog used
// by the create-from-source path: a code-resident default that operators can
// override with a stored profile (ADR-009 §7).
//
// The .ppkg is a host-path staged asset referenced via the secrets provider at
// render time (ppkgPathSecretKey) — its signing infrastructure is out of scope
// (#1851 PO decision #3); an unsigned/self-signed package behind
// module_trust.mode: bypass is acceptable for lab/dogfood.
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

	// ppkgPathSecretKey is the secrets-provider key the autounattend template
	// resolves to obtain the declared host path of the staged .ppkg. It matches
	// the {{ secret "ppkg-path-key" }} reference in autounattendTemplate.
	ppkgPathSecretKey = "ppkg-path-key"

	// defaultRegTokenSecretKey is the conventional secrets-provider key under
	// which the enrollment registration token is stored when a profile does not
	// override it.
	defaultRegTokenSecretKey = "hyperv/enroll/regtoken"

	// defaultWindowsEdition is the Windows Server image name selected by the
	// autounattend ImageInstall step when a profile/source does not specify one.
	defaultWindowsEdition = "Windows Server 2025 Standard (Desktop Experience)"
)
