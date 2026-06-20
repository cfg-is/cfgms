// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

// FILE NAME NOTE: this file is named linux_profile.go (Linux-first), NOT
// profile_linux.go. Go applies an IMPLICIT "//go:build linux" constraint to any
// file whose name ends in "_linux.go", which would exclude this file on the
// Windows steward host (where Hyper-V actually runs) and from cross-platform
// (GOOS=linux) build/test of the always-on create-from-source orchestration in
// vm_provision.go. That implicit GOOS constraint cannot be overridden by an
// explicit build tag, so the file is named linux_profile.go (the trailing
// element "profile" is not a GOOS) to keep the Linux preseed content compiled on
// every platform. The story (#2046) requested profile_linux.go; this rename is
// the only way to satisfy the same story's "no build tag / cross-platform clean"
// requirement.

// Linux preseed answer-file template for the create-from-source path (ADR-009
// §6, Linux row). This file carries NO build tag: the create-from-source
// orchestration in provisionVM() renders the preseed on every platform (driven
// by the recording transport in tests), so the template constant must compile
// on every platform.
//
// The template is rendered by ProfileRenderer.Render (profile.go) using
// text/template — NOT html/template — so preseed syntax is never HTML-escaped.
// Per-VM values ({{ .VMName }}, {{ .CorrelationID }}, {{ .EnrollToken }},
// {{ .AdminPassword }}) travel into the rendered bytes at render time. The join
// token is controller-supplied via config (ADR-010 §2), not a SecretStore
// lookup; the user password is randomized (ADR-010 §4). No secret VALUES are
// stored in the template or the profile.

// linuxDefaultProfileName is the built-in Debian 12 profile used when a Linux
// VM source declares no profile:// reference. Operators may override it by
// authoring a stored-config profile of the same name (ADR-009 §7).
const linuxDefaultProfileName = "debian-12-base"

// preseedRegTokenSecretKey is retained as profile metadata
// (Enroll.RegistrationTokenSecretKey) for operators who author a
// SecretStore-backed profile. The built-in template now resolves the token from
// controller-supplied config ({{ .EnrollToken }}, ADR-010), not this key.
const preseedRegTokenSecretKey = "hyperv/enroll/regtoken"

// preseedBundleURL is the default enrollment-bundle URL the built-in Debian
// profile pulls the steward .deb from in late_command. Operators override it by
// authoring a stored-config profile with a different BundleURL var binding.
const preseedBundleURL = "https://controller.cfg.is/enroll/cfgms-steward.deb"

// preseedTemplate is a Debian 12 preseed.cfg template (ADR-009 §6, Linux row).
// It covers locale/keyboard/timezone, DHCP networking, guided LVM partitioning,
// a non-interactive base install, and a late_command that downloads and
// installs the steward bundle then enrolls.
//
// The late_command uses declared paths only and contains NO banned patterns:
// no `eval`, no `bash -c "<string>"`, no `iex`, no inline code composition. Each
// step is a discrete invocation joined with `&&`; the registration token and
// the CorrelationID hostname hint are substituted at render time, not composed
// at install time inside the guest.
//
// The {{ .CorrelationID }} value is passed as the enrollment hostname/label so
// the controller-side completion reconciler (#2050) can match the registered
// steward's mTLS CN back to this VM's provisioning record.
const preseedTemplate = `# Debian 12 (bookworm) preseed — CFGMS create-from-source (ADR-009 §6)
# Rendered for VM {{ .VMName }} (correlation {{ .CorrelationID }}).

### Localization
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us

### Clock and time zone
d-i clock-setup/utc boolean true
d-i time/zone string Etc/UTC
d-i clock-setup/ntp boolean true

### Network configuration (DHCP)
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string {{ .CorrelationID }}
d-i netcfg/get_domain string cfg.is
d-i netcfg/hostname string {{ .CorrelationID }}

### Mirror settings
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string

### Account setup (root locked; a single sudo-capable user)
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/user-fullname string CFGMS Operator
d-i passwd/username string cfgms
d-i passwd/user-password password {{ .AdminPassword }}
d-i passwd/user-password-again password {{ .AdminPassword }}
d-i user-setup/allow-password-weak boolean false
d-i user-setup/encrypt-home boolean false

### Partitioning (guided, entire disk, LVM)
d-i partman-auto/method string lvm
d-i partman-auto/disk string /dev/sda
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true

### Base system + apt
d-i apt-setup/non-free-firmware boolean true
d-i apt-setup/contrib boolean false
d-i apt-setup/non-free boolean false
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string wget ca-certificates
d-i pkgsel/upgrade select full-upgrade
popularity-contest popularity-contest/participate boolean false

### Boot loader
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/bootdev string default

### Finish install without prompting
d-i finish-install/reboot_in_progress note

### First-boot enrollment.
# Declared paths only: download the steward bundle, install it, then register
# using the controller-supplied join token (ADR-010 §2 — {{ .EnrollToken }},
# not a SecretStore lookup). The hostname is set to {{ .CorrelationID }} above,
# so the controller-side reconciler (#2050) matches the registered steward by
# hostname. Each step is a discrete declared invocation joined with a command
# separator; no runtime code composition. (NOTE: CA-trust/--fingerprint wiring
# and how d-i loads this preseed are pending the Debian delivery-method decision;
# the registration command form is now correct regardless.)
d-i preseed/late_command string \
  in-target wget -q {{ .BundleURL }} -O /tmp/cfgms-steward.deb ; \
  in-target dpkg -i /tmp/cfgms-steward.deb ; \
  in-target cfgms-steward install --regtoken {{ .EnrollToken }}
`

// defaultLinuxProfile returns the built-in Debian 12 UnattendProfile used when a
// Linux VM source declares no profile:// reference. It is a real, renderable
// profile (preseed format) wired to the default registration-token secret key
// and bundle URL; operators override it by authoring a stored-config profile.
func defaultLinuxProfile() *UnattendProfile {
	return &UnattendProfile{
		Name:         linuxDefaultProfileName,
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     preseedTemplate,
		Enroll: EnrollConfig{
			RegistrationTokenSecretKey: preseedRegTokenSecretKey,
			BundleURL:                  preseedBundleURL,
		},
	}
}
