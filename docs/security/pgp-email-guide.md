# Using PGP Encrypted Email - Complete Guide

## Overview

PGP (Pretty Good Privacy) allows people to send you encrypted emails that only you can decrypt. This is essential for security vulnerability reports and confidential communications.

---

## How PGP Email Works

### The Basics

1. **You have TWO keys**:
   - **Public Key**: Share with everyone (publish on website)
   - **Private Key**: Keep SECRET, never share, protected by passphrase

2. **Sending encrypted email TO you**:
   - Researcher downloads your public key
   - Encrypts their message with your public key
   - Only your private key can decrypt it

3. **Reading encrypted email**:
   - You receive encrypted message
   - Use your private key + passphrase to decrypt
   - Read the plaintext message

---

## Using PGP with Email

### Option 1: Mailvelope Browser Extension (EASIEST for Webmail)

**Supported Webmail Providers**: Gmail, Yahoo, Outlook.com, Zoho, ProtonMail, and others

**Setup** (5 minutes):

1. **Install Mailvelope extension**:
   - Chrome: https://chrome.google.com/webstore (search "Mailvelope")
   - Firefox: https://addons.mozilla.org (search "Mailvelope")
   - Edge: https://microsoftedge.microsoft.com/addons (search "Mailvelope")

2. **Import your private key**:
   - Click Mailvelope icon → Options → Key Management
   - Import Keys → Select your private key file
   - Enter your passphrase when prompted

3. **Configure for your email provider**:
   - Mailvelope auto-detects most webmail providers
   - When you open your webmail, you'll see Mailvelope integration

**Reading encrypted email**:
- Open email in your webmail interface
- Mailvelope automatically detects PGP encrypted content
- Click to decrypt (enter passphrase)
- Read plaintext message

**Replying with encryption**:
- Click "Encrypt" button in Mailvelope compose window
- Add recipient's public key (if they sent you their key)
- Write message, click encrypt, send

**Advantages**:
- ✅ Works with any webmail provider
- ✅ No additional software needed
- ✅ Cross-platform (works anywhere with a browser)

### Option 2: Thunderbird Email Client (BETTER for High Volume)

**Setup**:

1. **Download Thunderbird**: https://www.thunderbird.net

2. **Add your email account**:
   - Account Settings → Add Mail Account
   - Enter your email address and password
   - Thunderbird auto-configures most providers (Gmail, Outlook, Zoho, etc.)
   - For custom providers, you may need IMAP/SMTP settings

3. **Enable built-in PGP**:
   - Settings → Account Settings → End-to-End Encryption
   - Add Key → Import existing key
   - Select your private key file
   - Enter passphrase

**Reading encrypted email**:
- Encrypted emails show lock icon
- Click to view → enter passphrase → read message

**Replying**:
- Compose window has "Encrypt" button
- Automatically uses recipient's public key (if available)

**Advantages**:
- ✅ Built-in PGP support (no extensions needed)
- ✅ Desktop client (works offline)
- ✅ Better for high email volume
- ✅ Full email features (folders, search, filters)

### Option 3: Apple Mail + GPG Suite (macOS)

**Setup**:

1. **Install GPG Suite**: https://gpgtools.org
2. **Import your private key** via GPG Keychain
3. **Apple Mail auto-detects** PGP keys
4. **Compose with encryption** using toolbar buttons

**Advantages**:
- ✅ Native macOS integration
- ✅ Works with iCloud, Gmail, Exchange, etc.
- ✅ Clean UI

### Option 4: GPG Command Line (for Power Users)

**Reading encrypted email**:

Save email to file (including headers), then:

```bash
gpg --decrypt encrypted-email.txt
```

Enter passphrase when prompted.

**Encrypting a reply**:

```bash
# Create message
echo "Thank you for the report. We're investigating." > reply.txt

# Encrypt for recipient
gpg --encrypt --armor --recipient researcher@example.com reply.txt

# Creates reply.txt.asc - paste this into email
```

**Advantages**:
- ✅ Works on any system
- ✅ Scriptable/automatable
- ✅ Most control

---

## Common Workflows

### Scenario 1: Researcher Reports Vulnerability

**They do**:
1. Download your public key from your security page
2. Write vulnerability details
3. Encrypt with your public key
4. Email to your security contact address

**You do**:
1. Check your security email inbox
2. See encrypted email (looks like gibberish text block)
3. Decrypt with Mailvelope/Thunderbird/GPG (enter passphrase)
4. Read vulnerability details
5. Reply (encrypted) to acknowledge receipt

### Scenario 2: Acknowledge Receipt

**Quick encrypted reply template**:

```
Subject: Re: [Security] <vulnerability description>

Thank you for your report. We have:
- Confirmed receipt
- Assigned internal tracking number: SEC-2025-XXX
- Expected timeline: 7-14 days for initial assessment

We will keep you updated via this encrypted channel.

Best regards,
[Your Organization] Security Team
```

### Scenario 3: Request Additional Information

**Encrypted back-and-forth**:

If researcher included their public key:
- Your email client auto-encrypts replies
- Entire conversation remains encrypted
- Safe to discuss technical details

If they didn't include their public key:
- Reply unencrypted asking them to send their public key
- Once received, import it and continue encrypted

---

## Best Practices

### DO:
✅ Store private key passphrase in password manager
✅ Back up private key securely (encrypted USB, password manager vault)
✅ Always verify sender's identity before acting on reports
✅ Keep conversation encrypted throughout disclosure process
✅ Document decryption in secure incident response log
✅ Test your setup before announcing it publicly
✅ Publish fingerprint on your security page for verification

### DON'T:
❌ Email your private key to anyone (NEVER!)
❌ Use same passphrase as your email password
❌ Reply unencrypted to encrypted message (breaks confidentiality)
❌ Share decrypted vulnerability details in public channels
❌ Store passphrase in plaintext files
❌ Reuse keys across different organizations

---

## Testing Your Setup

### Test with Yourself

1. **Send encrypted test email to yourself**:

```bash
# Create test message
echo "This is a test of PGP encryption" > test.txt

# Encrypt with your own public key
gpg --encrypt --armor --recipient security@your-domain.com test.txt

# Email the encrypted content (test.txt.asc) to security@your-domain.com
```

2. **Log into your email**
3. **Try decrypting** with Mailvelope/Thunderbird
4. **Success?** You're ready!

### Test with a Colleague

1. Exchange public keys
2. Send encrypted test messages
3. Verify both can decrypt
4. Practice replying with encryption

### Test with External User

1. Publish public key on your website
2. Ask security researcher friend to send test report
3. Decrypt and reply
4. Verify end-to-end workflow

---

## Troubleshooting

### "Cannot decrypt - wrong passphrase"
- Double-check passphrase (case-sensitive)
- Verify you're using correct private key
- Check caps lock is off

### "No public key for recipient"
- Recipient needs to send their public key first
- OR reply unencrypted asking them to include public key
- Import their key: `gpg --import their-key.asc`

### "Expired key"
- Regenerate key (or extend expiration if possible)
- Update website with new public key
- Notify regular correspondents

### "Email client doesn't show decrypt option"
- Ensure PGP extension/plugin is enabled
- Check email is actually PGP encrypted (starts with "-----BEGIN PGP MESSAGE-----")
- Verify private key is imported correctly

### "Encryption button is grayed out"
- Recipient's public key not imported
- Email client doesn't recognize recipient
- Import recipient's public key first

---

## Key Management

### Backing Up Your Private Key

**Export private key** (store securely!):
```bash
gpg --export-secret-keys --armor security@your-domain.com > private-key.asc
```

**Store in**:
- Password manager (1Password, Bitwarden, etc.)
- Encrypted USB drive (locked in safe)
- Secure backup service (encrypted)

**NEVER**:
- Email it to yourself
- Store in cloud unencrypted
- Share with anyone

### Importing Private Key on New System

```bash
gpg --import private-key.asc
gpg --edit-key security@your-domain.com
gpg> trust
gpg> 5 (ultimate trust)
gpg> quit
```

### Revoking a Compromised Key

If your private key is compromised:

1. **Generate revocation certificate**:
```bash
gpg --gen-revoke security@your-domain.com > revoke.asc
```

2. **Import and publish revocation**:
```bash
gpg --import revoke.asc
gpg --keyserver keys.openpgp.org --send-keys <KEY_ID>
```

3. **Update your website** with notice of revoked key
4. **Generate new key** and republish

---

## Quick Reference

### Key Locations
- **Private key**: `~/.gnupg/` (Linux/macOS) or `%APPDATA%\gnupg\` (Windows)
- **Public key**: Export and publish on your website

### Common Commands

```bash
# List your keys
gpg --list-keys

# Export public key
gpg --armor --export security@your-domain.com > pgp-key.asc

# Import someone's public key
gpg --import their-key.asc

# Encrypt file
gpg --encrypt --armor --recipient researcher@example.com file.txt

# Decrypt file
gpg --decrypt file.txt.asc

# Sign a file
gpg --sign file.txt

# Verify signature
gpg --verify file.txt.sig
```

### Email Format for Encrypted Messages

Encrypted emails contain:
```
-----BEGIN PGP MESSAGE-----

[encrypted gibberish here]

-----END PGP MESSAGE-----
```

Signed emails contain:
```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

[cleartext message]

-----BEGIN PGP SIGNATURE-----

[signature]

-----END PGP SIGNATURE-----
```

---

## Recommended Setup for Production

1. ✅ **Generate key** with strong passphrase
2. ✅ **Back up private key** to secure location
3. ✅ **Install email client/extension** (Mailvelope or Thunderbird)
4. ✅ **Publish public key** to your security page
5. ✅ **Test with yourself** (send encrypted test email)
6. ✅ **Add fingerprint** to SECURITY.md
7. ✅ **Document process** for team members
8. ✅ **Set up monitoring** for security inbox

**Time investment**: ~30 minutes setup, then seamless

---

## Publishing Your Public Key

### On Your Website

Create a security page (e.g., `https://your-domain.com/security/`) with:

```markdown
## PGP Encrypted Communication

For sensitive security reports, use PGP encryption:

- **Public Key**: [Download PGP Key](/security/pgp-key.asc)
- **Fingerprint**: `1234 5678 90AB CDEF 1234  5678 90AB CDEF 1234 5678`
- **Key ID**: `90ABCDEF12345678`

### How to Send Encrypted Email

1. Download our public key (above)
2. Import it: `gpg --import pgp-key.asc`
3. Encrypt your message: `gpg --encrypt --armor --recipient security@your-domain.com message.txt`
4. Email the encrypted output to security@your-domain.com
```

### In SECURITY.md

```markdown
## Reporting a Vulnerability

For sensitive security reports, we support PGP encrypted email:

- Email: security@your-domain.com
- PGP Key: https://your-domain.com/security/pgp-key.asc
- Fingerprint: `1234 5678 90AB CDEF 1234  5678 90AB CDEF 1234 5678`
```

---

## Resources

### Tools
- **Mailvelope** (Browser Extension): https://mailvelope.com/
- **Thunderbird** (Email Client): https://www.thunderbird.net
- **GPG Suite** (macOS): https://gpgtools.org
- **Gpg4win** (Windows): https://gpg4win.org
- **GnuPG** (Command Line): https://gnupg.org

### Guides
- **GPG Handbook**: https://www.gnupg.org/gph/en/manual.html
- **Email Self-Defense** (FSF): https://emailselfdefense.fsf.org/
- **Mailvelope User Guide**: https://mailvelope.com/help
- **Thunderbird OpenPGP Guide**: https://support.mozilla.org/kb/openpgp-thunderbird

### Key Servers
- **keys.openpgp.org**: Modern, privacy-respecting keyserver
- **keyserver.ubuntu.com**: Ubuntu keyserver
- **pgp.mit.edu**: MIT PGP keyserver (legacy)

---

## Security Considerations

### Threat Model
PGP protects against:
- ✅ Email interception (man-in-the-middle)
- ✅ Compromised email servers
- ✅ Data breaches exposing email content
- ✅ Accidental disclosure

PGP does NOT protect against:
- ❌ Compromised endpoint (malware on your computer)
- ❌ Keyloggers capturing passphrase
- ❌ Metadata (sender, recipient, timestamp visible)
- ❌ Social engineering

### Additional Security Measures
- Use 2FA on email accounts
- Keep software updated
- Use antivirus/antimalware
- Verify key fingerprints out-of-band (phone call, in person)
- Use secure workstation for handling sensitive reports
- Consider air-gapped system for highest security

---

## Legal and Compliance

### Export Restrictions
- PGP/GPG may be subject to export controls in some countries
- Check your local laws before using encryption

### Data Retention
- Consider your legal obligations for retaining encrypted communications
- Some jurisdictions require specific retention periods

### Professional Use
- Document your PGP setup in organizational security policies
- Train team members on proper use
- Include in incident response procedures

---

*This guide is maintained as part of the CFGMS security documentation. For questions or updates, contact the security team.*
