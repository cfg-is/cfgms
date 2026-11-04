# Sending an Encrypted Vulnerability Report

[SECURITY.md](../../SECURITY.md) owns the reporting address, disclosure process
and current public-key location. Encryption is optional under that policy.
This page covers the short sender workflow, not mailbox/keyserver administration.

1. Obtain the public key from the location published in SECURITY.md over verified
   HTTPS. Confirm its fingerprint through a trusted channel before relying on it;
   do not trust an arbitrary keyserver match for an email address.
2. Inspect/import the public key using your PGP client's current instructions.
   Never send, publish or import someone else's private key for this task.
3. Encrypt the report for that verified recipient and send it to the address in
   SECURITY.md. Keep exploit details and identifying client data out of public
   issue comments and unencrypted diagnostic attachments.
4. If you need an encrypted reply, include your own public key and a contact
   address. Retain your private key securely; it is not a report attachment.

A GnuPG inspection example for an already downloaded **public** key is:

```bash
gpg --show-keys --fingerprint pgp-key.asc
```

After verifying/importing the intended public key, encrypt with its verified
fingerprint rather than an ambiguous display name:

```bash
gpg --armor --encrypt --recipient VERIFIED_FINGERPRINT --output report.asc report.txt
```

Replace the fingerprint with the verified value; none is invented in this guide.
Use a protected workspace for plaintext preparation and follow your organization's
handling policy. If the published key cannot be verified or is expired, ask the
security contact for the current key instead of improvising another recipient.
