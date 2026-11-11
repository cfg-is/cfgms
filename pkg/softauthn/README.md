# softauthn

`softauthn` is a software WebAuthn authenticator core. Given a P-256
`crypto.Signer`, it produces registration and assertion responses that the
`go-webauthn` library verifies. The CLI, shared test support and the server's
AAGUID check all use this one implementation.

```go
a, err := softauthn.New(softauthn.Config{
    Signer:       signer,                         // P-256 crypto.Signer
    RPID:         "controller.example.test",
    Origin:       "https://controller.example.test",
    CredentialID: credID,
})
body, err := a.Register(beginJSON) // finish-registration request body
body, err = a.Assert(beginJSON)    // finish-login request body
```

`beginJSON` is the `protocol.CredentialCreation` / `protocol.CredentialAssertion`
JSON the controller returns from its begin endpoints, with the API envelope
(`data`) already removed.

## What it produces

- Registration: attestation format `none`; flags UP, UV and AT; BE=0, BS=0;
  AAGUID `softauthn.AAGUID`; ES256 (alg -7) COSE public key; discoverable
  (resident-key capable) credential.
- Assertion: flags UP and UV; signature is ES256 over
  `authData || SHA-256(clientDataJSON)`.

## Refusals

The authenticator is bound to one RP ID, one origin and one credential ID. It
returns an error and never signs when:

- the options carry a different `rpId`;
- `pubKeyCredParams` does not include -7;
- `excludeCredentials` contains its credential ID;
- `allowCredentials` is non-empty and omits its credential ID.

The options carry no origin, so an origin that is not an https origin for the
RP ID (the host equals the RP ID or is a subdomain of it) is refused by `New`.

## Limits

- **Sign count is always 0.** The controller accepts a stored/response counter
  of 0/0, and this package has no storage in which to keep an advancing
  counter. Counter-based clone detection therefore does not apply to a
  credential produced here.
- **The AAGUID is self-asserted.** The controller requests no attestation
  (format `none`), so any client can claim the CFGMS AAGUID. It labels the
  authenticator type; it is not proof of what produced the response.
  `Config.AAGUID` exists only so tests can model a non-CFGMS authenticator.
  Only `_test.go` files and `pkg/testutil/webauthntest` may set it; `cfg`
  never sets it (ADR-021 Amendment 10).
- **UV=1 means only that the holder can use the key.** The package sets the
  user-verified flag on every response. Nothing is verified about a person:
  whoever can call the signer gets a UV=1 assertion.
- **Storage is the caller's job.** The package keeps no key, credential or
  user record. The caller owns the signer, credential ID and (optionally)
  user handle, and supplies them on every construction. `Register` remembers
  the user handle in memory only; pass it again through `Config.UserHandle`
  after a restart so discoverable assertions carry it.
- Private key bytes never appear in a response, error string or log line; the
  package does not log and signer errors are not passed through.

TPM, NCrypt and Secure Enclave key code is out of scope: those are signers the
caller plugs in.
