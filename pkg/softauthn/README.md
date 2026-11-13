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

- Registration: attestation format `none` (or `tpm` when an `Attester` is
  configured, see below); flags UP, UV and AT; BE=0, BS=0; AAGUID
  `softauthn.AAGUID`; ES256 (alg -7) COSE public key; discoverable
  (resident-key capable) credential.
- Assertion: flags UP and UV; signature is ES256 over
  `authData || SHA-256(clientDataJSON)`.

## TPM attestation (optional)

`Config.Attester` is an interface with one method,
`AttestTPM(authData, clientDataHash) (*TPMStatement, error)`. When it is set,
`Register` emits attestation format `tpm` with the statement it returns (`ver`
"2.0", `alg` -7, `x5c`, `sig`, `certInfo`, `pubArea`, plus the extra `attStmt`
member `cfgmsActivation`) instead of `none`. With no `Attester` the output is
byte-for-byte what it always was. The AAGUID is `softauthn.AAGUID` either way and
an `Attester` cannot change it. A failing or incomplete attester makes `Register`
fail; it never falls back to `none`. Assertions are not affected.

`pkg/softauthn/tpmkey` is the TPM-backed implementation. It takes a
`transport.TPM`, so one code path runs on `/dev/tpmrm0` (Linux), TBS (Windows) and
a software TPM in tests:

- `Create` makes the credential key inside the TPM (P-256, `fixedTPM`,
  `fixedParent`, `sensitiveDataOrigin`) and returns its TPM-wrapped blobs; `Open`
  returns a `crypto.Signer` for `Config.Signer`.
- `Prepare` reads the endorsement key certificate from NV storage and derives the
  attestation key (an ECC P-256 restricted signing key, an endorsement-hierarchy
  primary from a fixed template, never persisted). `Activate` runs
  `TPM2_ActivateCredential` for the controller's challenge and returns the
  recovered secret.
- `Attest` / `NewAttester` run `TPM2_Certify` of the credential key, signed by the
  attestation key, with qualifying data `SHA-256(authData || clientDataHash)`.
  `x5c[0]` is a carrier certificate for the attestation key in the AIK profile
  go-webauthn requires, signed by a throwaway key generated per ceremony. It
  vouches for nothing: a verifier takes the public key from it and trusts that key
  through the activation challenge against the endorsement certificate.

The production API has no option that produces a deliberately wrong attestation.
`tpmkey/tpmkeytest` (Linux with cgo, imported from tests only) starts a software
TPM provisioned with an endorsement certificate from a test CA and exports the
wrong-output helpers a verifier's negative tests need.

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
- **The AAGUID is self-asserted.** With attestation `none` any client can claim
  the CFGMS AAGUID. It labels the authenticator type; it is not proof of what
  produced the response. A `tpm` attestation proves where the credential key is
  held, not what software built the response, so it does not change this.
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

NCrypt and Secure Enclave key code is out of scope: those are signers the caller
plugs in. TPM-held keys and their attestation live in `tpmkey`, not in this
package.
