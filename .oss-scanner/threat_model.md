# OpenPubkey threat model

Guidance for Anthropic's OSS Scanner. Free text; maintainers may edit it between scans.

## What this project does

OpenPubkey is a Go library that binds a user-held public key to an OpenID Connect ID Token without
changing the OpenID Provider (OP). The result is a **PK Token**: the OP's signed ID Token plus a
client-instance claim (CIC) signature by the user's key, and optionally a cosigner signature. Relying
parties call the verifier to decide whether a PK Token proves "this key belongs to identity X at issuer Y".
Downstream users include opkssh (SSH authentication) and signing tools, so a verifier bug is an
authentication bug for them.

For complete details on the threat model see our academic paper: [OpenPubkey: Augmenting OpenID Connect with User-held Signing Keys](https://eprint.iacr.org/2023/296.pdf)

## Where untrusted input enters

Treat these as attacker-controlled:

- **PK Tokens given to the verifier** (`verifier/`, `pktoken/`): compact and JSON serialisations, every
  protected header (`alg`, `kid`, `typ`, `jku`, …), every payload claim, signatures, the CIC, cosigner
  signatures, and GQ signatures. An attacker can craft them from scratch or modify a genuine one.
- **Network responses** from OPs and cosigners — discovery documents, JWKS (`discover/`), token and
  userinfo endpoints. Assume an attacker may control a non-configured issuer or sit on the network path.
- **HTTP requests to the local callback/chooser servers** started by the client (`providers/`,
  `client/choosers/`, `client/cos.go`) — any website the user visits can send requests to localhost.
- **Requests to a cosigner** (`cosigner/`): auth state, redirects and signing requests from clients.

The library's caller (the application) and its configuration — which issuers and client IDs to trust,
expiration policy — are trusted.

## Components that matter most / least

Most important:

- `verifier/` — `VerifyPKToken`, provider selection by issuer, audience/commitment checks, expiration
  policy, cosigner verification, GQ-only mode.
- `pktoken/` — parsing, compact encoding, signature handling, `osm`/`cos` claims.
- `gq/` — Guillou–Quisquater signature scheme (signing and verification over RSA).
- `oidc/`, `jose/`, `internal/jwx` — JWS/JWT parsing, algorithm handling, DPoP.
- `providers/` — provider verifiers (`providerverifier.go`, GitHub Actions, GitLab CI, Forgejo Actions,
  key-binding/DPoP) and commitment-claim handling.
- `discover/` — JWKS fetching and caching.
- `cosigner/` — MFA cosigner protocol and its auth-state store.

Less important but in scope: `client/` (login flow, choosers), `cert/` (X.509 from PK Tokens), `util/`.

Out of scope: `examples/`, `testutils/`, `*/mocks/`, `docs/`, `.github/`.

## Security properties we care about

1. `VerifyPKToken` accepts a token only if the ID Token is validly signed by a key the configured issuer
   publishes, `iss` and `aud` match the configured provider, the commitment (nonce / aud / GQ binding)
   binds the CIC, the CIC is validly signed by the key in the token, expiration policy holds, and any
   required cosigner signature is valid.
2. No algorithm confusion: an attacker cannot make the verifier use the wrong algorithm or key, a key
   from an unconfigured issuer, or skip a signature.
3. GQ signatures cannot be forged or used to recover/replace the OP's RSA signature; GQ-only mode cannot
   be downgraded.
4. A cosigner never signs for an identity the user did not authenticate as, and its auth state cannot be
   replayed or fixed by another party.
5. Malformed input returns an error; it never panics, hangs or allocates without bound.

## How to exercise it

- `go test ./...` runs offline. `providers.NewMockProvider` / `providers/mockprovider.go` and
  `pktoken/mocks` create OPs, keys and PK Tokens without network access; `verifier/verifier_test.go`,
  `verifier/multiprovider_test.go`, `providers/*_test.go` and `cosigner/*_test.go` show how to drive
  each component.
- `gq/` has its own tests and benchmarks for direct testing of the scheme.

## How we rate severity

- **Critical:** forging a PK Token or getting `VerifyPKToken` to accept a token for an identity, issuer,
  audience or key the attacker does not legitimately hold (including GQ forgery and algorithm confusion).
- **High:** cosigner bypass or auth-state hijack; accepting expired tokens contrary to the expiration
  policy; stealing a user's ID token or PK Token via the localhost servers.
- **Medium:** remotely triggerable panic, hang or unbounded allocation in parsing or verification;
  JWKS/discovery handling that lets a network attacker force a denial of service.
- **Low:** information leaks in errors/logs, issues needing a malicious caller configuration.

## Reporting preferences

- Include a minimal Go test that reproduces the issue against the package's public API.
- Patches should be minimal and fix the root cause, with a regression test.
- Deduplicate by root cause, not by caller.
