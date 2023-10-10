# OpenPubkey Reference Implementation

This repo contains the current reference implementation of OpenPubkey. The reference implementation is a work in progress.

## What is OpenPubkey?

OpenPubkey adds user or workload generated public keys to OpenID Connect (OIDC) enabling identities to sign messages or artifacts under their OIDC identity. In essence, OpenPubkey is a protocol for getting OpenID Providers (OPs) to bind identities to public keys.

Verifiers can check that these signatures are valid and associated with the signing OpenID identity. OpenPubkey does not add any new trusted parties beyond what is required for OpenID Connect. It is fully compatible with existing OpenID Providers (Google, Azure/Microsoft, Okta, OneLogin, Keycloak) without any changes to the OpenID Provider.

### ID Tokens and PK Tokens

OpenPubkey uses ID Tokens issued by OpenID Providers (OPs) to produce PK Tokens. A PK Token consist of the ID Token and the CIC (Client-Instance Claims) where the CIC contains the user's public key and associated metadata. The ID Token contains a hash of the CIC, so that the values in the CIC including the identities public key are cryptographically bound to the ID Token signed by the OP.

For workload-identity, the hash of the CIC is stored in the ID Token's `aud` claim following the pattern of GitHub Action's workload identity. For user-identity, the hash of the CIC is stored in the ID Token's `nonce` claim.

## OpenPubkey FAQ

### What is the difference between Sigstore and OpenPubkey?

OpenPubkey cannot really be compared to Sigstore. Sigstore is an end-to-end artifact signing solution, whereas OpenPubkey only binds public keys to OIDC identities for use as part of a larger signing solution. OpenPubkey is complementary to Sigstore, for example https://github.com/sigstore/fulcio/issues/1056

As stated in the Related Work section of [the OpenPubkey paper](https://eprint.iacr.org/2023/296.pdf):

> “Sigstore [31, 42] is an open source project for signing and verifying software artifacts. Users can sign under their OpenID Connect identity by using the sigstore Fulcio Certificate Authority [43] which uses an immutable log to store a mapping between an OpenID Connect ID Token and a short lived public key enabling parties to attribute signatures to identities. The Fulcio CA (Certificate Authority) is trusted to create this mapping between an ID Token and a public key. Using OpenPubkey this trust can be eliminated as OpenPubkey does not need a trusted party to map ID Tokens to public keys. The Fulcio CA could in turn help OpenPubkey by acting as a public OpenPubkey verifier and OP public key database."

### How does OpenPubkey ensure the nonce claim functions as nonce?

In the user-identity scenario the CIC that contains the user's public key is hashed to the `nonce` claim in the ID Token. As OIDC requires that this field never repeat, OpenPubkey includes a random value, rz, in the CIC. Thus the hash of the CIC is always different and random. This maintains the required properties needed by the `nonce` claim in OIDC.

```
rz = crypto.random()
CIC = {'rz': crypto.random(), 'upk': <publickey>, 'alg': 'EC256'}
IDToken.nonce = SHA3(CIC)
```

### Does OpenPubkey present a privacy leak?

The PK Tokens used by OpenPubkey contain the claims from the OIDC ID Tokens of the signer, so making them public necessarily makes those claims public too. This may include elements of the signer’s identity such as the signer’s name or email addresses. It is up to users of OpenPubkey as to whether or not PK Tokens are made public.

In a public artifact signing scenario, it could be argued that these very claims are the very claims upon which trust in the artifact should be based. However, some OIDC providers may include claims that the signer may wish to keep private. Users of OpenPubkey should consider carefully which OIDC providers to integrate with.

Most OpenID Providers (OP) allow you to scope the fields in the ID Tokens. For instance Google’s OP is by default scoped to only include userinfo-email claims: name, email address and icon. Given that purpose of OpenPubkey is to enable parties to verify that a particular identity e.g., ethan@bastion.com, produced a particular signature, if you do not want signatures to be associated with OIDC identities, then OpenPubkey may not be a good fit for your use case.

In other OpenPubkey deployment scenarios, such as those employed by BastionZero, the ID Tokens are not made publicly available.

### Can the ID Tokens in Pubkeys be replayed against OIDC Resource Providers?

Although not present in the original OpenPubkey paper, GQ signatures have now been integrated so that the OpenID Provider's signature can be stripped from the ID Token, and a proof of that signature published in its place. This prevents the ID Token present in the PK Token from being used against any OIDC resource providers as the original signature has been stripped. However the GQ Signature provides the same assurance that the signature provided.

We follow the approach specified in the paper: [Reducing Trust in Automated Certificate Authorities via Proofs-of-Authentication.](https://arxiv.org/abs/2307.08201)


### What about key management?

OpenPubkey assumes that all identity-held key pairs are ephemeral. You generate them as needed and delete them when you are done. No key management headaches.

### Should I be putting so much trust in a single OpenID Provider (OP)?

Currently anyone using OIDC is trusting a single OpenID Provider. OpenPubkey improves on this by providing an optional protocol for the user-identity scenario (interactive browser authentication with the OIDC provider) that removes the OP as a single point of compromise. This protocol independently  authenticates the user via MultiFactor Authentication (MFA) and then cosigns the user's PK Token. We call this the MFA-cosigner. If you desire to remove the OIDC Provider as a single point of compromise, consider requiring the use of an OpenPubkey MFA Cosigner. In the workload identity scenario, this is not supported.


## Remaining Work

Phase 1:

- [ ] Common OpenPubkey client struct constructor that supports:
  - [ ] [Github OpenID Provider (OP) with CIC in `aud` claim](https://github.com/openpubkey/openpubkey/issues/5)
  - [ ] [Azure OpenID Provider (OP)](https://github.com/openpubkey/openpubkey/issues/6)
  - [x] Google OpenID Provider (OP)
- [x] GQ Signature Support
  - [x] GQ signer and verifier
  - [x] [GQ JWS Support](https://github.com/openpubkey/openpubkey/pull/14)
- [ ] Examples
  - [ ] Google OP x509 signing example
  - [ ] Github Actions signing example
- [ ] [Cryptography review and remediation](https://github.com/openpubkey/openpubkey/issues/11)
- [ ] Opensource project must haves
  - [ ] Github actions to run unittest
  - [x] Linter enforcement
  - [ ] Code of conduct
  - [ ] Security.md
  - [ ] Developer.md
  - [ ] PR template

Phase 2:

- [ ] Additional Signers (TBD)

# How to use this library

To interact with OpenPubkey as a signer use the OpkClient struct.

<!-- # How it works

... -->

# Further reading

- [OpenPubkey: Augmenting OpenID Connect with User held Signing Keys](https://eprint.iacr.org/2023/296)

- [BastionZero’s OpenPubkey: A new approach to cryptographic signatures](https://www.bastionzero.com/blog/bastionzeros-openpubkey-why-i-think-it-is-the-most-important-security-research-ive-done)

- [Reducing Trust in Automated Certificate Authorities via Proofs-of-Authentication](https://arxiv.org/abs/2307.08201)

- [Guillou and Quisquater, A “Paradoxical” Indentity-Based Signature Scheme Resulting from Zero-Knowledge, Crypto 1988](https://link.springer.com/content/pdf/10.1007/0-387-34799-2_16.pdf)

- [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
- 