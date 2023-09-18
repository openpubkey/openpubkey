# OpenPubkey Reference Implementation
 
OpenPubkey adds user generated cryptographic signatures to OpenID Connect (OIDC) to enable users to sign messages or artifacts under their OpenID identity. Verifiers can check that these signatures are valid and associated with the signing OpenID identity. OpenPubkey does not add any new trusted parties beyond what is required for OpenID Connect and is fully compatible with existing OpenID Providers (Google, Azure/Microsoft, Okta, OneLogin, Keycloak) without any changes to the OpenID Provider.

This repo contains the current reference implementation of OpenPubkey. The reference implementation is a work in progress.

## Remaining Work

- [x] Signing example
- [ ] Common OpenPubkey client struct constructor that supports:
  - [ ] Github OpenID Provider (OP) with CIC in `aud` claim 
  - [ ] Azure OpenID Provider (OP)
  - [x] Google OpenID Provider (OP)
- [ ] GQ Signature Support
  - [ ] GQ signer and verifier
  - [ ] GQ JWS Support
- [ ] MFA Cosigner
  - [ ] MFA Cosigner example
  - [ ] Webauthn support

<!-- # How to use this library

...

# How it works

... -->

# Further reading

* [OpenPubkey: Augmenting OpenID Connect with User held Signing Keys](https://eprint.iacr.org/2023/296)

* [BastionZero’s OpenPubkey: A new approach to cryptographic signatures](https://www.bastionzero.com/blog/bastionzeros-openpubkey-why-i-think-it-is-the-most-important-security-research-ive-done)

* [Reducing Trust in Automated Certificate Authorities via Proofs-of-Authentication](https://arxiv.org/abs/2307.08201)

* [Guillou and Quisquater, A “Paradoxical” Indentity-Based Signature Scheme Resulting from Zero-Knowledge, Crypto 1988](https://link.springer.com/content/pdf/10.1007/0-387-34799-2_16.pdf) 
  
* [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)





