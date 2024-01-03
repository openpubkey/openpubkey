# OpenPubkey FAQ

## What is the difference between Sigstore and OpenPubkey?

OpenPubkey cannot really be compared to Sigstore. Sigstore is an end-to-end artifact signing solution, whereas OpenPubkey only binds public keys to OIDC identities for use as part of a larger signing solution. OpenPubkey is complementary to Sigstore, for example https://github.com/sigstore/fulcio/issues/1056.

As stated in the Related Work section of [the OpenPubkey paper](https://eprint.iacr.org/2023/296.pdf):

> Sigstore [31, 42] is an open source project for signing and verifying software artifacts. Users can sign under their OpenID Connect identity by using the sigstore Fulcio Certificate Authority [43] which uses an immutable log to store a mapping between an OpenID Connect ID Token and a short lived public key enabling parties to attribute signatures to identities. The Fulcio CA (Certificate Authority) is trusted to create this mapping between an ID Token and a public key. Using OpenPubkey this trust can be eliminated as OpenPubkey does not need a trusted party to map ID Tokens to public keys. The Fulcio CA could in turn help OpenPubkey by acting as a public OpenPubkey verifier and OP public key database.

## How does OpenPubkey ensure the nonce claim functions as nonce?

In the user-identity scenario the CIC (Client-Instance Claims) that contains the user's public key is hashed to the `nonce` claim in the ID Token. As OIDC requires that this field never repeat, OpenPubkey includes a random value, rz, in the CIC. Thus the hash of the CIC is always different and random. This maintains the required properties needed by the `nonce` claim in OIDC.

```golang
CIC = {'rz': crypto.random(), 'upk': <publickey>, 'alg': 'EC256'}
IDToken.nonce = SHA3(CIC)
```

## Does OpenPubkey present a privacy leak?

The PK Tokens used by OpenPubkey contain the claims from the OIDC ID Tokens of the signer, so making them public necessarily makes those claims public too. This may include elements of the signer’s identity such as the signer’s name or email addresses. It is up to users of OpenPubkey as to whether or not PK Tokens are made public.

In a public artifact signing scenario, it could be argued that these claims are the very claims upon which trust in the artifact should be based. However, some OIDC providers may include claims that the signer may wish to keep private. Users of OpenPubkey should consider carefully which OIDC providers to integrate with.

Most OpenID Providers (OP) allow you to scope the fields in the ID Tokens. For instance Google’s OP is by default scoped to only include userinfo-email claims: name, email address and icon. Given that the purpose of OpenPubkey is to enable parties to verify that a particular identity, e.g., ethan@bastion.com, produced a particular signature, if you do not want signatures to be associated with OIDC identities, then OpenPubkey may not be a good fit for your use case.

In other OpenPubkey deployment scenarios, such as those employed by BastionZero, the ID Tokens are not made publicly available.

## Can the ID Tokens contained in PK Token be replayed against OIDC Resource Providers?

Although not present in the original OpenPubkey paper, GQ signatures have now been integrated so that the OpenID Provider's (OP) signature can be stripped from the ID Token, and a proof of the OP's signature published in its place. This prevents the ID Token present in the PK Token from being used against any OIDC resource providers as the original signature has been removed without compromising any of the assurances that the original OP's signature provided.

We follow the approach specified in the paper: [Reducing Trust in Automated Certificate Authorities via Proofs-of-Authentication.](https://arxiv.org/abs/2307.08201).

For user-identity scenarios in which the PK Token is not made public, GQ signatures are not required. GQ Signatures are required for all current workload-identity use cases.

## Is it a problem that GQ Signatures only work with RSA signatures?

No because the OpenID Connect spec requires that all OPs (OpenID Providers) support RSA signatures.

> OPs MUST support signing ID Tokens with the RSA SHA-256 algorithm (an alg value of RS256), unless the OP only supports returning ID Tokens from the Token Endpoint (as is the case for the Authorization Code Flow) and only allows Clients to register specifying none as the requested ID Token signing algorithm.

From [OpenID Connect Core 1.0 - Section 15.1 Mandatory to Implement Features for All OpenID Providers](https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI).

## What about key management?

OpenPubkey assumes that all identity-held key pairs are ephemeral. You generate them as needed and delete them when you are done. No key management headaches.

## Should I be putting so much trust in a single OpenID Provider (OP)?

Currently anyone using OIDC is trusting a single OpenID Provider. OpenPubkey improves on this by providing an optional protocol for the user-identity scenario (interactive browser authentication with the OIDC provider) that removes the OP as a single point of compromise. This protocol independently  authenticates the user via MultiFactor Authentication (MFA) and then cosigns the user's PK Token. We call this the MFA-cosigner. If you desire to remove the OIDC Provider as a single point of compromise, consider requiring the use of an OpenPubkey MFA Cosigner. In the workload identity scenario, this is not supported.


## How does OpenPubkey handle OP (OpenID Provider) public key rollover?

OPs (OpenID Providers) issue ID Tokens by signing them. As required by OpenID Connect, OPs make their public keys avalaible at a JWKS (JSON Web Key Set) URI. Anyone can download the OP's public keys from the JWKS URI and verify an OP's signatures on an ID Token. The location of the JWKS URI is defined in the OPs ["/.well-known/openid-configuration"](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig). OPs rotate the public and signing keys they use for ID Tokens.

| OpenID Provider | .well-known/openid-configuration | JWKS URI | ~key rotation |
| -------------| ------------- | ------------- | ------------- |
| Google | https://accounts.google.com/.well-known/openid-configuration  | https://www.googleapis.com/oauth2/v3/certs |~14 days  |
| GitHub Actions | https://token.actions.githubusercontent.com/.well-known/openid-configuration | https://token.actions.githubusercontent.com/.well-known/jwks  |~84 days |

OpenPubkey relies on verifiers being able to check the OP's signature on the ID Token's contained in the PK Token. For many use cases, such as authenticating access to a server, a user can request a new ID Token after the OP rotates their keys. Such use cases do not require that PK Tokens remain verifiable beyond an OP key rotation.

However in the case in which the PK Token is being used to generate a public signature, it is necessary that verifiers can check the OP's signature on an ID Token even after the OP rotates their keys.

Below are a few of the proposed methods of ensuring the verifiability of signatures after the OP rotates signing keys. This is a non-exhaustive list.

### What about OP Public Keys via TUF (The Update Framework)?

Docker has proposed including a log of past OP public keys in the signed [TUF](https://theupdateframework.io/) state which is distributed with Docker Offical Images (DOIs). This seems like a natural fit for the Docker use case as DOIs already depend on the integrity of TUF.

### Can you tell me more about certificate transparency logs?

[Reducing Trust in Automated Certificate Authorities via
Proofs-of-Authentication](https://arxiv.org/pdf/2307.08201.pdf) proposes JWT Ledger, an approach that employs a certificate transparency log and audit mechanism to ensure ID Token's can continue to be verified even after the OP public keys are rotated off of the OP's JWKS URI. It states:

> To decrease the risk that the JWK Ledger will present false information to users, this ledger is backed by a transparency log.
> The pace of updates to this log should be relatively low, occurring
> only when the IdP rotates verification keys. Therefore, witnesses
> for the log can verify the current state of the key set on each update; they also check that no entries other than the given key set
> change have been added to the log. Clients can requires a quorum
> of witnesses on the JWK Ledger digest. When a client requests
> the key set for a given timestamp, the ledger serves two entries.
> The client checks that the timestamp of the first entry precedes
> the requested timestamp, that the timestamp of the second entry
> follows the requested timestamp, and that the entries are adjacent
> in the log. This convinces the client that the key set was valid at
> the given time.

This is similar to the approach sketched in _Appendix C: Archival Verification With Certificate Transparency Logs_ of the [OpenPubkey paper](https://eprint.iacr.org/2023/296.pdf).

### What about archival verifiers?

_Section 3.5.3: Archival Verification_ of the [OpenPubkey paper](https://eprint.iacr.org/2023/296.pdf) proposes archival verifiers which store a log of all past OP public keys. This approach is simple and does not require a transparency log. The main disadvantage is that you can't verify signatures from before the verifier started logging public keys.

## What are some other resources I can read to learn more about OpenPubkey?

We love this question! See our wiki for the [OpenPubkey Reading List](https://github.com/openpubkey/openpubkey/wiki/OpenPubkey-Reading-List). 
