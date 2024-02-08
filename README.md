# OpenPubkey

## Overview

OpenPubkey is a protocol for leveraging OpenID Providers (OPs) to bind identities to public keys. It adds user- or workload-generated public keys to [OpenID Connect (OIDC)](https://openid.net/developers/how-connect-works/), enabling identities to sign messages or artifacts under their OIDC identity.

We represent this binding as a PK Token. This token proves control of the OIDC identity and the associated private key at a specific time, as long as a verifier trusts the OP. Put another way, the PK Token provides the same assurances as a certificate issued by a Certificate Authority (CA) but critically, does not require adding a CA. Instead, the OP fulfills the role of the CA. This token can be distributed alongside signatures in the same way as a certificate.

OpenPubkey does not add any new trusted parties beyond what is required for OpenID Connect. It is fully compatible with existing OpenID Providers (Google, Azure/Microsoft, Okta, OneLogin, Keycloak) without any changes to the OpenID Provider.

Companies building on OpenPubkey include:

* [Docker, Inc](https://www.docker.com/) is building a public container registry where [OpenPubkey is used to sign Docker Official Images](https://www.docker.com/blog/signing-docker-official-images-using-openpubkey/).

* [BastionZero](https://www.bastionzero.com/) uses OpenPubkey to provide secure remote access to infrastructure.

OpenPubkey is a Linux Foundation project. It is open source and licensed under the Apache 2.0 license. This project presently provides an OpenPubkey client and verifier for creating and verifying PK Tokens from Google’s OP (for users) and GitHub’s OP (for workloads).

## Getting Started

Let's walk through a simple message signing example. For conciseness we omit the error handling code. The full code for this example can be found in [./examples/simple/example.go](./examples/simple/example.go).

We start by configuring the OP (OpenID Provider) our client and verifier will use. In this example we use Google as our OP.

```golang
op := &providers.GoogleOp{
  ClientID:     "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
  ClientSecret: "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", // The client secret is a public value
  Scopes:       []string{"openid profile email"},
  RedirURIPort: "3000",
  CallbackPath: "/login-callback",
  RedirectURI:  "http://localhost:3000/login-callback",
}
```

Next we create the OpenPubkey client and call `opkClient.Auth`:

```golang
opkClient, err := client.New(op)
pkt, err := opkClient.Auth(context.Background())
```

The function `opkClient.Auth` opens a browser window to the OP, Google in this case, which then prompts the user to authenticate their identity. If the user authenticates successfully the client will generate and return a PK Token, `pkt`.

The PK Token, `pkt`, along with the client's signing key can then be used to sign messages:

```golang
msg := []byte("All is discovered - flee at once")
signedMsg, err := pkt.NewSignedMessage(msg, opkClient.GetSigner())
```

To verify a signed message, we first verify that the PK Token `pkt` is issued by the OP (Google). Then we use the PK Token to verify the signed message.

```golang
err = client.VerifyPKToken(context.Background(), pkt, op)
msg, err := pkt.VerifySignedMessage(osm)
```

To run this example type: `go run .\examples\simple\example.go`.

This will open a browser window to Google. If you authenticate to Google successfully, you should see: `Verification successful: anon.author.aardvark@gmail.com (https://accounts.google.com) signed the message 'All is discovered - flee at once'` where `anon.author.aardvark@gmail.com` is your gmail address.

## How Does OpenPubkey Work?

OpenPubkey supports both workload identities and user identities. Let's look at how this works for users and then show how to extend OpenPubkey to workloads.

### OpenPubkey and User Identities

In OpenID Connect (OIDC) users authenticate to an OP (OpenID Provider), and the OP grants the user an ID Token. These ID Tokens are signed by the OP and contain claims made by the OP about the user such as the user's email address. Important to OpenPubkey is the `nonce` claim in the ID Token.

The `nonce` claim in the ID Token is a random value sent to the OP by the user's client during authentication with the OP. OpenPubkey follows the OpenID Connect authentication protocol with the OP, but it transmits a `nonce` value set to the cryptographic hash of both the user's public key and a random value so that the `nonce` is still cryptographically random, but any party that speaks OpenPubkey can check that ID Token contains the user's public key. From the perspective of the OP, the `nonce` looks just like a random value.

Let's look at an example where a user, Alice, leverages OpenPubkey to get her OpenID Provider, `google.com`, to bind her OIDC identity, `alice@acme.co`, to her public key `alice-pubkey`. To do this, Alice invokes her OpenPubkey client.

1. Alice's OpenPubkey client generates a fresh key pair for Alice, (`alice-pubkey`, `alice-signkey`), and a random value `rz`. The client then computes the `nonce=crypto.SHA3_256(upk=alice-pubkey, alg=ES256, rz=crypto.Rand())`. The value `alg` is set to the algorithm of Alice's key pair.
2. Alice's OpenPubkey client then initiates OIDC authentication flow with the OP, `google.com`, and sends the `nonce` to the OP.
3. The OP requests that Alice consents to issuing an ID Token and provides credentials (i.e., username and password) to authenticate to her OP (`Google`).
4. If Alice successfully authenticates, the OP builds an ID Token containing claims about Alice. Critically, this ID Token contains the `nonce` claim generated by Alice's client to commit to Alice's public key. The OP then signs this ID Token under its signing key and sends the ID Token to Alice.

The ID Token is a JSON Web Signature (JWS) and follows the structure shown below:

```
payload: {
  "iss": "https://accounts.google.com",
  "aud": "878305696756-6maur39hl2psmk23imilg8af815ih9oi.apps.googleusercontent.com",
  "sub": "123456789010",
  "email": "alice@acme.co",
  "nonce": 'crypto.SHA3_256(upk=alice-pubkey, alg=ES256, rz=crypto.Rand(), typ="CIC")',
  "name": "Alice Example",
  ...
} 
signatures: [
  {"protected": {"typ": "JWT", "alg": "RS256", "kid": "1234...", "typ": "JWT"},
  "signature": SIGN(google-signkey, (payload, signatures[0].protected))`
  },
]
```

At this point, Alice has an ID Token, signed by `google.com` (the OP). Anyone can download the OP's (`google.com`) public keys from `google.com`'s well-known JSON Web Key Set (JWKS) URI (https://www.googleapis.com/oauth2/v3/certs) and verify that this ID Token committing to Alice's public key was actually signed by `google.com`. If Alice reveals the values of `alice-pubkey`, `alg`, and `rz`, anyone can verify that the `nonce` in the ID Token is the hash of  `upk=alice-pubkey, alg=ES256, rz=crypto.Rand()`. Thus, Alice now has a ID Token signed by Google that cryptography binding her identity, `alice@acme.co`, to her public key, `alice-pubkey`.

### PK Tokens

A PK Token is simply an extension of the ID Token that bundles together the ID Token with values committed to in the ID Token `nonce`. Because ID Tokens are JSON Web Signatures (JWS) and a JWS can have more than one signature, we extend the ID Token into a PK Token by appending a second signature/protected header.

Alice simply sets the values she committed to in the `nonce` as a JWS protected header and signs the ID Token payload and this protected header under her signing key, `alice-signkey`. This signature acts as cryptographic proof that the user knows the secret signing key corresponding to the public key.

Notice the additional signature entry in the PK Token example below (as compared to the ID Token example above):

```
"payload": {
  "iss": "https://accounts.google.com",
  "aud": "878305696756-6maur39hl2psmk23imilg8af815ih9oi.apps.googleusercontent.com",
  "sub": "123456789010",
  "email": "alice@acme.co",
  "nonce": <crypto.SHA3_256(upk=alice-pubkey, alg=ES256, rz=crypto.Rand(), typ="CIC")>,
  "name": "Alice Example",
  ...
}
"signatures": [
  {"protected": {"alg": "RS256", "kid": "1234...", "typ": "JWT"},
  "signature": <SIGN(google-signkey, (payload, signatures[0].protected))>
  },
  {"protected": {"upk": alice-pubkey, "alg": "EC256", "rz": crypto.Rand(), "typ": "CIC"},
  "signature": <SIGN(alice-signkey, (payload, signatures[1].protected))>
  },
]
```

The PK Token can be presented to an OpenPubkey verifier, which uses OIDC to obtain the OP’s public key and verify the OP's signature in the ID Token. It then use the values in the protected header to extract the user's public key.

### OpenPubkey and Workload Identities

Just like OpenID Connect, OpenPubkey supports both user identities and workload identities.

The workload identity setting is very similar to the user identity setting with one major difference. Workload OpenID Providers, such as `github.com`, do not include a `nonce` claim in the ID Token. Unlike user identity providers, they allow the workload to specify an `aud`(audience) claim. Thus workload identity functions in a similar fashion as user identity but rather than commit to the public key in the `nonce`, we use the `aud` claim instead.

### GQ Signatures To Prevent Replay Attacks

Although not present in the original [OpenPubkey paper](https://eprint.iacr.org/2023/296), GQ signatures have now been integrated so that the OpenID Provider's (OP) signature can be stripped from the ID Token and a proof of the OP's signature published in its place. This prevents the ID Token within the PK Token from being used against any OIDC resource providers as the original signature has been removed without compromising any of the assurances that the original OP's signature provided.

We follow the approach specified in the following paper: [Reducing Trust in Automated Certificate Authorities via Proofs-of-Authentication](https://arxiv.org/abs/2307.08201).

For user-identity scenarios where the PK Token is not made public, GQ signatures are not required. GQ Signatures are required for all current workload-identity use cases.

## How To Use OpenPubkey

OpenPubkey is driven by its use cases. You can find all available use cases in the [examples folder](./examples/).

We expect this list to continue growing (and if you have an idea for an additional use case, please [file an issue](#file-an-issue), raise the idea in a [community meeting](#get-involved-with-our-community), or send a message in our [Slack channel](#join-our-slack)!

## How To Develop With OpenPubkey

As we work to get this repository ready for `v 1.0`, you can check out the [examples folder](./examples/) for more information about OpenPubkey's different use cases. In the meantime, we would love for the community to contribute more use cases. See [below](#get-involved-with-our-community) for guidance on joining our community.

## Governance and Contributing

### File An Issue

For feature requests, bug reports, technical questions and requests, please open an issue. We ask that you review [existing issues](https://github.com/openpubkey/openpubkey/issues) before filing a new one to ensure your issue has not already been addressed.

If you have found what you believe to be a security vulnerability, *DO NOT file an issue*. Instead, please follow our [security disclosure policy](./SECURITY.md).

### Code of Conduct

Before contributing to OpenPubkey, please review our [Code of Conduct](./CODE-OF-CONDUCT.md).

### Contribute To OpenPubkey

To learn more about how to contribute, see [CONTRIBUTING.md](./CONTRIBUTING.md).

### Get Involved With Our Community

To get involved with our community, see our [community repo](https://github.com/openpubkey/community/). You’ll find details such as when the next community and technical steering committee meetings are.

### Join Our Slack

Find us over on the [OpenSSF Slack](https://openssf.org/getinvolved/) in the `#openpubkey` channel.

### Report A Security Issue

To report a security issue, please follow our [security disclosure policy](./SECURITY.md).

## FAQ

See the [FAQ](./docs/FAQ.md) for answers to Frequently Asked Questions about OpenPubkey.
