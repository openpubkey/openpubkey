# PK Token

OpenPubkey works by binding an public key to an identity described in an ID Token. To provide verifiers with all the needed information to verify this binding between identity and public key, we extend the ID Token with additional signatures and include this additional information in the added signatures. This is possible because ID Tokens are JSON Web Signatures (JWS) and JWS can support more than one signature. We call an ID Token extended in this fashion a PK Token (Public Key Token).

In this document we provide background on JSON Web Signatures (JWS) and ID Tokens and describe our different types of PK Tokens using examples.

## JSON Web Signatures (JWS) and JSON Web Tokens (JWT)

A [JWS (JSON Web Signature)](https://www.rfc-editor.org/rfc/rfc7515.html) is a signed message format. The message which is signed is called the payload. It supports 1 or more signatures. Each signature has a protected header, denoted as `protected` in JSON, which specifies metadata about the signature such as the signing algorithm (`alg`) and the key ID (`kid`) of the public key which should be used to verify the signature.

```json
{"payload": "message payload"
"signatures": [
  {
    "protected": {"alg": "RS256", "kid": "1234"},
    "signature": "signature-1"
  },
  {
    "protected": {"alg": "RS256", "kid": "5678"},
    "signature": "signature-2"
  },
  {
    "protected": {"alg": "RS256", "kid": "9123"},
    "signature": "signature-3"
  },
]}
```


Note that each signature in a JWS signs the payload and the protected header associated with that signature. All signatures sign the same payload; no signature signs another signature's protected header. In the example above RSA signature-2 is computed as  `RSA-SIGN(SK, ("message payload", {"alg": "RS256", "kid": "1234"}))`.

[JWT (JSON Web Token)](https://datatracker.ietf.org/doc/html/rfc7519) is a type of JWS used by one party, the issuer, to make claims another parties, the subject. The issuer includes their identity in the JWT using the `iss` claim. JWTs are defined as having only one signature, the signature of the issuer.

```json
"payload": {
  "iss": "https://jwt.example.com",
  "claim-1": "value-1",
  "claim-2": "value-2",
} 
"signatures": [
  {
    "protected": {"alg": "RS256", "kid": "1234"},
    "signature": "RSA signature-1"
  }
]
```

An ID Token is a type of JWT used in the OpenID Connect protocol by an OP (OpenID Provider) to make claims about an identity. An OP is simply what an IDP (Identity Provider) is called in OpenID Connect. Here is an example ID Token issued by "https://issuer.example.com" making claims about the subject "alice@example.com".

```JSON
{"payload":{
    "iss": "https://issuer.example.com",
    "aud": "audience-id",
    "sub": "104852002444754136271",
    "nonce": "fsTLlOIUqtJHomMB2t6HymoAqJi-wORIFtg3y8c65VY",
    "email": "alice@example.com"},
"signatures":[
  {
    "protected":{
      "alg": "RS256",
      "kid": "1234",
      "typ": "JWT"
    },
    "signature": "GqjU... (Issuer's signature)"
  }
]}
```

## PK Tokens

Now let's look at what happens when we extend this ID Token with additional signatures to create a PK Token. A PK Token will have at least have at least two signatures but can have more than two signatures.

```JSON
{"payload":{
    "iss": "https://issuer.example.com",
    "aud": "audience-id",
    "sub": "104852002444754136271",
    "nonce": "fsTLlOIUqtJHomMB2t6HymoAqJi-wORIFtg3y8c65VY",
    "email": "alice@example.com"},
"signatures":[
  {
    "protected":{
      "alg": "RS256",
      "kid": "1234",
      "typ": "JWT"
    },
    "signature": "GqjU... (Issuer's signature)"
  },
  {
    "protected": {
    "alg": "ES256",
    "typ": "CIC",
    "rz": "b9522b5c4cff90687ec6787236184659e077a619b82827227114108440fec26a",
    "upk": {
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": "cvqyUFNs1OUdRcDSmzJfS7ynuTHAjlDqoeinCZy_r1Q",
        "y": "Whl5jJUIz7ujFvlB5Hzhaz6DIlpyWQmIIA3J7VMj53o"
    }},
    "signature":"TBPZa...  (Clients's signature)"
  },
  {
    "protected":{
      "alg": "ES256",
      "auth_time": 1722113589,
      "eid": "6e38311685191ac62e8647e8263f98ad1d57752dab14a5b83298c0d70fe19942",
      "exp": 1722117189,
      "iat": 1722113589,
      "iss": "https://mfa-cosigner.openpubkey.com",
      "kid": "7890",
      "nonce": "a958dd0574393cc3fa0e423b4d060009b44ecc710d1ff7af0e4cc74b9fc99649",
      "ruri": "http://localhost:54435/mfacallback",
      "typ": "COS"
    },
    "signature":"hiyDh... (Cosigner's signature)"
  }
]}
```

### Protected Header Claims

[Protected headers in JWS](https://datatracker.ietf.org/doc/html/rfc7515#section-2) were introduced as a place to put signature header parameters, that is metadata about the signature necessary to verify the signature. Parameters such as `alg` specify the algorithm used to generate the signature or `kid` which is the Key ID that can be used to look up the public key to verify the signature. While we still use protected headers for this purpose in PK Tokens we also now use protected headers to store claims the signature is making about the identity.

In an ID Token or JWT, the claims the issuer is making are set in the payload. However this isn't sufficient for OpenPubkey, parties may wish to add additional claims along with their signature. For instance a signing party who independently authenticated the identity, might want to add an additional claim specifying the time at which this independent authentication took place. This party can not update the payload without breaking the signature that already signed the payload.

Our solution is to allow signing parties to specify additional claims in the protected header they set. This enables the signing party to add claims without requiring any new signatures from any other parties.

#### Required Claims

In PK Tokens the following claims are required and assumed to exist `alg`, `typ` and `kid`. The one exception is that since OP (OpenID Providers) generate the OP signature and OP protected header, they may not include `typ` or `kid` and we can't make them. However in all other signatures in a PK Token, OpenPubkey enforces that `alg`, `typ` and `kid` are specified.

#### Custom Claims

OpenPubkey allows third party to extend OpenPubkey and specify any custom claims in the protected header of PK Token signatures. The only rule is that custom claims can not use the keys: `alg`, `typ` and `kid`.

For instance Docker uses the custom claim `att` in the CIC protected header to ensure [a particular PK Token can only be used to verify a particular signature.](https://github.com/openpubkey/openpubkey/issues/33)

### Signature Type (typ)

We use the `typ` value in the protected header of each signature to distinguish the "type" of signature it is. This is already an established pattern with OpenID Provider signatures in ID Tokens having `typ=JWT`.
The other signatures in a PK Token are always generated by OpenPubkey and have `typ` set correctly for that signature.
As shown, we have three signatures:

### Types of Signatures in a PK Token

1. ***OP signature (`typ=JWT`):*** The first signature is the signature of the party that issued the ID Token, that is the signature of the OpenID provider. The OP's signature is required.
2. ***CIC (Client-Instance Claims) signature (`typ=CIC`):*** The second signature  is generated by the identity's client. The CIC signature is required.
3. ***Cosigner signature( `typ=COS`):*** The third signature  is the COS (Cosigner) signature. The Cosigner is a third party who has independently authenticated the identity. It exists to remove the OpenID Provider as a single point of compromise. The COS signature is optional and not every PK Token will have one. It is up to OpenPubkey verifiers to decide if they require a Cosigner signature or not.

#### OP (OpenID Provider) Signature

This is signature of the OpenID Provider that created the payload and signed it to create the ID Token. This signature is responsible for binding the identity claims in the payload to that identity's public key.

Typically this signature among with the payload is simply the ID Token. For some more advanced forms of PK Tokens such as GQ or ZK PK Tokens, we transform this signature and protected header while still maintaining the ability of verifiers to cryptographically check that the payload was issued by a particular OP. In these cases, you can no longer recover the ID Token from the PK Token, but even when we alter the OP Signature and protected header in this way, we don't break the cryptographic binding between payload and OpenID Provider that the signature provides.

Some OpenID Providers do not specify `typ`. To get around this we classify a signature as being from the OpenID Provider if either `typ=JWT` or `typ` is not defined.

#### CIC (Client-Instance Claims) Signature

The Client-Instance is the identity's OpenPubkey client. The CIC are the claims made about the identity by this client. The CIC signature performs two functions. First, it provides the needed data to allow verifiers to check that an ID Token has a binding to the user's public key. Second, it functions as a Proof-of-Possession showing that the identity's knows the signing key associated with the public key `upk`. This Proof-of-Possession prevents rogue key attacks in which a attackers associates their identity with another identity's public key and the attempts to claim they produced signatures produced by the other identity.

The CIC always contains these claims (and may contain other claims)

* `alg` - the algorithm of both the signature and the identity's public key.
* `upk` - the JWK (JSON Web Key) of the identity's public key. UPK stands for User's Public Key.
* `typ` - this value is always set to `CIC` to identify this protected header and signature pair as the CIC.

#### COS (Cosigner) Signature

The Cosigner is a third party who issues this signature if they are able to authenticate the identity. This authentication must be independent of the OpenID Provider's authentication. The purpose of the Cosigner is enable OpenPubkey to maintain security even if the OpenID Provider becomes maliciously.

Cosigning is an optional feature of OpenPubkey and OpenPubkey can be used without a cosigner. In such cases there is no COS signature.

The claims in a COS signature are:

* auth_time - When the cosigner authenticated the identity (unix epoch)
* eid - Authentication id.
* exp - Expiration time of cosigner signature  (unix epoch)
* iat - Issued at time of this signature. May differ from auth_time because of refresh. (unix epoch)
* iss - Issuer, the cosigner which issued this signature. This can be used to look up the cosigner JWKS URI to get this cosigner's public keys.
* nonce - Nonce supplied by the user. This should not match the nonce in the payload.
* ruri - Redirect URI that was used by the cosigner to send the client-instance the auth_code.

## Types of PK Tokens

In this section we use actual PK Tokens from to illustrate the types of PK Tokens.

OpenPubkey has a number of different types of PK Tokens. A full list includes:

| PK Token Type                 | OP Support               | Identity type |
| -------------                 |--------------            | ------------- |
| Nonce-Commitment              | Google, Azure, Okta      | Human         |
| GQ Signed Nonce-Commitment     | Google, Azure, Okta      | Human         |
| GQ Signed Audience-Commitment | Github, GCP              | Machine       |
| GQ-Commitment                      | Gitlab-CI                | Machine       |
| ZKP PK Tokens           | Google, Azure, Okta, Github, Gitlab-CI | Human+Machine|

### Nonce-Commitment PK Token - Google Example

This PK Token is an Google issued ID Token that has been extended with two signatures.

```JSON
{"payload":{
    "iss": "https://accounts.google.com",
    "azp": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "aud": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "sub": "104852002444754136271",
    "email": "anon.author.aardvark@gmail.com",
    "email_verified": true,
    "at_hash": "4yj5j65fR9VuqPDZYJTadA",
    "nonce": "fsTLlOIUqtJHomMB2t6HymoAqJi-wORIFtg3y8c65VY",
    "name": "Anonymous Author",
    "picture": "https://lh3.googleusercontent.com/a/ACg8ocIdbWtaAGFsizjWVh7Q6C-XDBuSoUOpf7d7nGqgNQ-9yHmenNA=s96-c",
    "given_name": "Anonymous",
    "family_name": "Author",
    "iat": 1722113587,
    "exp": 1722117187},
"signatures":[
  {
    "protected":{
      "alg": "RS256",
      "kid": "e26d917b1fe8de13382aa7cc9a1d6e93262f33e2",
      "typ": "JWT"
    },
    "signature":"Zbli..."
  },
  {
    "protected": {
    "alg": "ES256",
    "rz": "b9522b5c4cff90687ec6787236184659e077a619b82827227114108440fec26a",
    "typ": "CIC",
    "upk": {
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": "cvqyUFNs1OUdRcDSmzJfS7ynuTHAjlDqoeinCZy_r1Q",
        "y": "Whl5jJUIz7ujFvlB5Hzhaz6DIlpyWQmIIA3J7VMj53o"
    }},
    "signature":"TBPZa..."
  },
  {
    "protected":{
      "alg": "ES256",
      "auth_time": 1722113589,
      "eid": "6e38311685191ac62e8647e8263f98ad1d57752dab14a5b83298c0d70fe19942",
      "exp": 1722117189,
      "iat": 1722113589,
      "iss": "http://localhost:3003",
      "kid": "b5eed4577745938ac3ed505229ed8b845bdbce5bd2a0820a2e5d405ceb836303",
      "nonce": "a958dd0574393cc3fa0e423b4d060009b44ecc710d1ff7af0e4cc74b9fc99649",
      "ruri": "http://mfa-cosigner.example.com:54435/mfacallback",
      "typ": "COS"
    },
    "signature":"hiyDh..."
  }
]}
```

#### Nonce-Commitment

Our example PK Token uses a *nonce-commitment* to bind the identity's public key `upk` to the ID Token. That is, the `nonce` value in the payload commits to the user's public key. By commits we mean that the nonce has been set to be the hash of the identity's public key and associated metadata.

```ascii
nonce = SHA3(
  Base64({"alg":"ES256",   
    "rz":"301a510ffd19b4888cdec7b9dda62192cfa06d85936cabb1afdd1a015ad44137",
    "typ":"CIC",
    "upk":{"alg":"ES256","crv":"P-256","kty":"EC" "x":"8JAMvpmdrhiKJi9A79LHPj5CPKlyztHHEkCr6tntyq8", "y":"jRqKcX8wIU24ffb5GI6z9XlePqlP1DOxvlEwvp0wC5s"}
  }))
```

Notice that the value which is hashed to generate the `nonce` value in the payload is exactly the value given in the protected header of the CIC. Put another way, the CIC allows the verifier to open the commitment to the identity's commitment in the nonce. The value `rz` is randomly chosen by the identity's client-instance to ensure that each time a nonce is generated, it is always unique and random. The value `upk` is the identity's public key.

#### MFA Cosigner Signature

We have included in an Cosigner signature in this example to show what it looks like. Given that the Cosigner signature does not not differ much between examples we have omitted it from the other examples. Note that PK Tokens can function without a Cosigner signature, it is a part of the protocol that a verifier can choose to require or not require.

### GQ Signed Nonce-Commitment PK Tokens - Google Example

This PK Token is for the same Google account as the prior example including the same use of the nonce-commitment, the only difference is that we have replaced Google's RSA signature and protected header with a GQ Signature.

```JSON
{
  "payload": {
    "iss": "https://accounts.google.com",
    "azp": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "aud": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "sub": "104852002444754136271",
    "email": "anon.author.aardvark@gmail.com",
    "email_verified": true,
    "at_hash": "7y8qnEw17J6BDoqvz6ydbg",
    "nonce": "8IpXCsOcYBGcCJmXJMFOpBjz4-kPXwDhYi3hm_DFM_U",
    "name": "Anonymous Author",
    "picture": "https://lh3.googleusercontent.com/a/ACg8ocIdbWtaAGFsizjWVh7Q6C-XDBuSoUOpf7d7nGqgNQ-9yHmenNA=s96-c",
    "given_name": "Anonymous",
    "family_name": "Author",
    "iat": 1722717291,
    "exp": 1722720891
  },
  "signatures": [
    {
      "protected": {
      "alg": "GQ256",
      "jkt": "w0bhEOa9d4qxGtKLGhwySJ2VZtRxPA-0abeIC9C-zPQ",
      "kid": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyNmQ5MTdiMWZlOGRlMTMzODJhYTdjYzlhMWQ2ZTkzMjYyZjMzZTIiLCJ0eXAiOiJKV1QifQ",
      "typ": "JWT"
      },
      "signature": "hAo4...(5504 base64 characters)"
    },
    {
      "protected":       {
      "alg": "ES256",
      "extra": "yes",
      "rz": "656f65b99da5d649ea315a52343add3642f14c7ff8d4ebce8ee33a2f4a4b41e0",
      "typ": "CIC",
      "upk": {
          "alg": "ES256",
          "crv": "P-256",
          "kty": "EC",
          "x": "PnzpEjQZ7bsCl2ZExs7dbFQlVzggv-_t50QuzZZWcoc",
          "y": "1Z-xC6JZL2eAO57ovFJCstnBcMsOiqsGF1NJLyqq1F4"
      }
      },
      "signature": "dsWL..."
    }
  ]
}
```

#### GQ Signatures

GQ (Guillou and Quisquater) signatures were invented in the paper ['A “Paradoxical” Indentity-Based Signature Scheme Resulting from Zero-Knowledge' (1988).](https://link.springer.com/content/pdf/10.1007/0-387-34799-2_16.pdf) GQ signatures are standardized in  GQ1 in [ISO/IEC 14888-2:2008](https://www.iso.org/standard/44227.html). Our GQ signatures are based on this standard but we have increased the security parameter to 256-bits.

A GQ signature is a a [Proof of Knowledge (PoK)](https://en.wikipedia.org/wiki/Proof_of_knowledge) of an RSA signature that keeps the RSA signature secret. It provides the same guarantee that the ID Token was signed by OpenID Provider, but it keeps the original signature secret, preventing the ID Token in the PK Token from being used an ID Token. This works because an OpenID Connect service are written to expect the RSA signature and so will rejected an ID Token that has a GQ signature instead.

Currently, an OpenPubkey token contains the ID Token from the OpenID Provider. If the PK Token was published publicly anyone who sees it could extract the ID Token including the signature issued by OpenID provider from the PK Token and then attempt to replay this ID Token to authenticate as the subject (remember ID Tokens are bearer authentication secrets). A correctly configured service would reject such a replayed ID Token because the audience value in the ID Token would not match the audience that the service expects. This is because ID Tokens issued use in PK Tokens will have a different audience that ID Token issued for use in that service. Unfortunately, a common misconfiguration is that services do not check the audience claim in the ID Token. To prevent such replay attacks in both OpenPubkey we use GQ signatures when a PK Token will be publicly posted.

Note that in cases where a PK Token mere used to authenticate to a server and is not made publicly available, no GQ signature is needed. For instance when OpenPubkey is used in SSH, SSH3, TLS and web authentication we do not need to use GQ signatures, but when OpenPubkey is used to for software artifact signing where the signatures and PK Tokens will be posted to a public ledger, then GQ signatures or Zero Knowledge Proofs should be used.

#### GQ Signature Protected Header

When we replace an RSA signature in a PK Token with a GQ signature, we also replace the protected header of the RSA signature. GQ signature's not only provide a Proof-of-Knowledge of the original RSA Signature, but they also enable anyone who knows the original RSA signature to sign a message using the RSA signature as the signing key. Using this property the GQ signature also acts a signature, signing the payload and the new protected header using the original RSA signature as the signing secret.

The required claims in a GQ signature protected header are:

* **alg** - To signal that the GQ protected header is for a GQ signature we set `alg=GQ256`.
* **kid** -  We set the kid (Key ID) of the new GQ protected to the Base64 encoding of the original RSA protected header `"kid": Base64({"alg":"RS256","kid":"e26d917b1fe8de13382aa7cc9a1d6e93262f33e2","typ":"JWT"})`. This is required because verifying the GQ signature requires the original protected header of the RSA signature.
* **jtk** - To ensure we can always lookup and find the correct public key to verify a GQ signed ID Token, we record the `jkt` (JSON Key Thumbprint) of the OP's public key in the GQ signature's protected header. The original OP's public key for the RSA signature is needed to verify the GQ signature. This is needed because OP (OpenID Provider) are not required to set a `kid` (Key ID) or use a unique `kid` for the public keys they in their JWKS. While it is extremely rare for an OP to not use an kid or to recycle a kid, such behavior is standards compliant and we must ensure we can handle this behavior and uniquely identify the OP public key used to verify the signature.
* **typ** - The typ (type) is always `typ=JWT` to signal is the OP's signature.

#### GQ Signing

We sign the payload and the GQ protected header using the RSA signature as the signing key.

For the complete details on the GQ signing see our package [gq.SignJWT](https://github.com/openpubkey/openpubkey/blob/main/gq/sign.go#L108)

```golang
origHeaders, payload, signature, err := jws.SplitCompact(jwt)
if err != nil {
  return nil, err
}

signingPayload := util.JoinJWTSegments(origHeaders, payload)

headers := jws.NewHeaders()
err = headers.Set(jws.AlgorithmKey, GQ256)
if err != nil {
  return nil, err
}
err = headers.Set(jws.TypeKey, "JWT")
if err != nil {
  return nil, err
}
err = headers.Set(jws.KeyIDKey, string(origHeaders))
```

### GQ Signed Audience-bound PK Tokens - GitHub Example

Audience-bound PK Tokens are very similar to Nonce-Bound PK Tokens. The main difference is that instead of committing to the CIC in the `nonce` claim, we commit to the CIC in the `aud` (audience) claim.

```JSON
{"payload":{
    "jti": "d41b4ff2-6f05-41ce-98e8-f0c06e05902f",
    "sub": "repo:openpubkey/gha-test:ref:refs/heads/main",
    "aud": "LEQE668yEBBpVxKfi4SvIkl8wFxn55TdzNF79aEomIA",
    "ref": "refs/heads/main",
    "sha": "6b906a4153c61a2486973a1347db8300dc9ce3ee",
    "repository": "openpubkey/gha-test",
    "repository_owner": "openpubkey",
    "repository_owner_id": "145685596",
    "run_id": "10133323083",
    "run_number": "38",
    "run_attempt": "1",
    "repository_visibility": "public",
    "repository_id": "771245825",
    "actor_id": "274814",
    "actor": "EthanHeilman",
    "workflow": "Go Checks",
    "head_ref": "",
    "base_ref": "",
    "event_name": "push",
    "ref_protected": "false",
    "ref_type": "branch",
    "workflow_ref": "openpubkey/gha-test/.github/workflows/test.yml@refs/heads/main",
    "workflow_sha": "6b906a4153c61a2486973a1347db8300dc9ce3ee",
    "job_workflow_ref": "openpubkey/gha-test/.github/workflows/test.yml@refs/heads/main",
    "job_workflow_sha": "6b906a4153c61a2486973a1347db8300dc9ce3ee",
    "runner_environment": "github-hosted",
    "iss": "https://token.actions.githubusercontent.com",
    "nbf": 1722185193,
    "exp": 1722186093,
    "iat": 1722185793}
"signatures":[
  {
    "protected":{
    "alg": "GQ256",
    "jkt": "UJCvHZiaJcaQDc2tJbP_kgtgxB-OcKd1lwD76M3riUY",
    "kid": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ikh5cTROQVRBanNucUM3bWRydEFoaHJDUjJfUSIsImtpZCI6IjFGMkFCODM0MDRDMDhFQzlFQTBCQjk5REFFRDAyMTg2QjA5MURCRjQifQ",
    "typ": "JWT"},
    "signature":"h4lbgJd... (5504 base64 characters)"
  },
  {
    "protected": {
    "alg": "ES256",
    "rz": "bca0353ea63adbfce72032ab7d8fb7940def3488ca0765546a89d46760113c70",
    "typ": "CIC",
    "upk": {
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": "5BP8B8bXgf0OFxHLJS5LSFlPOsfdIvf2tJU_3mwTGNE",
        "y": "7KzWJi88qdZOI_j-kUG2aPjkzEA7IGMXFp1f-jdt28I"
    }},
    "signature":"5dfaFj..."
  }
]}
```

#### Audience-Commitment

Machine identity ID Token issuance flows typically allow the identity requesting the ID Token to specify any value for the audience `aud`. Most machine identity flows do not use a `nonce`. To support OpenPubkey we use the `aud` in exactly the same way as the `nonce` commitment:

```ascii
nonce = SHA3(
  BASE64URL({"alg": "ES256",
    "rz": "bca0353ea63adbfce72032ab7d8fb7940def3488ca0765546a89d46760113c70",
    "typ": "CIC",
    "upk": {
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": "5BP8B8bXgf0OFxHLJS5LSFlPOsfdIvf2tJU_3mwTGNE",
        "y": "7KzWJi88qdZOI_j-kUG2aPjkzEA7IGMXFp1f-jdt28I"
    }}))
```

User identity ID Token issuance flows set the `aud` to a unique identifier to scope the ID Token to a particular service or OIDC client. This is done, among other reasons to prevent a malicious service from replaying the ID Tokens it receives from users to impersonate those users to a another service. Allowing the requesting party to specify the `aud` as is done in machine identity would be insecure for user identity. However it is both secure and the primary pattern in machine identity flows.

#### GQ Signatures Are Required For Aud-Commitment PK Tokens

The main use case of machine identity audience-commitment PK Tokens is to create publicly published signatures. As in such cases GQ signatures or ZK proofs should always be used, in such cases we require the use of GQ signatures. This eliminates the risks of accidental misconfigurations where a GQ signature should be used but is not used.

### GQ-Bound PK Tokens (Gitlab-CI Example)

GQ-bound PK Tokens are designed for the case where neither a nonce-commitment or an audience-commitment are possible. Instead the GQ signature itself functions as the binding between the identity's public key (and CIC protected header) and the ID Token. So far we have only encountered one OP which can't support a nonce-commitment or an aud-commitment: gitlab-CI.

**Critical:** GQ-bound PK Tokens should only be used if an OP can not support nonce or audience-commitment PK Tokens. Never verify a GQ-bound PK Token unless the issuing OP only supports GQ-bound PK Tokens.

```JSON
{"payload":{
    "namespace_id": "84329880",
    "namespace_path": "openpubkey",
    "project_id": "56004559",
    "project_path": "openpubkey/gl-test",
    "user_id": "20558032",
    "user_login": "ethan.r.heilman",
    "user_email": "ethan.r.heilman@gmail.com",
    "user_access_level": "owner",
    "pipeline_id": "1391152406",
    "pipeline_source": "push",
    "job_id": "7446098166",
    "ref": "main",
    "ref_type": "branch",
    "ref_path": "refs/heads/main",
    "ref_protected": "true",
    "groups_direct": [
        "openpubkey"
    ],
    "runner_id": 12270852,
    "runner_environment": "gitlab-hosted",
    "sha": "9898863c7dcd844a6fc3c70191769b8d07567f57",
    "project_visibility": "public",
    "ci_config_ref_uri": "gitlab.com/openpubkey/gl-test//.gitlab-ci.yml@refs/heads/main",
    "ci_config_sha": "9898863c7dcd844a6fc3c70191769b8d07567f57",
    "jti": "3a8b958c-0117-4d61-8d84-90b186efc4e7",
    "iat": 1722189366,
    "nbf": 1722189361,
    "exp": 1722192966,
    "iss": "https://gitlab.com",
    "sub": "project_path:openpubkey/gl-test:ref_type:branch:ref:main",
    "aud": "OPENPUBKEY-PKTOKEN:1234"
},
"signatures":[
  {"protected":{
    "alg": "GQ256",
    "cic": "HVIF0m3zCwEsAZSFjTiyQFU982qF2UZXSpCE__F6IbE",
    "jkt": "4i3sFE7sxqNPOT7FdvcGA1ZVGGI_r-tsDXnEuYT4ZqE",
    "kid": "eyJraWQiOiI0aTNzRkU3c3hxTlBPVDdGZHZjR0ExWlZHR0lfci10c0RYbkV1WVQ0WnFFIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ",
    "typ": "JWT"
    },
  "signature":"18nN... (5504 base64 characters)"},
  {"protected":{
    "alg": "ES256",
    "rz": "600e69b29d89651591836d2598f6813a9a74b9e4124ddb81bee1561299c3590e",
    "typ": "CIC",
    "upk": {
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": "c63goURlnP5vbJbt4chtOHTHwg6Yvy4h6_aw3Zc2A5o",
        "y": "pfsH8--s5c8u4DxXto0sN4g5n6SjlXn1WjzaKXrr9b4"
    }
  },
  "signature":"xpt6tTEzAqPrXCzAL6UCdiIliPPejRmn2sW1_RSxCt3WUQN38s3z_MURF3Bd8mlncU1UhWwSMCAcwDijm-Hc6w"}
]}
```

#### GQ-binding

For Google and github we bind the CIC (Client Instance Claims) that contains the user's public key to the ID Token by putting a hashed commitment to the CIC in one of the claims of the ID Token. For Google we put the commitment in the nonce claim, for github we put the commitment in the audience (aud) claim. Gitlab-CI does not provide an nonce claim and does not allow a running job/workflow to specify the aud. While Gitlab does allow customizing the `aud` (audience) claim, this custom `aud` can not be set per request, but it is a fixed configuration value. As such we can not use audience-commitment PK Tokens for gitlab-CI. As gitlab-CI is for machine identity it does not support specifying a nonce and thus nonce-commitment PK Tokens are not available either.

GQ-binding solves this problem. Remember that with GQ signatures we use the OP's RSA signature on the ID Token to generate a GQ signature that signs both the payload and the GQ protected header. Then we delete the RSA signature. We can simply put the commitment to the identity's public key, a.k.a., the hash of the CIC, in the protected header of the GQ signed ID Token and then when we GQ sign the payload and the protected header the GQ signature will also sign this commitment. GQ-bound PK Tokens were introduced in PR: [Adds gitlab-ci OP using GQ commitment binding](https://github.com/openpubkey/openpubkey/pull/143).

In a GQ-bound PK Token the GQ protected header contains a claim `cic` where:

```ascii
cic = "SHA3(
  Base64({"alg": "ES256",
    "rz": "600e69b29d89651591836d2598f6813a9a74b9e4124ddb81bee1561299c3590e",
    "typ": "CIC",
    "upk": {
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": "c63goURlnP5vbJbt4chtOHTHwg6Yvy4h6_aw3Zc2A5o",
        "y": "pfsH8--s5c8u4DxXto0sN4g5n6SjlXn1WjzaKXrr9b4"
    }))
```

and the `aud` is always prefixed with `"OPENPUBKEY-PKTOKEN:"`. In the next section we explain why we require the audience to be prefixed this way.

#### Security

If configured correctly, GQ-bound PK Tokens offer the same security as nonce or audience bound PK Tokens. However GQ-bound PK Tokens do introduce a security risk from misconfiguration not present in the other cases. The risk is that if a GQ signature is not used and an attacker learns the ID Token, the attacker can compute the GQ signature from the RSA signature and insert their own public key.

We mitigate this risk of misconfiguration by:

* Requiring that PK Tokens employing GQ-bindings must have "OPENPUBKEY-PKTOKEN:" prefixed in the audience (`aud`) and that they are not considered valid PK Tokens if they do not have this prefix. This also prevents attacks in which an ID Token not intended for use as a PK Token is replayed in a PK Token. This rule does not apply to other types of PK Tokens.
* Ensuring that OpenPubkey clients always enforce the deletion of the RSA signature and only verify GQ-Bound PK Tokens for OPs like gitlab-CI which can not support nonce or audience commitments.

### ZK PK Tokens (Under development)

Similar to our approach of GQ Signatures, we can use ZKP (Zero Knowledge Proofs) to provide privacy-enhanced PK Tokens, and if needed use the ZKP as a binding mechanism. This is currently under discussion and development in the issue: [Proposed zklogin JWS](https://github.com/openpubkey/openpubkey/issues/101).

## PK Token Compact Serialization

[RFC-7515 Section 7.1](https://datatracker.ietf.org/doc/html/rfc7515#section-7.1) describes a compact serialization format for a JWS (JSON Web Signatures):

```ascii
BASE64URL(UTF8(JWS Protected Header)) || '.' ||
BASE64URL(JWS Payload) || '.' ||
BASE64URL(JWS Signature)
```

This compact representation does not support a JWS with more than one signature. As our PK Tokens have at least two signatures, we invented a compact serialization format for a JWS with more than one signature:

```ascii
BASE64URL(JWS Payload) || ':' ||
BASE64URL(UTF8(JWS Protected Header-OP)) || ':' ||
BASE64URL(UTF8(JWS Signature-OP)) || ':' ||
BASE64URL(UTF8(JWS Protected Header-CIC)) || ':' ||
BASE64URL(UTF8(JWS Signature-CIC)) || ':' ||
BASE64URL(UTF8(JWS Protected Header-COS)) || ':' ||
BASE64URL(UTF8(JWS Signature-COS)) || ':' ||
```

### Refreshed Payload and Signature

If this JWS represents a PK Token, then we may wish to refresh the ID Token. Refreshed ID Tokens typically do not contain the nonce in the initial ID Token. As such, for nonce-commitment PK Tokens, we need to transmit both the initial ID Token that has the nonce-commitment and the refreshed ID Token. To do this, we use the following compact representation:

```ascii
BASE64URL(JWS Payload) || ':' ||
BASE64URL(UTF8(JWS Protected Header-OP)) || ':' ||
BASE64URL(UTF8(JWS Signature-OP)) || ':' ||
BASE64URL(UTF8(JWS Protected Header-CIC)) || ':' ||
BASE64URL(UTF8(JWS Signature-CIC)) || ':' ||
BASE64URL(UTF8(JWS Protected Header-COS)) || ':' ||
BASE64URL(UTF8(JWS Signature-COS)) || '.' ||
BASE64URL(JWS Refreshed Payload) || '.' ||
BASE64URL(UTF8(JWS Refreshed Protected Header-OP)) || ',' ||
BASE64URL(UTF8(JWS Refreshed Signature-OP)) || '.' ||
```

## Our JWS conventions

In this section we discuss how the patterns we use for PK Tokens can be more broadedly used for JSON Web Signatures in general.

### The TYP pattern

Because a PK Token always has more two or more signatures we have been forced to think about how to effective organize a JWS (JSON Web Signatures) that two or more signatures. If a JWS has only one signature, then the `iss` (issuer) claim in the payload identifies the party that generated the signature. Once you have two or more signatures, how do you determine which signature matches the issuer? How do you determine the identity of signer that generated each signature? Determining what party generated what signature is important because we need to know where to find which public key to verify which signature.

One approach is to use signature order. For instance, we could specify that the first signature in the signatures list is the party that created the payload, the second signature is the cosigner, and so on. This approach has two major drawbacks. First, the order of the signatures is not signed or enforced in anyway. This means we can not assume that software and libraries won't reorder the signature list, breaking our ability to match signers to signatures. Second, this approach doesn't solve the problem of optional signers, who may or may not be required.

Instead we use the `typ` (type) key in the protected header to specify the different types of signatures. For instance if the protected header of a signature has `typ=COS` it is a cosigner signature. In JWT's it is customary to have a `typ=JWT`. We extend this so that signatures each signing party in a protocol specifies their role in the `typ` key of their protected header.

### Protected header claims

In a JWT the claims the issuer is making are set in the payload. However this isn't sufficient for OpenPubkey, parties may wish to add additional claims although with their signature. For instance a signing party who independently authenticated the identity, might want to add an additional claim specifying the time at which this independent authentication took place. This signature can not update the payload without breaking the signature that already signed the payload.

Our solution is to allow signing parties to specify additional claims in their protected header. This enables the party to add claims without requiring any new signatures from any other parties and also makes it clear who added these claims.

### Compact representations of a JWS with two or more signatures

[RFC-7515 Section 7.1](https://datatracker.ietf.org/doc/html/rfc7515#section-7.1) describes a compact serialization format for a JWS (JSON Web Signatures):

```ascii
BASE64URL(UTF8(JWS Protected Header)) || '.' ||
BASE64URL(JWS Payload) || '.' ||
BASE64URL(JWS Signature)
```

This compact representation does not support a JWS with more than one signature. As our PK Tokens have at least two signatures we invented a compact serialization format for a JWS with more than one signature:

```ascii
BASE64URL(JWS Payload) || ':' ||
BASE64URL(UTF8(JWS Protected Header-1)) || ':' ||
BASE64URL(UTF8(JWS Signature-1)) || ':' ||
BASE64URL(UTF8(JWS Protected Header-2)) || ':' ||
BASE64URL(UTF8(JWS Signature-2)) || ':' ||
...
BASE64URL(UTF8(JWS Protected Header-N)) || ':' ||
BASE64URL(UTF8(JWS Signature-N))
```

We use `:` as a delimiter rather than `.` to avoid confusion arising from a someone attempting to parse this as a standard single signature JWS.
