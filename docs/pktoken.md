# PK Token

OpenPubkey works by binding an identity's public key to that identity's OpenID Connect ID Token. This binding allows verifiers that have learned the identity's public key to check if an ID Token is bound that particular public key. To provide verifiers with all the needed information, we add this additional information as additional signatures to the ID Token. This is possible because ID Tokens are JSON Web Signatures (JWS) and JWS can support more than one signature. We call this ID Token extended with additional signatures a PK Token (Public Key Token).

In this document we provide background on JSON Web Signatures (JWS), we breakdown how our PK Tokens function via an example PK Token and then finally provide a "Zoo" of all of the types of PK Tokens we use in OpenPubkey.

## JSON Web Signatures (JWS) and JSON Web Tokens (JWTs)

A [JWS (JSON Web Signature)](https://www.rfc-editor.org/rfc/rfc7515.html) is a signed message format. The message which is signed is called the payload. It supports 1 or more signatures. Each signature has a protected header (denoted as `protected` in JSON) which specifies metadata about the signature such as the algorithm (`alg`) that was used to verify it and the key ID (`kid`) of the public key which should be used to verify the signature.

```json
"payload": "message payload"
"signatures": [
  {
    "protected": {"alg": "RS256", "kid": "1234"},
    "signature": "signature-1"
  },
  {
    "protected": {"alg": "RS256", "kid": "5678",},
    "signature": "signature-2"
  },
  {
    "protected": {"alg": "RS256", "kid": "9123",},
    "signature": "signature-3"
  },
]
```

Note that each signature signs the payload and that signature's protected header. In the example above RSA signature-2 is computed as  `RSA-SIGN(SK, ("message payload", {"alg": "RS256", "kid": "1234"}))`. All signatures sign the same payload, no signature signs another signature's protected header.


[JWT (JSON Web Token)](https://datatracker.ietf.org/doc/html/rfc7519) is a type of JWS used by one party to make claims another set of parties. The party making the claims is called the issuer. The issuer includes their identity in the JWT using the `iss` claim. JWT are defined as having only one signature, the signature of the issuer.

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

An ID Token is a type of JWT used in the OpenID Connect protocol by an OpenID Provider to make claims about an identity. The party that issues the ID Token, i.e. the issuer, writes all the claims in the payload and identifies themselves using the claim `iss`. Here is an example ID Token:

```JSON
{"payload":{
    "iss": "https://issuer.example.com",
    "aud": "audience-id",
    "sub": "104852002444754136271",
    "email": "alice@example.com",
"signatures":[
  {
    "protected":{
      "alg": "RS256",
      "kid": "1234",
      "typ": "JWT"
    },
    "signature": "Issuer's signature"
  }
]}
```


## PK Tokens

Now let's look at what happens when we extend this ID Token with additional signatures to create a PK Token. The PK Token will have at least have at least two signatures but can have more than two signatures.

```JSON
{"payload":{
    "iss": "https://issuer.example.com",
    "aud": "audience-id",
    "sub": "104852002444754136271",
    "nonce": "fsTLlOIUqtJHomMB2t6HymoAqJi-wORIFtg3y8c65VY",
    "email": "alice@example.com",
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
      "iss": "htts://mfa-cosigner.openpubkey.com",
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

[Protected headers in JWS](https://datatracker.ietf.org/doc/html/rfc7515#section-2) were introduced as a place to put signature header parameters, that is metadata about the signature necessary to verify the signature. Parameters such as `alg` for the algorithm used to generate the signature or `kid` which is the Key ID that can be used to look up the public key to verify the signature. While we still use protected headers for this purpose we also now use protected headers to store claims the signature is making about the identity. Why is this needed?

In a ID Token or JWT the claims the issuer is making are set in the payload. However this isn't sufficient for OpenPubkey, parties may wish to add additional claims along with their signature. For instance a signing party who independently authenticated the identity, might want to add an additional claim specifying the time at which this independent authentication took place. This party can not update the payload without breaking the signature that already signed the payload.

Our solution is to allow signing parties to specify additional claims in their protected header such as the identity's public key (`upk`).This enables the signing party to add claims without requiring any new signatures from any other parties. The protected header in which the claims are made makes it clear who added these claims.


### Signature Type (typ)

We use the `typ` value in the protected header of each signature to distinguish the "type" of signature it is. This is already an established pattern with OpenID Provider signatures in ID Tokens having `typ=JWT`.
The other signatures in a PK Token are always generated by OpenPubkey and have `typ` set correctly for that signature.
As shown, we have three signatures:


### Types of Signatures in a PK Token

1. ***OP signature (`typ=JWT`):*** The first signature () is the signature of the party that issued the ID Token, that is the signature of the OpenID provider. The OP's signature is required.
2. ***CIC (Client-Instance Claims) signature (`typ=CIC`):*** The second signature  is generated by the identity's client. The CIC signature is required.
3. ***Cosigner signature( `typ=COS`):*** The third signature  is the COS (Cosigner) signature. The Cosigner is a third party who has independently authenticated the identity. It exists to remove the OpenID Provider as a single point of compromise. The COS signature is optional and not every PK Token will have one.

#### OP (OpenID Provider) Signature

This is signature of the OpenID Provider that created the payload and signed it to create the ID Token. This signature is responsible for binding the identity claims in the payload to that identity's public key.

Typically this signature plus the payload is simply the ID Token. However for some of those more advanced forms of PK Token's such as GQ or ZK PK Tokens we transform this signature and protected header while still maintaining the ability of verifiers to cryptographically check that the payload was issued by a particular OP. Or put another way, even when we alter the OP Signature, it is important that we don't break the cryptographic binding between payload and OpenID Provider that the signature provides.

Some OpenID Providers do not specify `typ`. Thus we classify a signature as being from the OpenID Provider if either `typ=JWT` or `typ` is not defined.

#### CIC (Client-Instance Claims) Signature

The Client-Instance is the identity's OpenPubkey client. The CIC are the claims made about the identity by this client. The CIC signature performs two functions. First, it provides the needed data to allow verifiers to check that an ID Token has a binding to the user's public key. Second, it functions as a Proof-of-Possession showing that the identity's knows the signing key associated for the public key `upk`. This Proof-of-Possession prevents rogue key attacks in which a attackers associates their identity with another identity's public key and the attempts to claim they produced signatures produced by the other identity.

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

* Nonce-bound PK Tokens
* Audience-bound PK Tokens
* Nonce-bound GQ PK Tokens
* Audience-bound GQ PK Tokens
* GQ-bound PK Tokens
* ZKP-bound PK Tokens

### Nonce-Commitment PK Token (Google)

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

```
nonce = SHA3(
  Base64({"alg":"ES256",   
    "rz":"301a510ffd19b4888cdec7b9dda62192cfa06d85936cabb1afdd1a015ad44137",
    "typ":"CIC",
    "upk":{"alg":"ES256","crv":"P-256","kty":"EC" "x":"8JAMvpmdrhiKJi9A79LHPj5CPKlyztHHEkCr6tntyq8", "y":"jRqKcX8wIU24ffb5GI6z9XlePqlP1DOxvlEwvp0wC5s"}
  }))
```

Notice that the value which is hashed to generate the `nonce` value in the payload is exactly the value given in the protected header of the CIC. Put another way, the CIC allows the verifier to open the commitment to the identity's commitment in the nonce. The value `rz` is randomly chosen by the identity's client-instance to ensure that each time a nonce is generated it is always unique and random. The value `upk` is the identity's public key.


### Nonce-bound (GQ) PK Tokens


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
refreshed ID Token eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyNmQ5MTdiMWZlOGRlMTMzODJhYTdjYzlhMWQ2ZTkzMjYyZjMzZTIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTIwMjg0OTk3NjgtY2U5anVjbGIzdnZja2gyM3I4M2Zqa212ZjFsdmpxMTguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTIwMjg0OTk3NjgtY2U5anVjbGIzdnZja2gyM3I4M2Zqa212ZjFsdmpxMTguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ4NTIwMDI0NDQ3NTQxMzYyNzEiLCJlbWFpbCI6ImFub24uYXV0aG9yLmFhcmR2YXJrQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiSDJmaWtZNEM4NjdPdnlBek5NN3NxdyIsIm5hbWUiOiJBbm9ueW1vdXMgQXV0aG9yIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0lkYld0YUFHRnNpempXVmg3UTZDLVhEQnVTb1VPcGY3ZDduR3FnTlEtOXlIbWVuTkE9czk2LWMiLCJnaXZlbl9uYW1lIjoiQW5vbnltb3VzIiwiZmFtaWx5X25hbWUiOiJBdXRob3IiLCJpYXQiOjE3MjI3MTcyOTQsImV4cCI6MTcyMjcyMDg5NH0.BxYzk2nuVcPZgwZSqPVE4ZeBzL-lpjXiqh3MZlOCQdkij_Q6iIkGtlAFE7FMSl9Xdeggtiy7yCJd4xxOcQOLG7CjkRNCh9xCRI5iPuL8g-1lrIx9YcZBl_D23rfiJQnXIKYQm4vsIQIH7HQujNxEwPyVxwO7LhRiLEgRK3zTErJ7AX7jx5mcmrMCSbQ6OQiDuc7TJf1KBc0pCmCYt7srBbCon7SKBAZ0QCm9VfRhJqmC6YLqWdZYL6Hfyio5y7P96SXW5Qs-ue4bR-l2L60nw2rQd4URVDDhJo5ILgAz5R_mBz9bAtpGT_gbV1BIcoJSBUxdsEWjFNmhNgVxpmHGEw
Compact 6994 eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTIwMjg0OTk3NjgtY2U5anVjbGIzdnZja2gyM3I4M2Zqa212ZjFsdmpxMTguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTIwMjg0OTk3NjgtY2U5anVjbGIzdnZja2gyM3I4M2Zqa212ZjFsdmpxMTguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ4NTIwMDI0NDQ3NTQxMzYyNzEiLCJlbWFpbCI6ImFub24uYXV0aG9yLmFhcmR2YXJrQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiN3k4cW5FdzE3SjZCRG9xdno2eWRiZyIsIm5vbmNlIjoiOElwWENzT2NZQkdjQ0ptWEpNRk9wQmp6NC1rUFh3RGhZaTNobV9ERk1fVSIsIm5hbWUiOiJBbm9ueW1vdXMgQXV0aG9yIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0lkYld0YUFHRnNpempXVmg3UTZDLVhEQnVTb1VPcGY3ZDduR3FnTlEtOXlIbWVuTkE9czk2LWMiLCJnaXZlbl9uYW1lIjoiQW5vbnltb3VzIiwiZmFtaWx5X25hbWUiOiJBdXRob3IiLCJpYXQiOjE3MjI3MTcyOTEsImV4cCI6MTcyMjcyMDg5MX0:eyJhbGciOiJHUTI1NiIsImprdCI6IncwYmhFT2E5ZDRxeEd0S0xHaHd5U0oyVlp0UnhQQS0wYWJlSUM5Qy16UFEiLCJraWQiOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SW1VeU5tUTVNVGRpTVdabE9HUmxNVE16T0RKaFlUZGpZemxoTVdRMlpUa3pNall5WmpNelpUSWlMQ0owZVhBaU9pSktWMVFpZlEiLCJ0eXAiOiJKV1QifQ:hAo4UuNJB2N7P7opamsY8WCOoPgJCtcgLNLwmbnjPeZ3_nlPSuS2UJgOlM-qoBZI1Wm6SG62bfH0qfjr9GLaC9h04-o6xgoYeE1lI2wl1q4IN7o9MauIvdltDvv8GFQCqtaSOP2PmHlfvzs0Ve_rwmAgpR4c_FBcHzal86G55o9YmHNrBfcjMjTaChxar98ve_IJoDYAnQoyF8MSYM09inR_FRUSyYPa8Z2y0mIdoPP70S03dU894oFbvwSzz1TuE8_Bv9dByxYZjfM5mCdufuI1wBqertRPy0Q5chj5RpRWaGp-10r4RPVnDsBSHdIz-tWCFlwqExmgJRfVimCBt8t2U4jPORxmN8mrqRMMQEIpGXg5KvJPmhTDX4VH9AskaPwAGnq4Xr4T9Au_HR7_FqUCpBpp04HeARrAGdUZbn3YAuWsbZgZ42qscdS_LCJ-MQKsYDpfZxZpL_E5Xr5eUt8353z67CqF3Lo71PKE2AOQA379KftxjY4Tys8XQWOpPA9qq4EqI2ltXX36qtAMF5arx89Ht_3f5mTJmDAF7qfBL12D-Aoow1mMhg_u3bb14JpCWSSDuQX6e0r2rpGQxJAvEcYdbqEGBd1keU4rgVjXIBcQFjVXDklno1tnDDk88SczUWfJ0eHh0PPz-BwW8Fn-51edRqcRzY37LrxCJaR9BG_eSfoITpoaVQX3usXSZFWyrj6KpFBVVjFda5HHU1RLPIuVg5ZhSkbRSu3iDOtdCP6VSVJWF7A6qh5zk5Hnu96DGGLr2tqId-XTRl4_VmBSc7cyRPkkSa0UFtzSnamnCWhzQXQBA9cebNdNvmSiceY4y9BlZ-dJOmZCPDb9DX5SQcUrCR38CyVJuU6fr2RNSurmE68wOCdRxVuMUOGPjM2mh2dJjAelda4IID1XA71yZnP0yt2Mq5C-cGesAdfqQfFjY0xPSsGbkKYTI2IvV1TEHZNn3vahqUv4Ke2SJN2im-2vFrxKupgSPIvxLalxxOyzeFQB1ueyHfatRgoHJUWbBYYcleiAuJ_bRcTkJEP8QwIGAimRKIRE7MS91O_MK8wQPtpKg21e1DkJ4moFIzSuWj5o1EzUD1ZXY0V2oSuOXg5pvVkMtmjPu1pk0IUuooitcBCbhMLTMiG6dve1OYlTHZTNwJPeOKGw-6R9VB-1HFpnRAruRCbzUIlHmsr7iLKi7yB2VtZFoiy2oDHYuOGssOMhRv3AYh9lU30avY_b6kckuV2hdqqwWFEAByM-4sXRUdg0NeT1kcZinyuEoieD4bm3peArZdJPFLZWtAKzqdjsFdbArT69tia4n8HW_mtHHv0N9KpYFib4_K79fgm6xF0m3_ZR7aPCNNtlj6AMFnIpmosanYgO5osK8BGaYxpzXyw7E-BTemmI3AAfCaZNmv7SaKSfmd0JKtH92yu-4wNQXnuBht-bMl53lEn8w5mwSaEYpftgChCRFDFimDaXyjCeTbvpx6tNPDgBPao2pQyMqt2332NNwwU9fQY0pDMYL3VS_xZnrwfLOx6mQ41nhhrJvuomA3IojP9vHI5J_dl2tx5nXnpx0ZVcikEGqAmxzlDp4GmtL1y026vZZOrErz7CXku3jV0g7BMeoBh0tKD4colAl-6HE13jK6V0qNC1OgI0gudeJqJq9l2Zj7rPxAtlzLDRUrmEiR_-ANUr6p22epF61BI1rHSt5aFS-jvcnTdmH6b8KY8uuVlz5Pq_zmknkoivbUIKCubFjV7nJmdhUnmC2ITjDy_hcpJCsOf8efF8W_1TO14FN2vNabk4eOhB_VKg2s9mXDZU_GP57ClhbwUV638Ujp9Ie8WLb9t2wcu0GQiiGO0KvgIAedeRCxeYVhauL0qCRZV0j-5lmUAgnxbjSZvs_KjT2B7NEVwH4DBB0fA8j1N76hNMbw_uCK4H3yotc8NR_iWvDZOUQZ1hp6Akc9KiW_eIBU8GC2QmyXCIg4AMAe3AHdq09-2KYfhcTM7KfvKrON0wJ_YY7OKxSrb8ZlspaJCy0ZP07TEPneKW1LpfXBQrxfV0o2Bqj5pOtTMT8Ak31_k-BwCIQ7sTsP-RuGy4Dk-jDjBLBb36ISrBRDEfOMZ8vR4KynjLirjKcAAXGWm2nXGtnJ4GbV-0ie6qswwkFU_oKAvAbjzSe0TYEm6kE3nqZ0950Yy11bK0m7udtOxT5gIJpkXljPn1edxMCcYKQAKA-hpnUQZeGQU20BzlUYITZDhqz680hjHd3WqIbQ2_dXsIcqgn6L2GrNRWiFvj4WqJMmuQ-tsZOwwKcc_pXfomYEDdxlDRqefFJbv7H4HQNNysfcg6GPEhlst6bm3uR9apEdGG4yFY6eM107EmUMbkQG6eMRWdQ5jAw5fXpS7XY7b0y7QKgCR1I9Plk4po8A7C3qJTEGILZqx_0HIYmQqEcNeoG555CbtjxjKofh1RtzuOFRyCSDy1p5pWqMPM_Soiz4P2vxixB5nU5Ua7w3H-GA5FvZ5ZqnUNOpaiemTid905ojxZafVY4bqwjZAiEyP7V8TAbsjv6nM0GgShsm9wkfARSQ_LXlz1E-Nh7mz7_aylUE-eVd2WJSUpwY9jtUV9BHW-vnz-0TEVZobwmWXI1QtLvHHi3zPFdUdEONv8PKIl-FflkShftWopemczam_o1n_yFF_5JhUM1OS6u8fuOeDjvNnU51Sy5jjMoq-py-Z_SgQRmhyIzqiGjNkK6mwrAm_6zq5GxNYRyCCcaUfbcw-98pXdnknNM65MjFhds4zXjCa2PNYZTtO6HwAktXAjAnvzFx1TjA_Byb9_dFmf5sfE4j7aoxsOxNqdlIigBU-u_pn8ySO8DYo49GSCwuxzz34rJm7uMMSNhjNiXbD2IIqegDViCJiODNbT-_1IkBJp4KnSQI8rQik8UYwyuNzRgCb2fuIFgchP-_I5zR81bMJB_c3WgmhitK4ANEu13yS-3BtrOGIeL4TeSJGckLFZG4j5aEJIR_LAQPiVpx6htYasAci-H-Ok18oRg7pd5bmWfkDy8XcZFAmImo8SuXSxm-zmR-joNTqt3VTJC820XmCCsxU152er6HVo3PLrCUp6lVcLeqZiw5RWIfWT9iv77GaiStGqpcfnmyK0ROv96_Q_caA81ZtZ_4h4rN0py4O2bC-f0m_hgTs2yV5gFqoGSvxz_gBtXX58XOMyRw8pOR1QWh4g_ZP9pw-Pv64zYkxd8bttZa4Ca9UhpJDEfjMAaKP3U5ECl1zCzvVGimAy02gG40F1f1wJ9yC7X763_iQcMQpTurJelDEaP_5vAcumbPU7eM4OW2vWNP0HgYe4RwWmw7YxKDI8C_ufdJo1WzQ-BtzIoKG9ikp2qsJX_DpuKrvaB2sJfiyl55MWC-_R_kC1SFNI3BndMwDe5s5xqPtffVN5jDAV2oDL_OilfwC_gHJoyzJz9hRIQ9icYb52LrvdAKgdjlrJQcNmoTnu_Dgy3bJ-6Y3bMjx7Y-vRv1V12mBW2WVG0TlMj76LdWGFJWUBW9tAPiaeZDQjeMG9REPILAe26z6XTVQ27d-Yzvp_ossmfSreSE2M18ti-H4iAvSmS6VM7P69bKO49vX_pDEl8sRvBEIiHAIZIFRwGDJ9w0DKJaWYo1YRUm6eV5DY_sqUK2BXP13Akde3tAiyH0j8ELKwqeexz2Hnv5AZA794v9SMZXHxo4D4FLEulqUdJJbAR1XuB5wXCL2Q82zmO2-dbMVEsLAhsjsutSVoQww7tX0DyLuyllleyhg7scs3yv2KguYis0vpFBWFMRqiC5qepzOvNmXRJilJC-a18fmNv6dfFkiaJT1Cb2-bJFc2JWDEsWnaAWtSpOLp7fbRlaouh3e05DEL1pv6x-35C9h8tw2Dg69QAyVCwZqbmcrCw7yGJucDfD6tTnB7GO7QRKK2TsYIxmV3Q-m86yEbbo9hTZXyufEpG-KovKPiUYUDEguHfzOkcDnnwLfAX-HriefGt3ZjD27nRn8NTTQxmze0wePNPy1r-PG-2XDU-dEPAO-eXj10-MZj3nmYyjzeoIXbabaB2v5OJiGMZGtc16INeCEG87jp-PEuTT4pa3TFEknv8kJDCXQhO6sCduv1NoHns3JhW_IqM-otH-9-34f_J-RyTjNmHXZuGDv-eWIjhlGRAfuKS7eCaMYdFrcIuhqPaX3BqA6p7nk5gO9AC6qQV79A-qCW-QNapPV7Kd5NVlJprwCCbC54W7JYCYkKjH2by-Q_1Lhk1kKNBKG2jbZjlE20QzcYjA-fRm_eXf8CpRy5Y74UX-82cVjl_kxy410smK6bUlAJZidFcAGmnpLd5179fb_N6KdvmIv5Dr6ylxGE6tQAgMG5Q5oqqTio_E2A2yJHydKPZF5uSBLLyvUVjQ2vfD-FRha-wr0NJ75P_SURcVKaOwm7lphxHviQPUh32rKoxDByyOGe_rA7zjtOm7KEWQ9OSZtOlJdfhSvAhXgqIBiV3xMeY0L7q8Wc5YvWo2psYYdm9fQMP1fsXI0eN6N7GNyXtoPqyipOAdlAOlymj1z4_8jcyg3-Z-JlJ6XODYOEx6AelhJ0FqMgr7-EvXnjXMKpooOKK20STPlk6w7NUayhIWilX_Ov9qzZbfrJkqf2-mZrQub0actK51RAEX7Mbkp9o__be-ZmumQWAQ_YVJBKFc6Yg5E2DYLjcXpel-qj3Ngd04Kd249VjcTZGhjaW1EJhOmhK37Qp6UjbfIBqH6H54evF1xJ2NDf55NKFpU8CUgS5PTcXTzquFXLP1WgIMCmY17S6sC2bgOh2sSmNa9uw-3cLhVFm1dElkSZzBi0lZEzAeZWpYYlYGs6AgKWWLDi2eflfTzFkDq4X2EI4T2MP6vMysPKBI5ow4wgzfp7FyRotQOP0wmBhjpKJ7-vo6Nm4j3SR7DOkMvL2An4MUOriVJ7MZCSAyJ8R3CV89rvlNFBHfQFrNRR0rm06nAWNhJiod-OmXWdU2cGLDq7wIlym0Jq_XCwS5DCRqfJh73rLZU5WUWaVCZSZOF5kjL98bHvktwh0b36uG3ImnVIi1p9UWxIPUouGMgryREQD4fM2OQ9CnyfT4TCu3lQr2IWO2ZXLzb7on7gx-cnU55xHELwcnvl9puuEdYXUPLysux8SDJn6rBW6pKqpkxyggiO5g_7nGRSl8-s_2hWs5BLByb9hf_tmDEDctAB3VR_m3M8O3yjUMPmgECxJDH3B1rlGJO81zByC3N0aburjdxk2-Erjq_Om0sp1bfQwLMBQQR_Ll8SuKVKIu0dMM6kldzOPnWr6S4MeG1sa5pcjlsQdaqW1EO31U5CiVVuHAzzTC9xHTtIXtt1GaRWYVSETgqvroZYFQsfkiJnc6xgGfRGP07U9zGhLWCaLihssk2n0NGET5t7LyH9L7FlWuMYzLxPLLKhdwiwAcU_wPoGjw1ogMzUBItbh0eQn2BEu5NJNbrTRXW-wLasm7uh_AraT8QVx_xsdoVjGu7qtjFb8SXz:eyJhbGciOiJFUzI1NiIsImV4dHJhIjoieWVzIiwicnoiOiI2NTZmNjViOTlkYTVkNjQ5ZWEzMTVhNTIzNDNhZGQzNjQyZjE0YzdmZjhkNGViY2U4ZWUzM2EyZjRhNGI0MWUwIiwidHlwIjoiQ0lDIiwidXBrIjp7ImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJQbnpwRWpRWjdic0NsMlpFeHM3ZGJGUWxWemdndi1fdDUwUXV6WlpXY29jIiwieSI6IjFaLXhDNkpaTDJlQU81N292RkpDc3RuQmNNc09pcXNHRjFOSkx5cXExRjQifX0:dsWL4LshPklBGYpI_JWyYADIubmxdAbdZj2hAQBZWC3XwnFaCbL9lw2hGh0MugxKmcLVBI8ZkhXeKZHDgxK2ZQ
```

### Audience-bound (GQ) PK Tokens

Audience-bound PK Tokens are very similar to Nonce-Bound PK Token. The main difference is that instead of committing to the CIC in the `nonce` claim, we commit to the CIC in the  `aud` (audience) claim.

User identity OpenID Connect ID Token issuance flows typically hardcode the `aud` but allow the user to specify the `nonce`. Machine identity OpenID Connect ID Token issuance flows do not use a `nonce` but they do allow the identity to specify a custom audience `aud`. To support machine identity.


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

### GQ-Bound PK Tokens

ERH: provide example of audience, explain encoding decoding

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


### ZK PK Tokens


## PK Token Zoo

| PK Token Type      | ALG | Supported OPs | Identity type |
| -------------      |-------------- | ------------- |------------- |
| Nonce-bound        |   |Google, Azure, Okta   | Human  |
| Audience-bound (GQ)|    |Github, GCP  | Machine  |
| GQ-bound           | alg=GQ256 |Gitlab  | Human, Machine  |
| ZKP-bound          | alg=ZKP | Google, Azure, Okta, Github, GCP, Gitlab  |Human, Machine  |

| OpenID Provider      | Supports               | Identity type |
| -------------        |--------------          | ------------- |
| Google, Azure, Okta, |  Nonce-bound           | Human  |
| Github-Actions       |  Audience-bound (GQ)   | Machine  |
| Gitlab-CI            |  GQ-bound              | Machine  |

### Google

### Github

### Gitlab-CI



## Our JWS conventions

### The TYP pattern

Because a PK Token always has more two or more signatures we have been forced to think about how to effective organize a JWS (JSON Web Signatures) that two or more signatures. If a JWS has only one signature, then the `iss` (issuer) claim in the payload identifies the party that generated the signature. Once you have two or more signatures who do you determine which signature matches the issuer? How do you determine the identity of signer that generated each signature? Determining what party generated what signature is important because we need to know where to find which public key to verify which signature.

One approach is to use signature order. For instance, we could specify that the first signature in the signatures list is the party that created the payload, the second signature is the cosigner, and so on. This approach has two major drawbacks. First, the order of the signatures is not signed or enforced in anyway. This means we can not assume that software and libraries won't reorder the signature list, breaking our ability to match signers to signatures. Second, this approach doesn't solve the problem of optional signers, who may or may not be required.

Instead we use the `typ` (type) key in the protected header to specify the different types of signatures. For instance if the protected header of a signature has `typ=COS` it is a cosigner signature. An other 

In JWT's it is customary to have a `typ=JWT`. We extend this so that signatures each signing party in a protocol specifies their role in the `typ` key of their protected header.

### Protected header claims

In a JWT the claims the issuer is making are set in the payload. However this isn't sufficient for OpenPubkey, parties may wish to add additional claims although with their signature. For instance a signing party who independently authenticated the identity, might want to add an additional claim specifying the time at which this independent authentication took place. This signature can not update the payload without breaking the signature that already signed the payload.

Our solution is to allow signing parties to specify additional claims in their protected header. This enables the party to add claims without requiring any new signatures from any other parties and also makes it clear who added these claims.

### Compact representations of a JWS with ore two or more signatures


### Signature wrapping

GQ Signatures, ZKP

