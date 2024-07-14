# PK Token

OpenPubkey works by 

## JSON Web Signatures (JWS) and JSON Web Tokens (JWTs)

A [JWS (JSON Web Signature)](https://www.rfc-editor.org/rfc/rfc7515.html) is a signed message format. The message which is signed is called the payload. It supports 1 or more signatures. Each signature has a protected header (`protected`) which specifies metadata about the signature such as the algorithm (`alg`) that was used to verify it or the key ID (`kid`) of the public key to verify the signature.

```json
payload: "message payload"
signatures: [
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

Note that each signature signs the payload and that signature's protected header. In the example above RSA signature-2 is RSA-SIGN(SK, ("message payload", "{"alg": "RS256", "kid": "1234"}")). All signature's sign the same payload, no signature signs another signature's protected header.


A [JWT (JSON Web Token)](https://datatracker.ietf.org/doc/html/rfc7519) is a type of JWS used by one party to make claims another set of parties. The party making the claims is called the issuer and they include their identity in the JWT using the `iss` claim. JWT are defined as making only one signature, the signature of the issuer.

```json
payload: {
  "iss": "https://accounts.google.com",
  "claim": "claimvalue",
} 
signatures: [
  {
    "protected": {"alg": "RS256", "kid": "1234..."},
    "signature": "RSA signature-1"
  }
]
```

An ID Token is a type of JWT used in OpenID Connect protocol to enable an OpenID Provider to make claims about an identity.


## PK Tokens


OpenPubkey has a number of types of signatures. We encode the type of a signature in a PK Token using the helpful `typ` (type) key in the protected header of each signature.

Explain the different types



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

