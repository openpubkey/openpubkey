# ID Token Zoo

This document contains example ID Tokens from different providers. We do include the signatures.

## Azure

### ID Token

```json
{
    "payload": {
    "ver": "2.0",
    "iss": "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
    "sub": "AAAAAAAAAAAAAAAAAAAAAJ8PFm0pjpXKQouYRalE11g",
    "aud": "bd345b9c-6902-400d-9e18-45abdf0f698f",
    "exp": 1737500954,
    "iat": 1737414254,
    "nbf": 1737414254,
    "preferred_username": "alice@gmail.com",
    "oid": "00000000-0000-0000-7862-618d09e9fa0e",
    "email": "alice@gmail.com",
    "tid": "9188040d-6c67-4c5b-b112-36a304b66dad",
    "nonce": "pElF-ABr22cAQOTAC0qpxI83OH14Hu7fjRSWzS6ViLY",
    "aio": "DoD*c*IDip3fgOs3T8dIIBWw!JwcIwhQCwMcpNinmjEss4Ifu0PKKMPCiuJOXBAtX8OObt*128kwC7cPM97!AHy8mw1kRA9P5dcw6wlj8doC1j5nn03eNizuiwI9JMgdD1I0rfWBClENOSqDUg4ODsuPds!G1NtVGt6bxfRJrM81"
    },
    "protected": {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "aB0xDdGXk535PvewBP9Hl5pf7wc"
    }
}
```

### Refreshed ID Token

```json
{
"payload": {
    "ver": "2.0",
    "iss": "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
    "sub": "AAAAAAAAAAAAAAAAAAAAAJ8PFm0pjpXKQouYRalE11g",
    "aud": "bd345b9c-6902-400d-9e18-45abdf0f698f",
    "exp": 1737500957,
    "iat": 1737414257,
    "nbf": 1737414257,
    "preferred_username": "eth3rs@gmail.com",
    "oid": "00000000-0000-0000-7862-618d09e9fa0e",
    "email": "eth3rs@gmail.com",
    "tid": "9188040d-6c67-4c5b-b112-36a304b66dad",
    "aio": "DmyH0vHZqJZRcv752O*ph8K!x!EOAIk!e1nSWrtlGxUlMccl2n5qHa9vY4YtAfWma!VI3BqIfsfzYdrrMDW22D5qIRAOYDP9utExgqTitwxNf83p*3nLqtCTnND!GVwhM35BGCaLqsA9MF8gu1dbUfTPgYxD4yTOH3sZq3hDyAbY"
    },
"protected": {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "aB0xDdGXk535PvewBP9Hl5pf7wc"
    }
}
```

## Google

### ID Token

```json
{
"payload": {
    "iss": "https://accounts.google.com",
    "azp": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "aud": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "sub": "103030642802723203118",
    "email": "alice@gmail.com",
    "email_verified": true,
    "at_hash": "fTQQ5_pA8i-Zx_Bif9PVrA",
    "nonce": "oZifhxF_UkB0AG6K1hPyEsvDCHuqW3QsyK4O_XIlTzU",
    "name": "Alice Example",
    "picture": "https://lh3.googleusercontent.com/a/ACg8ocJie7Hgt4fitN0_GWXaFHYBuy1UMkr_ufkLXTW7MEpA_UMx1XlU=s96-c",
    "given_name": "Alice",
    "family_name": "Example",
    "iat": 1737415178,
    "exp": 1737418778
    },
"protected": {
    "alg": "RS256",
    "kid": "6337be6364f3824008d0e9003f50bb6b43d5a9c6",
    "typ": "JWT"
    }
}
```

### Refreshed ID Token

```json
{
"payload": {
    "iss": "https://accounts.google.com",
    "azp": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "aud": "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
    "sub": "103030642802723203118",
    "email": "alice@gmail.com",
    "email_verified": true,
    "at_hash": "kUOiPWtlZegMkNufB3eDaA",
    "name": "Alice Example",
    "picture": "https://lh3.googleusercontent.com/a/ACg8ocJie7Hgt4fitN0_GWXaFHYBuy1UMkr_ufkLXTW7MEpA_UMx1XlU=s96-c",
    "given_name": "Alice",
    "family_name": "Example",
    "iat": 1737415180,
    "exp": 1737418780
    },
"protected": {
    "alg": "RS256",
    "kid": "6337be6364f3824008d0e9003f50bb6b43d5a9c6",
    "typ": "JWT"
    }
}
```
