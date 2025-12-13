# JWKS (JSON Web Key Set) Zoo

This document contains example JWK Sets from different providers.

## Azure

```json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "yEUwmXWL107Cc-7QZ2WSbeOb3sQ",
            "x5t": "yEUwmXWL107Cc-7QZ2WSbeOb3sQ",
            "n": "sFO9W05FQwiZenzhV4wYRMpok4hgSMR-TZKRZKt26FojHgHfOhySAjcCesHo_QVvj0Wos9KSgIB3Pt55qo2lc4TmRLdpFsKZ5XEyWaCZL87pGb6fqsCNIqw-768vhGUk3nR2NHOjNrzwJb_soyZO0_2Wq7cZRqD8yFeVWRFxY8qDm1e_qutcxSQm-d0rvgGP3ZSbcx5HpTjQIz-HmiRDJoIfhRBgFRriBNmF7mG8H9Tug2GsZObGl4PbNyMYzVfJvqUGVvxdpX0TOgZ9hnva5QSfPaJCpyya1diUX6rJAxXU5JU7_yoWXW49nHAd1LUtxnSrVgD8tY84HNcyAmNZ6w",
            "e": "AQAB",
            "x5c": [
                "MIIC/jCCAeagAwIBAgIJAM/j60cyShQEMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMjUxMDAxMDUxNjM2WhcNMzAxMDAxMDUxNjM2WjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsFO9W05FQwiZenzhV4wYRMpok4hgSMR+TZKRZKt26FojHgHfOhySAjcCesHo/QVvj0Wos9KSgIB3Pt55qo2lc4TmRLdpFsKZ5XEyWaCZL87pGb6fqsCNIqw+768vhGUk3nR2NHOjNrzwJb/soyZO0/2Wq7cZRqD8yFeVWRFxY8qDm1e/qutcxSQm+d0rvgGP3ZSbcx5HpTjQIz+HmiRDJoIfhRBgFRriBNmF7mG8H9Tug2GsZObGl4PbNyMYzVfJvqUGVvxdpX0TOgZ9hnva5QSfPaJCpyya1diUX6rJAxXU5JU7/yoWXW49nHAd1LUtxnSrVgD8tY84HNcyAmNZ6wIDAQABoyEwHzAdBgNVHQ4EFgQUYdczXud2h1dPEOcA7tnbvbh/+sAwDQYJKoZIhvcNAQELBQADggEBABpmhrnzarikYdrPOr72YQhi2Hw/GMswnvVyrf9ORSwynpHR1jKki+rr/rtEUTZbArRsvy0U/0PwnmDHM/J1R7o9mi4sbf56o0CuZOifk362i2THIiS9s7QCuOJneGrZo6YsIvcTubo2C13taowzhvar/cJgMTeWcvqw2UAnOr8uXkM5NWbUQGj2r2aAg0U71dJrSQGukkujzxj2wdQshg9BKC3QkIH8mvaQAVkSYTBDI2whF1JcYRmNzIsZGGG3kWUncKzIw6zmPQRYK96E/n4Tq6yYybq5CsfrvP9/9iDg+hhOt5gzbuQSX/0yYA6vbk4y8ZaOr51OCvfEj1ew2Bg="
            ],
            "cloud_instance_name": "microsoftonline.com",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
        },
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "-MyGFduIUViaL6NDYyTV0FGATGk",
            "x5t": "-MyGFduIUViaL6NDYyTV0FGATGk",
            "n": "p5cmEcNwRuuH-AloG-bA4At8VAkpIuMlu7Zl0AhFewUUfOEf0tOKNGH7LGc6pzjYGwZuey94xelj4SRLHMyeTopjjHtmyy1LJyXZLUBT6tVTIwGWECpHQKNcIjXbSgRR80C6lrAcBSErXV43h9awnu1JrhlfVrCaDYuE2oBFO5PZR6H0ZyfehCIRYt_69MCxUMmbx-nyj-bnlJXmRuF87ll6hmceEYXTUnpuWNelHp6UMSTKE2UCna6KSsvOJ8WPXQJq2SImefNyF67hSSKgdPJcnid-E4hb63mrkfxyFm-bLMtd4twEKZv9F5q9Wk3NrHZuMIqjjcSdyt_aEcFBTQ",
            "e": "AQAB",
            "x5c": [
                "MIIC/jCCAeagAwIBAgIJAJcPVeVovVVRMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMjUxMDE1MTkzMTM1WhcNMzAxMDE1MTkzMTM1WjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp5cmEcNwRuuH+AloG+bA4At8VAkpIuMlu7Zl0AhFewUUfOEf0tOKNGH7LGc6pzjYGwZuey94xelj4SRLHMyeTopjjHtmyy1LJyXZLUBT6tVTIwGWECpHQKNcIjXbSgRR80C6lrAcBSErXV43h9awnu1JrhlfVrCaDYuE2oBFO5PZR6H0ZyfehCIRYt/69MCxUMmbx+nyj+bnlJXmRuF87ll6hmceEYXTUnpuWNelHp6UMSTKE2UCna6KSsvOJ8WPXQJq2SImefNyF67hSSKgdPJcnid+E4hb63mrkfxyFm+bLMtd4twEKZv9F5q9Wk3NrHZuMIqjjcSdyt/aEcFBTQIDAQABoyEwHzAdBgNVHQ4EFgQUjulxdRp7rNoGxO9r/r4vh+sOVOUwDQYJKoZIhvcNAQELBQADggEBAG0FMXXZzggEePMs1cxHLViL9/fP5QF50P2qm1snTsN8/SfNcpUPOy+cH+DP58omGXz4GfC8J28Yq/Ct8aSh7AX6Sn88QdEzojaKB/maCcfINH9YUxaYXW0aVawr2Qz7DH1gP453shqduay+d9vlglNNtqqeK9Xfyi3npHIJloLtD5B8/YPlOQ69dUTNVtNeZVlw/GyM+aca/V+WHr8YocxybAM/8ZPjS8Z7i587y6HN9ojDiVPZ3R3kgDM2C1o0mBVh2ZkX3zJVUKcehJslGhWtFJH39/1QOIQGpPtLMy+fdWXhsoz8OI4Kc9tlInrXBIwSdTlrIK2owYyMbzX+EQU="
            ],
            "cloud_instance_name": "microsoftonline.com",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
        },
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "rtsFT-b-7LuY7DVYeSNKcIJ7Vnc",
            "x5t": "rtsFT-b-7LuY7DVYeSNKcIJ7Vnc",
            "n": "sE-vzm1BhzJJ5KKgJKPGX4M3GbeM0c25HOVQL1aLbOEHm92HBFk1djM9a8WLDfg_d8SLh3Ehta0i0ctATwU0CSeeodvsqL4mKEOXYEqIi1f8ixCX0c7vJ0ESNcyWeAm18F9WNtFKKDOM7gzCn0zuuAZR3m_rBaPDOkoX1AULrkMZjnantrw4z8hL344dLAneta5JiulJor2NiJGNU5EHcVjw7eMDunPTpC_IAxDKF5_hTQ0Hj4-R2AzuSBO0DZ3T2G7_6lmIguOIanfGoYGKev4JvumXahkVGf_tgZ3WuoUqB8KEIM8VGjS0MjBFgCtxX6GmvRD-H3F58x4bsBAZxw",
            "e": "AQAB",
            "x5c": [
                "MIIC/jCCAeagAwIBAgIJAPJGEpowIhBNMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMjUxMDI2MTk0NjQ1WhcNMzAxMDI2MTk0NjQ1WjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsE+vzm1BhzJJ5KKgJKPGX4M3GbeM0c25HOVQL1aLbOEHm92HBFk1djM9a8WLDfg/d8SLh3Ehta0i0ctATwU0CSeeodvsqL4mKEOXYEqIi1f8ixCX0c7vJ0ESNcyWeAm18F9WNtFKKDOM7gzCn0zuuAZR3m/rBaPDOkoX1AULrkMZjnantrw4z8hL344dLAneta5JiulJor2NiJGNU5EHcVjw7eMDunPTpC/IAxDKF5/hTQ0Hj4+R2AzuSBO0DZ3T2G7/6lmIguOIanfGoYGKev4JvumXahkVGf/tgZ3WuoUqB8KEIM8VGjS0MjBFgCtxX6GmvRD+H3F58x4bsBAZxwIDAQABoyEwHzAdBgNVHQ4EFgQU+A6C3/xdVe7vu2wezFXPLQE0nyMwDQYJKoZIhvcNAQELBQADggEBADAAoTCjqbO+Ku6E1nbOUkq513ETV+7iL6g7FnxY4ysl2qPAsgPcLOO/HoWGLNfu4fbqyBqtSpoHYQUEe2e4FNF9T0EB5B5NShFiSlLVcQyp23PcrcInQRnb7x9iX/ztxm1bpNnLXrQrh/RTsdev6LqiIfhC2XH70Avb6LTYcBMkUuo9Y2kxT3WtyklSl0Ogr3td/lPZne1vcPP4h64uzE9+GKcm+2iZRyWGMjtG6DnC1whmoetqDDmQ9pmHi2xlxSjcTS8oq/FwEA20sjNO4DdBN9tS2VMwVZldZ/Z594sRKOPo3kPVdKhJZud5Yt2nt+xiHcjKY48HmOXRnF8AOto="
            ],
            "cloud_instance_name": "microsoftonline.com",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
        },
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "QhLMpTTJogmIIa5vrgJiSFgh97I",
            "x5t": "QhLMpTTJogmIIa5vrgJiSFgh97I",
            "n": "jHZTt07m5_SfsLAPwFOzY53bXiMZRhKnMaY-MQF9S6J0EZbMNTyMTg5a4Tm_BsOKt9zGxxbn5avI48FIfIqH0wo33FqyrFCpnHPxZ8AtOUsZ15vPeeX_ay0PDZEGPXkQV0Uc304HRXJtPZ1hGid4jEgTjgax6HTrnRlX-R35nz0GJi58e2VMQINqX1Soz2T_bJLTSc79nI9ihzN8EYb7LLoGV4AvwffO3ZXORoFSs468ZfQRwJ2usfoEUt6PtIEGTdJ8uS59EdAVpSUANI1sDVnJnonINWXyr10QClZwNqm54IBh_tk98ZgeVuj1tCoIoCpOUy8WKai6tWkWvL3Fzw",
            "e": "AQAB",
            "x5c": [
                "MIIC6jCCAdKgAwIBAgIJAL1iBsaLYB8iMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGGxvZ2luLm1pY3Jvc29mdG9ubGluZS51czAeFw0yNTExMDkxNzAwNDFaFw0zMDExMDkxNzAwNDFaMCMxITAfBgNVBAMTGGxvZ2luLm1pY3Jvc29mdG9ubGluZS51czCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIx2U7dO5uf0n7CwD8BTs2Od214jGUYSpzGmPjEBfUuidBGWzDU8jE4OWuE5vwbDirfcxscW5+WryOPBSHyKh9MKN9xasqxQqZxz8WfALTlLGdebz3nl/2stDw2RBj15EFdFHN9OB0VybT2dYRoneIxIE44Gseh0650ZV/kd+Z89BiYufHtlTECDal9UqM9k/2yS00nO/ZyPYoczfBGG+yy6BleAL8H3zt2VzkaBUrOOvGX0EcCdrrH6BFLej7SBBk3SfLkufRHQFaUlADSNbA1ZyZ6JyDVl8q9dEApWcDapueCAYf7ZPfGYHlbo9bQqCKAqTlMvFimourVpFry9xc8CAwEAAaMhMB8wHQYDVR0OBBYEFBiWesvUh7Ny+crgGVrEmwQc+X/zMA0GCSqGSIb3DQEBCwUAA4IBAQA3N+vcAcpceN7s/uOORi+5eB9FtL03ZVUmJtoUMMme6Q6588oIaTg4HhEM8XSzQJyljDJtsjJnw1YoZWCVi5ju0c3f+L+ue8AphB+9VkjqSvwIR9gOrNhhO3ZFG8tvvIf7dZTbI5EaiMdHrpPCtRLruWUugbVZwqjM3foMixnOgxG1mMPNYNnSURxo1ygS0WbS4dSzjXVX3GyuXIMjk+75CWtOan8JgY7KJCFqgXHgAb/QpWjY7a5H0blu79rD6RFawH+zH5V6//9CgeiKPSmd4mfkS5IrVJ0jceek5ttqmYrRTYSQknl/mVMP4pRX6rKLwwTahNWVHCvcaNlgXECX"
            ],
            "cloud_instance_name": "microsoftonline.us",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
        },
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "9GLFlGnl81ASh2i83EnTMFHh6sw",
            "x5t": "9GLFlGnl81ASh2i83EnTMFHh6sw",
            "n": "h5rnkYHENgZOIugBapCkUVcSq02XnnWQrjprJoq-SdAJSygIarlGtBAuSwgbMnfsTZ6hvf0WRfLtXChr35X7roQW4-A_7XTnAdCYD1RjyDC_GSIG3LRrhWl9w6Bq7dEdRAxnzJb3qzxD_ZAb6fby9_hyABr0FdxtgltdiSu38pVb5Pm_UnTTh4KL-ARf0JDTdIqsSTxZu6gEY8pjJY1pS3a6i65irzjvEsK19c1jCzns9iBKDFDrA4yqIM5Xwk5v_LWvvXbR1IiW-1RNTvjhCUhrDCpKECphr5QGaMYGZxKzsLiVgNIpY59Mp7nE-sScmXaimrrrmr33BSAs5EOajw",
            "e": "AQAB",
            "x5c": [
                "MIIC6jCCAdKgAwIBAgIJANFGBCNqp3cgMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGGxvZ2luLm1pY3Jvc29mdG9ubGluZS51czAeFw0yNTExMzAxNzAwMjlaFw0zMDExMzAxNzAwMjlaMCMxITAfBgNVBAMTGGxvZ2luLm1pY3Jvc29mdG9ubGluZS51czCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIea55GBxDYGTiLoAWqQpFFXEqtNl551kK46ayaKvknQCUsoCGq5RrQQLksIGzJ37E2eob39FkXy7Vwoa9+V+66EFuPgP+105wHQmA9UY8gwvxkiBty0a4VpfcOgau3RHUQMZ8yW96s8Q/2QG+n28vf4cgAa9BXcbYJbXYkrt/KVW+T5v1J004eCi/gEX9CQ03SKrEk8WbuoBGPKYyWNaUt2uouuYq847xLCtfXNYws57PYgSgxQ6wOMqiDOV8JOb/y1r7120dSIlvtUTU744QlIawwqShAqYa+UBmjGBmcSs7C4lYDSKWOfTKe5xPrEnJl2opq665q99wUgLORDmo8CAwEAAaMhMB8wHQYDVR0OBBYEFP8HB0d61yTicxq00MMg7eDQo3lDMA0GCSqGSIb3DQEBCwUAA4IBAQB41t3OuRm13hcadz6wlc1Na0uuVTXG/kKbT4pFo2x1eO5T7vZWnGjlYkZfOnkYywVPvcfW2nj3RswMOiYwzoNzYBmRUAYLh8OerCniKlPJKrONJsGBtpVOjU80QWatFRVVxNqskAMSFUAYxcqa5OomZXnTvAyxwWuNXc9CMMMQBZ8y1JHID7BmHPZKRO55uwNhVHhM7rVSQAjssbUZ6UU2ZramGul7Cs/ikynHXWPBOibX2ucexQcDlobJLk6qc3AJxs7KyRS1D723gqm1xIMKED+Vo7QKEB2/7Lz1lzGVfuAOUSQIY7tHH3CtMMnsQOniqbTYDW2mbzb35UngRe00"
            ],
            "cloud_instance_name": "microsoftonline.us",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
        },
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "fr4hEBEECiE7xC8D3u2vlr3n9ok",
            "x5t": "fr4hEBEECiE7xC8D3u2vlr3n9ok",
            "n": "kMni47R_k2L8vbM91mUGr9nBQzxLGkPIYJvalQLebPErH6LNJzl6m-mDZ_aaHZaM85jgeHAEIQIRzXoaA5fA4X5_Q1MVHaGq9ARr8X5vUKAwxDWQK2IRAsnyyxSZv77VRDQIK_rzPsBF7UKbVZ4fudl9kxL4zcs2XUKFknQdCRgfB_Eu-YLVd5q2yFdK1Bl6Ewi4AkQBTgKMw_N55jFBNfTXWKLmGN2K8OM5RErYgPvVkIaHZPW0ErFPACH6VVu94XTq4evecm-VyBV1P6G3d6z3-DUFIZRIQ6LfRI2LLy4-J35pQ-8-14kRV8zUjCS7BdWpHHKMRN5DIH4XWcADdw",
            "e": "AQAB",
            "x5c": [
                "MIIDCzCCAfOgAwIBAgIRAKQwMXicq/VzEingHpC+vG8wDQYJKoZIhvcNAQELBQAwKTEnMCUGA1UEAxMeTGl2ZSBJRCBTVFMgU2lnbmluZyBQdWJsaWMgS2V5MB4XDTI1MTEyNTExMzEyMVoXDTMwMTEyNTExMzEyMVowKTEnMCUGA1UEAxMeTGl2ZSBJRCBTVFMgU2lnbmluZyBQdWJsaWMgS2V5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkMni47R/k2L8vbM91mUGr9nBQzxLGkPIYJvalQLebPErH6LNJzl6m+mDZ/aaHZaM85jgeHAEIQIRzXoaA5fA4X5/Q1MVHaGq9ARr8X5vUKAwxDWQK2IRAsnyyxSZv77VRDQIK/rzPsBF7UKbVZ4fudl9kxL4zcs2XUKFknQdCRgfB/Eu+YLVd5q2yFdK1Bl6Ewi4AkQBTgKMw/N55jFBNfTXWKLmGN2K8OM5RErYgPvVkIaHZPW0ErFPACH6VVu94XTq4evecm+VyBV1P6G3d6z3+DUFIZRIQ6LfRI2LLy4+J35pQ+8+14kRV8zUjCS7BdWpHHKMRN5DIH4XWcADdwIDAQABoy4wLDAdBgNVHQ4EFgQUJNvFQ6s5K++89Ii6JiYm4A5H5a8wCwYDVR0PBAQDAgLEMA0GCSqGSIb3DQEBCwUAA4IBAQCDXYOLIRlU1KszeLiV1xfspBSf7Ijw/adjex+O2FTy5fWv6wp7N/jxHpFSen4LRT6ZP9kI9hwwqA8EzsnTFb1vEILr/0MVe0TkDk1LtiRnoemIjj3BIzStlD0dCVvgfLgQS25F2Hx/kt/J3PXyYI5ld33BQMNKzj6whHQF4T+xr+w1mnw6M0VuuFDp83YSRX8EQGDfxpH0RrX7QBHv4IULZ5qGjhIgaHEk/Daf1iZSXoIEjKy2Ioy2K0PvqtVupUB2MIUz5XcEMtLWeYknCi1fbpRpkAVz7mPldTbL7fajGUj3qWAaHsvVobbGeROIIFdZpdqmUdD/eRdIQP0JGHG0"
            ],
            "cloud_instance_name": "microsoftonline.com",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
        },
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "l7YavV1KfsHj8PUGSztDOk9VpKA",
            "x5t": "l7YavV1KfsHj8PUGSztDOk9VpKA",
            "n": "6UqWPAlAKEa3vd_NkgMeCBbOgsaanWsWdf8j5PuLeqktxqUiTUeYYwmH7J_AxThhDqqEVUkZ2xtMsAl92rhuqrzlodS73M5r62HgDpN3zOdOacn3yG-uHODTKw9uqqZXX-S9zSD-0MAewK5ffb-RheLr03GM6D3Wj5ju_DONfu01hNGnpRb0AEw1rp_In6bXSYHqdOUPS8mwCR5ZMRG4AaF9OOs5sqXr0Ij7n7c_mV5OIc2vzRQYwCb6HF-3X2xRGznMxU4-gy6sm3D1YGf4I9mf84YfOMJWlLO7YrcHmhz_RSW-iAjzxmCut7CHbO7drTBQTrfWfyJFgBb3W2IGLQ",
            "e": "AQAB",
            "x5c": [
                "MIIDCjCCAfKgAwIBAgIQdNTI+uLK3/xh/6PxIhSLdzANBgkqhkiG9w0BAQsFADApMScwJQYDVQQDEx5MaXZlIElEIFNUUyBTaWduaW5nIFB1YmxpYyBLZXkwHhcNMjUxMTEyMTQwMTM1WhcNMzAxMTEyMTQwMTM1WjApMScwJQYDVQQDEx5MaXZlIElEIFNUUyBTaWduaW5nIFB1YmxpYyBLZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpSpY8CUAoRre9382SAx4IFs6CxpqdaxZ1/yPk+4t6qS3GpSJNR5hjCYfsn8DFOGEOqoRVSRnbG0ywCX3auG6qvOWh1LvczmvrYeAOk3fM505pyffIb64c4NMrD26qpldf5L3NIP7QwB7Arl99v5GF4uvTcYzoPdaPmO78M41+7TWE0aelFvQATDWun8ifptdJgep05Q9LybAJHlkxEbgBoX046zmypevQiPuftz+ZXk4hza/NFBjAJvocX7dfbFEbOczFTj6DLqybcPVgZ/gj2Z/zhh84wlaUs7titweaHP9FJb6ICPPGYK63sIds7t2tMFBOt9Z/IkWAFvdbYgYtAgMBAAGjLjAsMB0GA1UdDgQWBBThms94PFzVzLbLaXhrwb1AACsWGTALBgNVHQ8EBAMCAsQwDQYJKoZIhvcNAQELBQADggEBACLF4BdHg9h123bEKSuYgvPIQx4TpMteYr1yww5lx86JF11qyeg5XhSCJ5408x+fvLOIsRTL/keslVVCYjGqOTmmW3iHdbDJ9uAhKrTxB5Q63/2+jW6bf8F9ugU4BA/Y+A5dRkLesgA157IthYAMiODzCOO7/tSYvlZKV+yLK1sR9aK86S87fq0p5Ye5cMEfHvZxk58m+FK0UxY/qevYgp8czn9GnKrYdqVlGaNuGk63RQBSIZi/HxFm0Pa4rmvQy25423Hkpe0aBo1LcrMzPfUhAmoU3Kd2VnzsUrpJHtm6tudP/TFaDAzMZMiIY068b4TwK8mls9bZv7mBOeb5NCg="
            ],
            "cloud_instance_name": "microsoftonline.com",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
        },
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "RnvQx2FFNAulTRLsWjUWajmTTBE",
            "x5t": "RnvQx2FFNAulTRLsWjUWajmTTBE",
            "n": "oVxV2IHo4QizaoC-JhiZf4W22Fmnz1TVoPT_tjGDM1blsyKayh9YazwBiL0YPYL-X8mFjJUD8P0l0av1ePVu3eCLRxJX8PMOt72F5z5JV6W2wmftZEU53JhfD281F1tSgczC0TTi1v_6RZ9HMEptI9e6sX5kqtmrDKESw4R41-Wby2Nq0Rq-9DED3l17WatLbpTlTxzWW01YdRbWjG9mmUjV8a9jQ8QqnZycLLJm9v2rwVeOokIvS0Q--c3gE1oEM5Epq9-tc-vJyNyUyhewQAcVZyDbR1UU5K7L61gUlVgN3jlG0PMdxPd8N5jPtC-8Q2Q4N1avhhCnHIajUx-L2w",
            "e": "AQAB",
            "x5c": [
                "MIIDCjCCAfKgAwIBAgIQJy28aTJFzgK2jVOdvdPADzANBgkqhkiG9w0BAQsFADApMScwJQYDVQQDEx5MaXZlIElEIFNUUyBTaWduaW5nIFB1YmxpYyBLZXkwHhcNMjUxMDMwMTcwMTQzWhcNMzAxMDMwMTcwMTQzWjApMScwJQYDVQQDEx5MaXZlIElEIFNUUyBTaWduaW5nIFB1YmxpYyBLZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChXFXYgejhCLNqgL4mGJl/hbbYWafPVNWg9P+2MYMzVuWzIprKH1hrPAGIvRg9gv5fyYWMlQPw/SXRq/V49W7d4ItHElfw8w63vYXnPklXpbbCZ+1kRTncmF8PbzUXW1KBzMLRNOLW//pFn0cwSm0j17qxfmSq2asMoRLDhHjX5ZvLY2rRGr70MQPeXXtZq0tulOVPHNZbTVh1FtaMb2aZSNXxr2NDxCqdnJwssmb2/avBV46iQi9LRD75zeATWgQzkSmr361z68nI3JTKF7BABxVnINtHVRTkrsvrWBSVWA3eOUbQ8x3E93w3mM+0L7xDZDg3Vq+GEKcchqNTH4vbAgMBAAGjLjAsMB0GA1UdDgQWBBRH4Tdl/o9+b2tFzwN69kotlJ8yAjALBgNVHQ8EBAMCAsQwDQYJKoZIhvcNAQELBQADggEBADWLtIi+8GLriTWglNWJ0cIE59Wr7upAQqUajkESEYcruX3uTDr4zf79ZYot/WS+fc1fai82P6tIU4YqpTRsbN4d/Lv4WGxl+lZL+vSEqrvPoAfEEz5MNX63GAYTzfpclB+/73v90SxdJp1TZnDKTsPfGFF4jFq1CStuKui/qdkUGhIble4Mq6m4IsYL1zuZgZ6WsExKmxyBIMmPxUON52OOnIR9gNlZkWP+YZlPz21jNDFLWbx0RsPibJv6vBgbU2MUsrNteDBbW8jReyrRnM+4upB2YRtlnS0+7ew+JdlpGT3P+BbqgSL9iuj1TwuGdXPoVhh0PTe2CZAJTEROwlc="
            ],
            "cloud_instance_name": "microsoftonline.com",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
        }
    ]
}
```

## Google

```json
{
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "kid": "93a9358ccf99f1bb040bc6221d5493e1ffd8ada1",
            "e": "AQAB",
            "n": "lS1jk0KK-dNV-znvOtWcgkiY52Wdfs7RN3117id4c1cmJ3gR0bgRbKo_G6MeY6pAdgWjoGl114tkEAbhKv-4uONGXizTMtqEj10vXzDaZhFeAYX-7VthR-kyuCKFDwU6KHYunV7G-kcKIlCM9p6nnpky7JxBYh9eDzshRbrF6qhxemidcsoL0OGclfslbzgkcUbG2uP21X-fGpX2NmoT5CWcSBoFoo3oesggZuU7goQ_mXdsndPtOEwspmwRpwC_sssdMhDhkG8ehuSSYrbGMCUF3yAOkZfmFRKf6cjtOBeBifmzarhk5XCD5-NIMUBBoD5pdQrsrZuQrImIIPoqwQ",
            "use": "sig"
        },
        {
            "kid": "d543e21a0273efc66a4750002441cb2151cb235f",
            "n": "v62PQeiSTlcNC1fLRNYV1M6x63Gjqy6SlxwFgYT71tPegLUtwKHStnGV_RxekgPEzthePFhjhgfZVJQ1RshUaXd4nVAIKOyBppoZDfrP1ueMnxd-HfaG0NFV3UjUiI7Tq8UaZufuxsJn873LZ0wQN5Q17z4yirPCuf8ryllOELUM1S1yGz1xwYTmeaWZEzUftqDpoPHoBO6st3RprHeNnJKATYcCIEhKC6S_e7MDVxkTptH5mhX8L-QChMPk_27EGLwt8g6_QOW9qV1XF5wIwqoxzGeGUGPvIK9JH6g1aWuEVZdQvxBlMcknNTBkVyUUpXM-cUVMNd_pfLJ2WyeXrQ",
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "alg": "RS256"
        }
    ]
}
```

## Github Actions

```json
{
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "cc413527-173f-5a05-976e-9c52b1d7b431",
            "n": "w4M936N3ZxNaEblcUoBm-xu0-V9JxNx5S7TmF0M3SBK-2bmDyAeDdeIOTcIVZHG-ZX9N9W0u1yWafgWewHrsz66BkxXq3bscvQUTAw7W3s6TEeYY7o9shPkFfOiU3x_KYgOo06SpiFdymwJflRs9cnbaU88i5fZJmUepUHVllP2tpPWTi-7UA3AdP3cdcCs5bnFfTRKzH2W0xqKsY_jIG95aQJRBDpbiesefjuyxcQnOv88j9tCKWzHpJzRKYjAUM6OPgN4HYnaSWrPJj1v41eEkFM1kORuj-GSH2qMVD02VklcqaerhQHIqM-RjeHsN7G05YtwYzomE5G-fZuwgvQ",
            "e": "AQAB"
        },
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "38826b17-6a30-5f9b-b169-8beb8202f723",
            "n": "5Manmy-zwsk3wEftXNdKFZec4rSWENW4jTGevlvAcU9z3bgLBogQVvqYLtu9baVm2B3rfe5onadobq8po5UakJ0YsTiiEfXWdST7YI2Sdkvv-hOYMcZKYZ4dFvuSO1vQ2DgEkw_OZNiYI1S518MWEcNxnPU5u67zkawAGsLlmXNbOylgVfBRJrG8gj6scr-sBs4LaCa3kg5IuaCHe1pB-nSYHovGV_z0egE83C098FfwO1dNZBWeo4Obhb5Z-ZYFLJcZfngMY0zJnCVNmpHQWOgxfGikh3cwi4MYrFrbB4NTlxbrQ3bL-rGKR5X318veyDlo8Dyz2KWMobT4wB9U1Q",
            "e": "AQAB",
            "x5c": [
                "MIIDKzCCAhOgAwIBAgIUDnwm6eRIqGFA3o/P1oBrChvx/nowDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwaYWN0aW9ucy5zZWxmLXNpZ25lZC5naXRodWIwHhcNMjQwMTIzMTUyNTM2WhcNMzQwMTIwMTUyNTM2WjAlMSMwIQYDVQQDDBphY3Rpb25zLnNlbGYtc2lnbmVkLmdpdGh1YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOTGp5svs8LJN8BH7VzXShWXnOK0lhDVuI0xnr5bwHFPc924CwaIEFb6mC7bvW2lZtgd633uaJ2naG6vKaOVGpCdGLE4ohH11nUk+2CNknZL7/oTmDHGSmGeHRb7kjtb0Ng4BJMPzmTYmCNUudfDFhHDcZz1Obuu85GsABrC5ZlzWzspYFXwUSaxvII+rHK/rAbOC2gmt5IOSLmgh3taQfp0mB6Lxlf89HoBPNwtPfBX8DtXTWQVnqODm4W+WfmWBSyXGX54DGNMyZwlTZqR0FjoMXxopId3MIuDGKxa2weDU5cW60N2y/qxikeV99fL3sg5aPA8s9iljKG0+MAfVNUCAwEAAaNTMFEwHQYDVR0OBBYEFIPALo5VanJ6E1B9eLQgGO+uGV65MB8GA1UdIwQYMBaAFIPALo5VanJ6E1B9eLQgGO+uGV65MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGS0hZE+DqKIRi49Z2KDOMOaSZnAYgqq6ws9HJHT09MXWlMHB8E/apvy2ZuFrcSu14ZLweJid+PrrooXEXEO6azEakzCjeUb9G1QwlzP4CkTcMGCw1Snh3jWZIuKaw21f7mp2rQ+YNltgHVDKY2s8AD273E8musEsWxJl80/MNvMie8Hfh4n4/Xl2r6t1YPmUJMoXAXdTBb0hkPy1fUu3r2T+1oi7Rw6kuVDfAZjaHupNHzJeDOg2KxUoK/GF2/M2qpVrd19Pv/JXNkQXRE4DFbErMmA7tXpp1tkXJRPhFui/Pv5H9cPgObEf9x6W4KnCXzT3ReeeRDKF8SqGTPELsc="
            ],
            "x5t": "ykNaY4qM_ta4k2TgZOCEYLkcYlA"
        },
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "38E9B30B3A023A1B72309921A69A42FCC496C42C",
            "n": "tEq2Fp9HcdT5MwMsB_UTm8j_woJJLi3sA-y0RX2tioTm581seyfvOH6lJ5JmHVtS-_fb8B2tRT1pznHQSNq14PsJdu9bp5egbWmIz-5RvhqoM-oKem_MJENCNFuqXijRLT47FRdfH3inqde1vJlA_JJHCqYMKIpHH7kqNFYcCpwr0vk80Hc2rTyL0uBXI7NqBZbtUgNoyucWO5O7QQrPNOmlr-GI8aFckFRfobCaCOiH9qW02FtkV74fwBGVCNhNf3a1CK81-O8xEGimvVydI_pQA5B8QqVuQjY_ntOu555HdirA0hKkY6fsE9eZCMFmWDHZ2kSWLjhabxWxIzSzXQ",
            "e": "AQAB",
            "x5c": [
                "MIIDrDCCApSgAwIBAgIQbuIOJTcGQ4GOQs29F1/uLzANBgkqhkiG9w0BAQsFADA2MTQwMgYDVQQDEyt2c3RzLXZzdHNnaHJ0LWdoLXZzby1vYXV0aC52aXN1YWxzdHVkaW8uY29tMB4XDTI1MDkxMTE5MzcxOFoXDTI3MDkxMTE5NDcxOFowNjE0MDIGA1UEAxMrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALRKthafR3HU+TMDLAf1E5vI/8KCSS4t7APstEV9rYqE5ufNbHsn7zh+pSeSZh1bUvv32/AdrUU9ac5x0EjateD7CXbvW6eXoG1piM/uUb4aqDPqCnpvzCRDQjRbql4o0S0+OxUXXx94p6nXtbyZQPySRwqmDCiKRx+5KjRWHAqcK9L5PNB3Nq08i9LgVyOzagWW7VIDaMrnFjuTu0EKzzTppa/hiPGhXJBUX6Gwmgjoh/altNhbZFe+H8ARlQjYTX92tQivNfjvMRBopr1cnSP6UAOQfEKlbkI2P57TrueeR3YqwNISpGOn7BPXmQjBZlgx2dpEli44Wm8VsSM0s10CAwEAAaOBtTCBsjAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNgYDVR0RBC8wLYIrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTAfBgNVHSMEGDAWgBQLxdObdnfWzaBcxau87tdSUtEuQjAdBgNVHQ4EFgQUC8XTm3Z31s2gXMWrvO7XUlLRLkIwDQYJKoZIhvcNAQELBQADggEBAD2Eo703wXQgB2vJn/RwTTcHGkeMkYXm0mWCxOSh4iCKVvqypBJrmLzRkMMJN0/10qIGciYWUl6EkL7yj48tpXXH01Ep0ONDdo9UYmKGp81Z4j3u3FBJTVQSdj2tnPOPZlYWaBkerIkcIeyWBRKvne1UBaobbk84epfBmUfAMFmyJEk+x+q7cqmsbjDtdrmhiWaInqCijpS2dW2MitJ5F7tBBS26SMTqLQteA2IOwIW1BMlYIPuSO3dKn/rYVS8RjL+x+MxP98vla5sichoEZwVWnXiXgFZ4n/asGqc+Da9q6ILLtInvgI5bi7kjJJ2ARTRC5/a+J/v3EL+t8SdnOO8="
            ],
            "x5t": "OOmzCzoCOhtyMJkhpppC_MSWxCw"
        },
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "4F3E9AD8C9A6F5EB3173006F4FA630E28F43DCE9",
            "n": "tGevqhkBGn8NB0dKxs8Ddxhn-xZPm55svcSlkJZEOwDOXDLl_0-iVOVKNJfcHHLHvMqa6zh2DDcpAWZi2FpeBAJupsrymqwzllxOODWKWoVIoaIjOO7h1JLiF9Knwuq-o6BPtKdwOT-bOrXRzChMtQsc5C1Auex-D0Z6loObBuK1Lkm0RK9ISQsLqBEwq8g0OOupI_shU1r2rT2G0nkZ0CvxVlQeUGShFi8Mdys2s5LPqBwjC4LKwjk8moWQV32KEccbTPKxnG_539DxRglHJgHPHisSVGsfZIUXi2chtXdQHZPdVve8ZRmknCykZtkJ6K87llSUXi7oyzhCIZdiUQ",
            "e": "AQAB",
            "x5c": [
                "MIIDrDCCApSgAwIBAgIQPQS35v3ITW6fNLO8GX5QBjANBgkqhkiG9w0BAQsFADA2MTQwMgYDVQQDEyt2c3RzLXZzdHNnaHJ0LWdoLXZzby1vYXV0aC52aXN1YWxzdHVkaW8uY29tMB4XDTI1MDgwNjE0MTEzMloXDTI3MDgwNjE0MjEzMlowNjE0MDIGA1UEAxMrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALRnr6oZARp/DQdHSsbPA3cYZ/sWT5uebL3EpZCWRDsAzlwy5f9PolTlSjSX3Bxyx7zKmus4dgw3KQFmYthaXgQCbqbK8pqsM5ZcTjg1ilqFSKGiIzju4dSS4hfSp8LqvqOgT7SncDk/mzq10cwoTLULHOQtQLnsfg9GepaDmwbitS5JtESvSEkLC6gRMKvINDjrqSP7IVNa9q09htJ5GdAr8VZUHlBkoRYvDHcrNrOSz6gcIwuCysI5PJqFkFd9ihHHG0zysZxv+d/Q8UYJRyYBzx4rElRrH2SFF4tnIbV3UB2T3Vb3vGUZpJwspGbZCeivO5ZUlF4u6Ms4QiGXYlECAwEAAaOBtTCBsjAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNgYDVR0RBC8wLYIrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTAfBgNVHSMEGDAWgBRKoYOga736JYE15vT7b4gWjC1hwTAdBgNVHQ4EFgQUSqGDoGu9+iWBNeb0+2+IFowtYcEwDQYJKoZIhvcNAQELBQADggEBAJVZIPtoZUlvqgu+Pl0nj8WopA8iuy1m7JRg5fg+bOIGFhXFR8+mH8prpeodjUQ40q2Hq6IwnVir+G56zVwAPf2HHksqdp8be9qjkTjD0mJorPCt/lumrKoNGOVmYffYuIyr73hwsl8fN6sGjAyXLFBkozE4s5ssbeodFxiYE1A61SXnzldC00M7qWleMWjTUBixiZ+R/eroddkLNBGDv9ewDrTQv1ipNec89+Wi7Wb6SAXNxBADiC5kVlFylBgHo3oZNg3KFzZS01REyc4zdH7v1wfZzilLluI6ygTyYRYpJCsKrX5D9JW196f2PCzcs+VXMfneRDnvyfjep7Y1Pi8="
            ],
            "x5t": "Tz6a2Mmm9esxcwBvT6Yw4o9D3Ok"
        }
    ]
}
```

## Gitlab

```json
{
    "keys": [
        {
            "kty": "RSA",
            "kid": "kewiQq9jiC84CvSsJYOB-N6A8WFLSV20Mb-y7IlWDSQ",
            "e": "AQAB",
            "n": "5RyvCSgBoOGNE03CMcJ9Bzo1JDvsU8XgddvRuJtdJAIq5zJ8fiUEGCnMfAZI4of36YXBuBalIycqkgxrRkSOENRUCWN45bf8xsQCcQ8zZxozu0St4w5S-aC7N7UTTarPZTp4BZH8ttUm-VnK4aEdMx9L3Izo0hxaJ135undTuA6gQpK-0nVsm6tRVq4akDe3OhC-7b2h6z7GWJX1SD4sAD3iaq4LZa8y1mvBBz6AIM9co8R-vU1_CduxKQc3KxCnqKALbEKXm0mTGsXha9aNv3pLNRNs_J-cCjBpb1EXAe_7qOURTiIHdv8_sdjcFTJ0OTeLWywuSf7mD0Wpx2LKcD6ImENbyq5IBuR1e2ghnh5Y9H33cuQ0FRni8ikq5W3xP3HSMfwlayhIAJN_WnmbhENRU-m2_hDPiD9JYF2CrQneLkE3kcazSdtarPbg9ZDiydHbKWCV-X7HxxIKEr9N7P1V5HKatF4ZUrG60e3eBnRyccPwmT66i9NYyrcy1_ZNN8D1DY8xh9kflUDy4dSYu4R7AEWxNJWQQov525v0MjD5FNAS03rpk4SuW3Mt7IP73m-_BpmIhW3LZsnmfd8xHRjf0M9veyJD0--ETGmh8t3_CXh3I3R9IbcSEntUl_2lCvc_6B-m8W-t2nZr4wvOq9-iaTQXAn1Au6EaOYWvDRE",
            "use": "sig",
            "alg": "RS256"
        },
        {
            "kty": "RSA",
            "kid": "4i3sFE7sxqNPOT7FdvcGA1ZVGGI_r-tsDXnEuYT4ZqE",
            "e": "AQAB",
            "n": "4cxDjTcJRJFID6UCgepPV45T1XDz_cLXSPgMur00WXB4jJrR9bfnZDx6dWqwps2dCw-lD3Fccj2oItwdRQ99In61l48MgiJaITf5JK2c63halNYiNo22_cyBG__nCkDZTZwEfGdfPRXSOWMg1E0pgGc1PoqwOdHZrQVqTcP3vWJt8bDQSOuoZBHSwVzDSjHPY6LmJMEO42H27t3ZkcYtS5crU8j2Yf-UH5U6rrSEyMdrCpc9IXe9WCmWjz5yOQa0r3U7M5OPEKD1-8wuP6_dPw0DyNO_Ei7UerVtsx5XSTd-Z5ujeB3PFVeAdtGxJ23oRNCq2MCOZBa58EGeRDLR7Q",
            "use": "sig",
            "alg": "RS256"
        },
        {
            "kty": "RSA",
            "kid": "UEtnUohTq58JiJzxHhBLSU0yTpsmW-9EY1Wykha6VIg",
            "e": "AQAB",
            "n": "9UAG0U59NZ3MBMQkjCVuA8c0ZHEL8SEljnXYYxAuuvy4P79XxTYNodmBAioe1CBsdOmFjjdtXzPIxYv_zEHwkI5WoL1U0r83Q8RSbcl_YSCjfq32TW1hj1KQe0bjzx1TohtnOZSIq-0_8QLbdJrwN7LnBHkalAdMYFk9qUEFlTP-jwUIxztmjpok_-d6W1621iDQwUzYqKiTYc7ZQdC3Bf5jv-8yTm7pMQrR0W6XvPNnRwJmGZdkDH1ZC6okTzLsaMBgMV5awtXJeSZqrR3Qy3ATX6hiitmld9K3FyKFyyIOpaygjltKVzNy5giwnDfTHaGs24Y51Jy1SZ51vqfEFQ",
            "use": "sig",
            "alg": "RS256"
        }
    ]
}
```

## AWS Cognito

```json
{
    "keys": [
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "UGIevE1I5DkrQL0VFF7nRif5Z5G5PXaHEArHtBu/HM0=",
            "kty": "RSA",
            "n": "s50y5_eTFpWiCtXWC_AGz6u3eX-sh2sVWetXAqGQwUjaNWmRNilDua0CMMSGdsprDlMG6OmNVukyea-HrUSC9rTrCvLigYRtS6XESfZdI8K0086DVBJG55pO51PQyMDYsWIFMFsnfmKw8t2rnrtPR-mfwBR-09g1oqO44ARfdBvsk1lW3UzpzImpwkRtn6DIpYFB5aZxKoLmLZxjabl2neh5EaO4BqS9SGRffl_YN6yhifP6T3b2Tku4VxeBgNCKjMKTHNjMMHUSspeDpfuweAfXmL76Hn-Tw4a-aqY5aJtSB2ylmyNLXOZT9D9iEBsGz7r3tvUxJ_6jbOiZZHEO_w",
            "use": "sig"
        },
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "cp0ki1D1mvwFpOogCSL60SbczuqkLnW1HRlYQLmteao=",
            "kty": "RSA",
            "n": "v7ZaQCHr9BP89rGzi6ltXawv-6ILGM59Ep74lvcEGyWq2DI0Q6a5vn_WnuiAAVHnOVXCmfkxQuK9qIqMsXFBZNVg7tFKYP5pFVBkvyD1eo9jjqz0Bkx_M15EPf1sn-F7wS75Zdcqa1TWf-jTV-RhuGgZe0QSWcpDD2tiVZxhTC-xZst3F6MP7Q5l3iOhPJHz3X1JqnY0jJCbV7S4xyQR-KbmBrwrjLb_sZqCRNrTb1dQpfmF2Sv9RcQiSdHdEyNthwpjl_aqehMfATvEqn8sN1OSmOOcshEXImYRlrr67CilvU0jtDjm9Z2QfjGpkwhGnNNx_XTClmKkkLS67cB0gw",
            "use": "sig"
        }
    ]
}
```
