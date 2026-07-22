// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestNewPublicKeyRecord(t *testing.T) {
	commonIssuer := "https://example.com"
	tests := []struct {
		name        string
		keyJson     map[string]string
		expectedAlg string
		shouldError bool
	}{
		{
			name: "alg=RS256",
			keyJson: map[string]string{
				jwk.AlgorithmKey: "RS256",
				jwk.KeyTypeKey:   "RSA",
				jwk.RSAEKey:      "AQAB",
				jwk.RSANKey:      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			},
			expectedAlg: jwa.RS256().String(),
		},
		{
			name: "alg=RS256 with private key",
			keyJson: map[string]string{
				jwk.AlgorithmKey: "RS256",
				jwk.KeyTypeKey:   "RSA",
				jwk.RSAEKey:      "AQAB",
				jwk.RSANKey:      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				jwk.RSADKey:      "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
				jwk.RSAPKey:      "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
				jwk.RSAQKey:      "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft0NGLzQGz7BqX_GJxPttJ0S3e6DfBz7HO6NpXsL6MYJrKXMNgj3Dv1xIx23DW-FUdxEZwHnTSWlJHzQU",
				jwk.RSADPKey:     "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
				jwk.RSADQKey:     "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
				jwk.RSAQIKey:     "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
			},
			expectedAlg: jwa.RS256().String(),
		},
		{
			name: "alg=ES256",
			keyJson: map[string]string{
				jwk.AlgorithmKey: "ES256",
				jwk.KeyTypeKey:   "EC",
				jwk.ECDSACrvKey:  "P-256",
				jwk.ECDSAXKey:    "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
				jwk.ECDSAYKey:    "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
				jwk.ECDSADKey:    "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
			},
			expectedAlg: jwa.ES256().String(),
		},
		{
			name: "alg=EdDSA",
			keyJson: map[string]string{
				jwk.AlgorithmKey: "EdDSA",
				jwk.KeyTypeKey:   "OKP",
				jwk.OKPCrvKey:    "Ed25519",
				jwk.OKPXKey:      "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			expectedAlg: jwa.EdDSA().String(),
		},
		{
			name: "alg is missing",
			keyJson: map[string]string{
				jwk.KeyTypeKey:  "RSA",
				jwk.KeyUsageKey: "sig",
				jwk.RSANKey:     "vRIL3aZt-xVqOZgMOr71ltWe9YY2Wf_B28C4Jl2nBSTEcFnf_eqOHZ8yzUBbLc4Nti2_ETcCsTUNuzS368BWkSgxc45JBH1wFSoWNFUSXaPt8mRwJYTF0H32iNhw_tBb9mvdQVgVs4Ci0dVJRYiz-ilk3PeO8wzlwRuwWIsaKFYlMyOKG9DVFbg93DmP5Tjq3C3oJlATyhAiJJc1T2trEP8960an33dDEaWwVAHh3c_34meAO4R6kLzIq0JnSsZMYB9O_6bMyIlzxmdZ8F442SynCUHxhnIh3yZew-xDdeHr6Ofl7KeVUcvSiZP9X44CaVJvknXQbBYNl-H7YF5RgQ",
				jwk.RSAEKey:     "AQAB",
			},
			// If "alg" key is missing, code assumes algorithm is RSA/RS256
			expectedAlg: jwa.RS256().String(),
		},
		{
			name: "alg=PS256",
			keyJson: map[string]string{
				jwk.AlgorithmKey: "PS256",
				jwk.KeyTypeKey:   "RSA",
				jwk.RSAEKey:      "AQAB",
				jwk.RSANKey:      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			},
			expectedAlg: jwa.PS256().String(),
		},
		{
			name: "alg is unknown",
			keyJson: map[string]string{
				jwk.AlgorithmKey: "RS512",
				jwk.KeyTypeKey:   "RSA",
				jwk.KeyUsageKey:  "sig",
				jwk.RSANKey:      "vRIL3aZt-xVqOZgMOr71ltWe9YY2Wf_B28C4Jl2nBSTEcFnf_eqOHZ8yzUBbLc4Nti2_ETcCsTUNuzS368BWkSgxc45JBH1wFSoWNFUSXaPt8mRwJYTF0H32iNhw_tBb9mvdQVgVs4Ci0dVJRYiz-ilk3PeO8wzlwRuwWIsaKFYlMyOKG9DVFbg93DmP5Tjq3C3oJlATyhAiJJc1T2trEP8960an33dDEaWwVAHh3c_34meAO4R6kLzIq0JnSsZMYB9O_6bMyIlzxmdZ8F442SynCUHxhnIh3yZew-xDdeHr6Ofl7KeVUcvSiZP9X44CaVJvknXQbBYNl-H7YF5RgQ",
				jwk.RSAEKey:      "AQAB",
			},
			shouldError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("TestNewPublicKeyRecord: keyJson: %#v", tt.keyJson)
			keyJsonBytes, err := json.Marshal(tt.keyJson)
			require.NoError(t, err, "failed to marshal keyJson map into JSON")
			key, err := jwk.ParseKey(keyJsonBytes)
			require.NoError(t, err, "jwk.ParseKey failed to parse keyJsonBytes")

			gotPublicKeyRecord, err := publicKeyRecordFromJWK(key, commonIssuer)

			if tt.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "NewPublicKeyRecord should succeed")
				require.Equal(t, tt.expectedAlg, gotPublicKeyRecord.Alg)
				require.Equal(t, commonIssuer, gotPublicKeyRecord.Issuer)
				require.NotNil(t, gotPublicKeyRecord.PublicKey)
			}
		})
	}
}

func TestPublicKeyFinder(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	publicKeys := []crypto.PublicKey{}
	keyIDs := []string{}
	algs := []string{}
	idTokens := [][]byte{}

	for i := range 4 {
		algOp := "RS256"
		signer, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		publicKeys = append(publicKeys, signer.Public())
		keyIDs = append(keyIDs, fmt.Sprintf("%d", i))
		algs = append(algs, algOp)

		idToken := CreateIDToken(t, issuer, signer, algOp, keyIDs[i])
		idTokens = append(idTokens, idToken)
	}

	// Let's add something unexpected
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKeys = append(publicKeys, signer.Public())
	keyIDs = append(keyIDs, "ABCDEF")
	algs = append(algs, jwa.ES256().String())
	idToken := CreateIDToken(t, issuer, signer, jwa.ES256().String(), "ABCDEF")
	idTokens = append(idTokens, idToken)

	// Add EdDSA key
	edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKeys = append(publicKeys, edPubKey)
	keyIDs = append(keyIDs, "ED25519-KEY")
	algs = append(algs, jwa.EdDSA().String())
	edToken := CreateIDToken(t, issuer, edPrivKey, jwa.EdDSA().String(), "ED25519-KEY")
	idTokens = append(idTokens, edToken)

	// Add PS256 key (RSASSA-PSS with RSA key)
	ps256Signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKeys = append(publicKeys, ps256Signer.Public())
	keyIDs = append(keyIDs, "PS256-KEY")
	algs = append(algs, jwa.PS256().String())
	ps256Token := CreateIDToken(t, issuer, ps256Signer, jwa.PS256().String(), "PS256-KEY")
	idTokens = append(idTokens, ps256Token)

	mockJwks, err := MockGetJwksByIssuer(publicKeys, keyIDs, algs)
	require.NoError(t, err)

	finder := NewPubkeyFinderWithCache(mockJwks, NewMapDiscoveryCache(), time.Hour)

	for i := range publicKeys {
		pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, keyIDs[i], true)
		require.NoError(t, err)
		if i == 0 {
			require.False(t, wasCached, "First call should have fetched fresh JWKS")
		} else {
			require.True(t, wasCached, "Second and subsequent calls should use cached JWKS")
		}
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := range publicKeys {
		pubkeyRecord, _, err := finder.ByToken(ctx, issuer, idTokens[i], true)
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := range publicKeys {
		jwk, err := jwk.Import(publicKeys[i])
		require.NoError(t, err)
		jkt, err := jwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jktB64 := util.Base64EncodeForJWT(jkt)

		pubkeyRecord, _, err := finder.ByJKT(ctx, issuer, string(jktB64), true)
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	// Test failure cases
	pubkeyRecord, _, err := finder.ByKeyID(ctx, issuer, "not-a-key-id", true)
	require.Error(t, err)
	require.Nil(t, pubkeyRecord)

	wrongSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongIdToken := CreateIDToken(t, issuer, wrongSigner, "RS256", "not-a-key-id")
	pubkeyRecord, _, err = finder.ByToken(ctx, issuer, wrongIdToken, true)
	require.EqualError(t, err, "no matching public key found for kid not-a-key-id")
	require.Nil(t, pubkeyRecord)

	// Tests we don't return the wrong Public Key even if not kid is supplied
	wrongIdToken2 := CreateIDToken(t, issuer, wrongSigner, "RS256", "")
	pubkeyRecord, _, err = finder.ByToken(ctx, issuer, wrongIdToken2, true)
	require.EqualError(t, err, "no matching public key found for kid ")
	require.Nil(t, pubkeyRecord)

	wrongJKT := "not-a-jkt"
	pubkeyRecord, _, err = finder.ByJKT(ctx, issuer, wrongJKT, true)
	require.EqualError(t, err, "no matching public key found for jkt not-a-jkt")
	require.Nil(t, pubkeyRecord)
}

func TestByTokenWhenOnePublicKey(t *testing.T) {
	ctx := context.Background()

	issuer := "testIssuer"

	publicKeys := []crypto.PublicKey{}
	algs := []string{}
	idTokens := [][]byte{}

	algOp := "RS256"
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKeys = append(publicKeys, signer.Public())
	algs = append(algs, algOp)

	idToken := CreateIDToken(t, issuer, signer, algOp, "")
	idTokens = append(idTokens, idToken)

	mockJwks, err := MockGetJwksByIssuer(publicKeys, nil, algs)
	require.NoError(t, err)

	finder := NewPubkeyFinderWithCache(mockJwks, NewMapDiscoveryCache(), time.Hour)

	for i := range publicKeys {
		pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.EqualError(t, err, "no matching public key found for kid 1234", "no kid (keyID) ByKeyID should return nothing")
		if i == 0 {
			require.False(t, wasCached, "First call should have fetched fresh JWKS")
		} else {
			require.True(t, wasCached, "Second and subsequent calls should use cached JWKS")
		}
		require.Nil(t, pubkeyRecord)
	}

	for i := range publicKeys {
		pubkeyRecord, _, err := finder.ByToken(ctx, issuer, idTokens[i], true)
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := range publicKeys {
		jwk, err := jwk.Import(publicKeys[i])
		require.NoError(t, err)
		jkt, err := jwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jktB64 := util.Base64EncodeForJWT(jkt)

		pubkeyRecord, _, err := finder.ByJKT(ctx, issuer, string(jktB64), true)
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}
}

func TestGQTokens(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	publicKeys := []crypto.PublicKey{}
	keyIDs := []string{}
	algs := []string{}
	idTokens := [][]byte{}

	for i := range 4 {
		algOp := "RS256"
		signer, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		publicKeys = append(publicKeys, signer.Public())
		keyIDs = append(keyIDs, fmt.Sprintf("%d", i))
		algs = append(algs, algOp)

		idToken := CreateIDToken(t, issuer, signer, algOp, keyIDs[i])

		rsaKey, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok)

		gqToken, err := gq.GQ256SignJWT(rsaKey, idToken)
		require.NoError(t, err)

		idTokens = append(idTokens, gqToken)
	}

	mockJwks, err := MockGetJwksByIssuer(publicKeys, keyIDs, algs)
	require.NoError(t, err)

	finder := NewPubkeyFinderWithCache(mockJwks, NewMapDiscoveryCache(), time.Hour)

	for i := range publicKeys {
		pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, keyIDs[i], true)
		require.NoError(t, err)
		if i == 0 {
			require.False(t, wasCached, "First call should have fetched fresh JWKS")
		} else {
			require.True(t, wasCached, "Second and subsequent calls should use cached JWKS")
		}
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := range publicKeys {
		pubkeyRecord, _, err := finder.ByToken(ctx, issuer, idTokens[i], true)
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := range publicKeys {
		jwk, err := jwk.Import(publicKeys[i])
		require.NoError(t, err)
		jkt, err := jwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jktB64 := util.Base64EncodeForJWT(jkt)

		pubkeyRecord, _, err := finder.ByJKT(ctx, issuer, string(jktB64), true)
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}
}

func CreateIDToken(t *testing.T, issuer string, signer crypto.Signer, alg string, kid string) []byte {
	headers := jws.NewHeaders()
	err := headers.Set(jws.AlgorithmKey, alg)
	require.NoError(t, err)

	// This lets us test JKT behavior when there is no kid
	if kid != "" {
		err := headers.Set(jws.KeyIDKey, kid)
		require.NoError(t, err)
	}
	err = headers.Set(jws.TypeKey, "JWT")
	require.NoError(t, err)

	payload := map[string]any{
		"sub": "me",
		"aud": "also me",
		"iss": issuer,
		"iat": time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	keyAlg, err := jwa.KeyAlgorithmFrom(alg)
	require.NoError(t, err)

	idToken, err := jws.Sign(
		payloadBytes,
		jws.WithKey(
			keyAlg,
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
	require.NoError(t, err)

	return idToken

}

func TestCacheHitAvoidsProviderFetch(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCache(), time.Hour)

	pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.False(t, wasCached, "First call should have fetched fresh JWKS")
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	require.Equal(t, 1, source.Calls())

	pubkeyRecord, wasCached, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, wasCached, "Second call should use cached JWKS")
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	require.Equal(t, 1, source.Calls(), "Cached call should not reach the provider")
}

func TestUncachedLookupAlwaysFetches(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCache(), time.Hour)

	for i := range 3 {
		pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", false)
		require.NoError(t, err)
		require.False(t, wasCached, "mayUseCache=false should never report a cached key")
		require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
		require.Equal(t, i+1, source.Calls(), "mayUseCache=false should always reach the provider")
	}
}

func TestCacheEntryExpiresAtStandardMaxAge(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clock := NewMockClock()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCacheWithClock(clock.Now), time.Hour)

	_, _, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.Equal(t, 1, source.Calls())

	clock.Advance(59 * time.Minute)
	_, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, wasCached, "Entry inside StandardMaxAge should still be served from cache")
	require.Equal(t, 1, source.Calls())

	clock.Advance(2 * time.Minute)
	_, wasCached, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.False(t, wasCached, "Entry past StandardMaxAge should be refetched")
	require.Equal(t, 2, source.Calls())
}

func TestFallbackUsedWhenProviderUnreachable(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clock := NewMockClock()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))

	// NewPubkeyFinderWithCache sets FallbackMaxAge to twice StandardMaxAge
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCacheWithClock(clock.Now), time.Hour)

	_, _, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	// The entry is now too old for a standard read but still inside FallbackMaxAge
	clock.Advance(90 * time.Minute)
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)

	pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err, "Stale entry inside FallbackMaxAge should be used when the provider is down")
	require.True(t, wasCached, "Fallback key came from the cache")
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
}

func TestFallbackExpiresAtFallbackMaxAge(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clock := NewMockClock()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCacheWithClock(clock.Now), time.Hour)

	_, _, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	clock.Advance(3 * time.Hour)
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)

	pubkeyRecord, _, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorIs(t, err, providerErr, "Provider error should surface once the fallback window has closed")
	require.Nil(t, pubkeyRecord)
}

func TestFallbackNotUsedWhenCacheBypassed(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clock := NewMockClock()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCacheWithClock(clock.Now), time.Hour)

	_, _, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)

	// A caller that asked to bypass the cache should not be handed a cached key,
	// whether that entry is fresh...
	clock.Advance(time.Minute)
	pubkeyRecord, _, err := finder.ByKeyID(ctx, issuer, "1234", false)
	require.ErrorIs(t, err, providerErr, "Fresh cache entry should not be served when mayUseCache is false")
	require.Nil(t, pubkeyRecord)

	// ...or stale enough to only be reachable through the fallback read
	clock.Advance(90 * time.Minute)
	pubkeyRecord, _, err = finder.ByKeyID(ctx, issuer, "1234", false)
	require.ErrorIs(t, err, providerErr, "Fallback entry should not be served when mayUseCache is false")
	require.Nil(t, pubkeyRecord)
}

func TestRotatedKeyRecoveredByUncachedLookup(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	oldSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{oldSigner.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCache(), time.Hour)

	_, _, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	// The provider rotates the key material behind the same kid
	source.SetJwks(createMockJwks(t, issuer, []crypto.PublicKey{newSigner.Public()}, []string{"1234"}, []string{"RS256"}))

	pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, wasCached)
	require.Equal(t, oldSigner.Public(), pubkeyRecord.PublicKey, "Cached lookup still returns the pre-rotation key")

	// This is the retry a verifier performs after failing to verify with a cached key
	pubkeyRecord, wasCached, err = finder.ByKeyID(ctx, issuer, "1234", false)
	require.NoError(t, err)
	require.False(t, wasCached)
	require.Equal(t, newSigner.Public(), pubkeyRecord.PublicKey, "Uncached retry should pick up the rotated key")

	// The refetch should also have refreshed the cache
	pubkeyRecord, wasCached, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, wasCached)
	require.Equal(t, newSigner.Public(), pubkeyRecord.PublicKey)
}

func TestCorruptCacheEntryIsRefetchedAndOverwritten(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cache := NewMapDiscoveryCache()
	require.NoError(t, cache.Write(issuer, []byte("{ this is not json")))

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, cache, time.Hour)

	pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err, "Unparseable cache entry should fall through to a fresh fetch")
	require.False(t, wasCached)
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	require.Equal(t, 1, source.Calls())

	// The fresh fetch should have replaced the corrupt entry
	pubkeyRecord, wasCached, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, wasCached)
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	require.Equal(t, 1, source.Calls())
}

func TestCorruptCacheEntryDoesNotMaskProviderError(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	cache := NewMapDiscoveryCache()
	require.NoError(t, cache.Write(issuer, []byte("{ this is not json")))

	source := NewMockJwksSource(nil)
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)
	finder := NewPubkeyFinderWithCache(source.Fetch, cache, time.Hour)

	pubkeyRecord, _, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorIs(t, err, providerErr, "A corrupt fallback entry should not hide why the provider fetch failed")
	require.Nil(t, pubkeyRecord)
}

func TestUnparseableFreshJwksFallsBackToCache(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clock := NewMockClock()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCacheWithClock(clock.Now), time.Hour)

	_, _, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	// The provider is reachable but serving something that isn't a JWKS
	clock.Advance(90 * time.Minute)
	source.SetJwks([]byte("<html>502 Bad Gateway</html>"))

	pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, wasCached)
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
}

func TestUnparseableFreshJwksWithoutCacheEntry(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	source := NewMockJwksSource([]byte("<html>502 Bad Gateway</html>"))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCache(), time.Hour)

	pubkeyRecord, _, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorContains(t, err, "unmarshal")
	require.Nil(t, pubkeyRecord)
}

func TestFinderWithoutCache(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))

	// This is how DefaultPubkeyFinder and the provider packages build a finder
	finder := &PublicKeyFinder{
		JwksFunc: source.Fetch,
	}

	for _, mayUseCache := range []bool{true, false} {
		pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", mayUseCache)
		require.NoError(t, err, "A finder with no cache should not fail or panic")
		require.False(t, wasCached)
		require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	}
	require.Equal(t, 2, source.Calls(), "A finder with no cache fetches on every lookup")

	// The fallback path must not touch the nil cache either
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)
	pubkeyRecord, _, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorIs(t, err, providerErr)
	require.Nil(t, pubkeyRecord)
}

func TestFinderWithNoOpCache(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	cache := NoOpCache{}
	require.NoError(t, cache.Write(issuer, []byte("anything")))
	cached, err := cache.Read(ctx, issuer, time.Hour)
	require.ErrorIs(t, err, ErrCacheMiss)
	require.Nil(t, cached)

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, cache, time.Hour)

	for i := range 3 {
		_, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.NoError(t, err)
		require.False(t, wasCached)
		require.Equal(t, i+1, source.Calls(), "NoOpCache should never satisfy a lookup")
	}
}

// TestZeroMaxAgeDisablesCache documents the misconfiguration case where a cache
// is supplied but the max ages are left at their zero value: every read misses
// and the cache is silently inert.
func TestZeroMaxAgeDisablesCache(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := &PublicKeyFinder{
		JwksFunc: source.Fetch,
		Cache:    NewMapDiscoveryCache(),
	}

	for i := range 2 {
		_, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.NoError(t, err)
		require.False(t, wasCached)
		require.Equal(t, i+1, source.Calls())
	}
}

func TestCacheWriteFailureIsNotFatal(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cache := NewMockWriteErrorCache(NewMapDiscoveryCache())
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, cache, time.Hour)

	for i := range 2 {
		pubkeyRecord, wasCached, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.NoError(t, err, "A failing cache write should not fail the lookup")
		require.False(t, wasCached)
		require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
		require.Equal(t, i+1, source.Calls(), "With no successful writes every lookup refetches")
	}
	require.Equal(t, 2, cache.Writes())
}

func TestMapDiscoveryCacheReadRespectsMaxAge(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	clock := NewMockClock()
	cache := NewMapDiscoveryCacheWithClock(clock.Now)

	cached, err := cache.Read(ctx, issuer, time.Hour)
	require.ErrorIs(t, err, ErrCacheMiss, "Empty cache should miss")
	require.Nil(t, cached)

	require.NoError(t, cache.Write(issuer, []byte("jwks-v1")))

	cached, err = cache.Read(ctx, issuer, time.Hour)
	require.NoError(t, err)
	require.Equal(t, []byte("jwks-v1"), cached)

	// The boundary is exclusive, an entry exactly maxAge old is a miss
	clock.Advance(time.Hour)
	cached, err = cache.Read(ctx, issuer, time.Hour)
	require.ErrorIs(t, err, ErrCacheMiss)
	require.Nil(t, cached)

	// But a wider maxAge still reaches it, which is what the fallback read does
	cached, err = cache.Read(ctx, issuer, 2*time.Hour)
	require.NoError(t, err)
	require.Equal(t, []byte("jwks-v1"), cached)
}

func TestMapDiscoveryCacheWriteResetsTimestamp(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	clock := NewMockClock()
	cache := NewMapDiscoveryCacheWithClock(clock.Now)

	require.NoError(t, cache.Write(issuer, []byte("jwks-v1")))
	clock.Advance(30 * time.Minute)
	require.NoError(t, cache.Write(issuer, []byte("jwks-v2")))

	clock.Advance(45 * time.Minute)
	cached, err := cache.Read(ctx, issuer, time.Hour)
	require.NoError(t, err, "The second write should have reset the timestamp as well as the value")
	require.Equal(t, []byte("jwks-v2"), cached)
}

func TestMapDiscoveryCacheExpire(t *testing.T) {
	ctx := context.Background()

	clock := NewMockClock()
	cache := NewMapDiscoveryCacheWithClock(clock.Now)

	require.NoError(t, cache.Write("issuerA", []byte("jwksA")))
	clock.Advance(30 * time.Minute)
	require.NoError(t, cache.Write("issuerB", []byte("jwksB")))

	// issuerA is now 75 minutes old, issuerB is 45 minutes old
	clock.Advance(45 * time.Minute)
	require.Equal(t, 1, cache.Expire(time.Hour), "Only issuerA is older than an hour")

	cached, err := cache.Read(ctx, "issuerA", 24*time.Hour)
	require.ErrorIs(t, err, ErrCacheMiss, "An expired entry should be gone regardless of maxAge")
	require.Nil(t, cached)

	cached, err = cache.Read(ctx, "issuerB", time.Hour)
	require.NoError(t, err)
	require.Equal(t, []byte("jwksB"), cached)

	require.Equal(t, 0, cache.Expire(time.Hour), "Nothing left to expire")
}

// TestMapDiscoveryCacheConcurrentAccess is intended to be run with -race
func TestMapDiscoveryCacheConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	cache := NewMapDiscoveryCache()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 50 {
				_ = cache.Write(issuer, []byte("jwks"))
				_, _ = cache.Read(ctx, issuer, time.Hour)
				if i%4 == 0 {
					cache.Expire(time.Hour)
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestConcurrentLookups is intended to be run with -race. It deliberately makes
// no assertion about the number of provider fetches: there is no singleflight,
// so concurrent cache misses may each reach the provider.
func TestConcurrentLookups(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCache(), time.Hour)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pubkeyRecord, _, err := finder.ByKeyID(ctx, issuer, "1234", true)
			if err != nil {
				errs <- err
				return
			}
			if pubkeyRecord.PublicKey == nil {
				errs <- errors.New("nil public key")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}
