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
	"bytes"
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
	"strings"
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

			gotPublicKeyRecord, err := publicKeyRecordFromJWK(key, commonIssuer, false)

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
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, keyIDs[i], true)
		require.NoError(t, err)
		if i == 0 {
			require.False(t, pubkeyRecord.WasCached, "First call should have fetched fresh JWKS")
		} else {
			require.True(t, pubkeyRecord.WasCached, "Second and subsequent calls should use cached JWKS")
		}
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := range publicKeys {
		pubkeyRecord, err := finder.ByToken(ctx, issuer, idTokens[i], true)
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

		pubkeyRecord, err := finder.ByJKT(ctx, issuer, string(jktB64), true)
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	// Test failure cases
	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "not-a-key-id", true)
	require.Error(t, err)
	require.Nil(t, pubkeyRecord.PublicKey)

	wrongSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongIdToken := CreateIDToken(t, issuer, wrongSigner, "RS256", "not-a-key-id")
	pubkeyRecord, err = finder.ByToken(ctx, issuer, wrongIdToken, true)
	require.EqualError(t, err, "no matching public key found for kid not-a-key-id")
	require.Nil(t, pubkeyRecord.PublicKey)

	// Tests we don't return the wrong Public Key even if not kid is supplied
	wrongIdToken2 := CreateIDToken(t, issuer, wrongSigner, "RS256", "")
	pubkeyRecord, err = finder.ByToken(ctx, issuer, wrongIdToken2, true)
	require.EqualError(t, err, "no matching public key found for kid ")
	require.Nil(t, pubkeyRecord.PublicKey)

	wrongJKT := "not-a-jkt"
	pubkeyRecord, err = finder.ByJKT(ctx, issuer, wrongJKT, true)
	require.EqualError(t, err, "no matching public key found for jkt not-a-jkt")
	require.Nil(t, pubkeyRecord.PublicKey)
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
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.EqualError(t, err, "no matching public key found for kid 1234", "no kid (keyID) ByKeyID should return nothing")
		if i == 0 {
			require.False(t, pubkeyRecord.WasCached, "First call should have fetched fresh JWKS")
		} else {
			require.True(t, pubkeyRecord.WasCached, "Second and subsequent calls should use cached JWKS")
		}
		require.Nil(t, pubkeyRecord.PublicKey)
	}

	for i := range publicKeys {
		pubkeyRecord, err := finder.ByToken(ctx, issuer, idTokens[i], true)
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

		pubkeyRecord, err := finder.ByJKT(ctx, issuer, string(jktB64), true)
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
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, keyIDs[i], true)
		require.NoError(t, err)
		if i == 0 {
			require.False(t, pubkeyRecord.WasCached, "First call should have fetched fresh JWKS")
		} else {
			require.True(t, pubkeyRecord.WasCached, "Second and subsequent calls should use cached JWKS")
		}
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := range publicKeys {
		pubkeyRecord, err := finder.ByToken(ctx, issuer, idTokens[i], true)
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

		pubkeyRecord, err := finder.ByJKT(ctx, issuer, string(jktB64), true)
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

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.False(t, pubkeyRecord.WasCached, "First call should have fetched fresh JWKS")
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	require.Equal(t, 1, source.Calls())

	pubkeyRecord, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, pubkeyRecord.WasCached, "Second call should use cached JWKS")
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
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", false)
		require.NoError(t, err)
		require.False(t, pubkeyRecord.WasCached, "mayUseCache=false should never report a cached key")
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

	_, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.Equal(t, 1, source.Calls())

	clock.Advance(59 * time.Minute)
	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, pubkeyRecord.WasCached, "Entry inside StandardMaxAge should still be served from cache")
	require.Equal(t, 1, source.Calls())

	clock.Advance(2 * time.Minute)
	pubkeyRecord, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.False(t, pubkeyRecord.WasCached, "Entry past StandardMaxAge should be refetched")
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

	_, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	// The entry is now too old for a standard read but still inside FallbackMaxAge
	clock.Advance(90 * time.Minute)
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err, "Stale entry inside FallbackMaxAge should be used when the provider is down")
	require.True(t, pubkeyRecord.WasCached, "Fallback key came from the cache")
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

	_, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	clock.Advance(3 * time.Hour)
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorIs(t, err, providerErr, "Provider error should surface once the fallback window has closed")
	require.Nil(t, pubkeyRecord.PublicKey)
}

func TestFallbackNotUsedWhenCacheBypassed(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clock := NewMockClock()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCacheWithClock(clock.Now), time.Hour)

	_, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)

	// A caller that asked to bypass the cache should not be handed a cached key,
	// whether that entry is fresh...
	clock.Advance(time.Minute)
	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", false)
	require.ErrorIs(t, err, providerErr, "Fresh cache entry should not be served when mayUseCache is false")
	require.Nil(t, pubkeyRecord.PublicKey)

	// ...or stale enough to only be reachable through the fallback read
	clock.Advance(90 * time.Minute)
	pubkeyRecord, err = finder.ByKeyID(ctx, issuer, "1234", false)
	require.ErrorIs(t, err, providerErr, "Fallback entry should not be served when mayUseCache is false")
	require.Nil(t, pubkeyRecord.PublicKey)
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

	_, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	// The provider rotates the key material behind the same kid
	source.SetJwks(createMockJwks(t, issuer, []crypto.PublicKey{newSigner.Public()}, []string{"1234"}, []string{"RS256"}))

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, pubkeyRecord.WasCached)
	require.Equal(t, oldSigner.Public(), pubkeyRecord.PublicKey, "Cached lookup still returns the pre-rotation key")

	// This is the retry a verifier performs after failing to verify with a cached key
	pubkeyRecord, err = finder.ByKeyID(ctx, issuer, "1234", false)
	require.NoError(t, err)
	require.False(t, pubkeyRecord.WasCached)
	require.Equal(t, newSigner.Public(), pubkeyRecord.PublicKey, "Uncached retry should pick up the rotated key")

	// The refetch should also have refreshed the cache
	pubkeyRecord, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, pubkeyRecord.WasCached)
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

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err, "Unparseable cache entry should fall through to a fresh fetch")
	require.False(t, pubkeyRecord.WasCached)
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	require.Equal(t, 1, source.Calls())

	// The fresh fetch should have replaced the corrupt entry
	pubkeyRecord, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, pubkeyRecord.WasCached)
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

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorIs(t, err, providerErr, "A corrupt fallback entry should not hide why the provider fetch failed")
	require.Nil(t, pubkeyRecord.PublicKey)
}

func TestUnparseableFreshJwksFallsBackToCache(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clock := NewMockClock()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCacheWithClock(clock.Now), time.Hour)

	_, err = finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)

	// The provider is reachable but serving something that isn't a JWKS
	clock.Advance(90 * time.Minute)
	source.SetJwks([]byte("<html>502 Bad Gateway</html>"))

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err)
	require.True(t, pubkeyRecord.WasCached)
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
}

func TestUnparseableFreshJwksWithoutCacheEntry(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	source := NewMockJwksSource([]byte("<html>502 Bad Gateway</html>"))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCache(), time.Hour)

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorContains(t, err, "unmarshal")
	require.Nil(t, pubkeyRecord.PublicKey)
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
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", mayUseCache)
		require.NoError(t, err, "A finder with no cache should not fail or panic")
		require.False(t, pubkeyRecord.WasCached)
		require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	}
	require.Equal(t, 2, source.Calls(), "A finder with no cache fetches on every lookup")

	// The fallback path must not touch the nil cache either
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)
	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorIs(t, err, providerErr)
	require.Nil(t, pubkeyRecord.PublicKey)
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
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.NoError(t, err)
		require.False(t, pubkeyRecord.WasCached)
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
		JwksFunc:    source.Fetch,
		CacheConfig: DiscoveryCacheConfig{Cache: NewMapDiscoveryCache()},
	}

	for i := range 2 {
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.NoError(t, err)
		require.False(t, pubkeyRecord.WasCached)
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
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.NoError(t, err, "A failing cache write should not fail the lookup")
		require.False(t, pubkeyRecord.WasCached)
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
			pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
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

// --- Lenient JWKS parsing (issue #403) ---

// An entry no jwx build can decode (the EC point is not on the P-256 curve),
// the hello.coop Ed25519 entry from jwksWithEd25519Alg, and a valid ES256 key.
const jwksWithUndecodableEntry = `{"keys":[
	{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iD6aTuMHLsPj6tQXJRx4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7xqOsmKAjSr0tHtjWWE","alg":"ES256","kid":"broken-ec","use":"sig"},
	{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlnw-vv-DE0Ts","alg":"Ed25519","kid":"ed25519-as-alg","use":"sig"},
	{"kty":"EC","crv":"P-256","x":"7pyPlY0DYYm78D-BugKXrNDxXn2NfOibB-wV3IMGBRg","y":"i_A-q4Sbk1nIDFJobjyOkrMvcinsacTWFa8bL8BfOLs","alg":"ES256","kid":"good-es256","use":"sig"}
]}`

// The exact entry shape that broke logins against a real provider
// (openpubkey/opkssh#655): an OKP key whose alg is "Ed25519". "Ed25519" is a
// crv, not an alg, but providers publish it anyway.
const jwksWithEd25519Alg = `{"keys":[
	{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlnw-vv-DE0Ts","alg":"Ed25519","kid":"ed25519-as-alg","use":"sig"}
]}`

func TestParseJwksRetainsUndecodableEntries(t *testing.T) {
	jwks, err := parseJwks([]byte(jwksWithUndecodableEntry))
	require.NoError(t, err, "An undecodable entry must not fail the whole JWKS")
	require.Equal(t, 3, jwks.Len(), "The undecodable entry should be retained, not dropped")

	// The broken entry stays addressable by its kid, but exports no key
	broken, ok := jwks.LookupKeyID("broken-ec")
	require.True(t, ok, "The retained entry should keep its kid")
	var brokenPub any
	require.Error(t, jwk.Export(broken, &brokenPub), "A retained entry must not export a usable key")

	// The good key remains fully usable
	good, ok := jwks.LookupKeyID("good-es256")
	require.True(t, ok)
	var pub any
	require.NoError(t, jwk.Export(good, &pub))
	require.IsType(t, &ecdsa.PublicKey{}, pub)
}

func TestParseJwksAcceptsOkpKeyWithEd25519Alg(t *testing.T) {
	jwks, err := parseJwks([]byte(jwksWithEd25519Alg))
	require.NoError(t, err, "The alg=Ed25519 OKP entry from opkssh issue 655 should parse")
	require.Equal(t, 1, jwks.Len())

	key, ok := jwks.LookupKeyID("ed25519-as-alg")
	require.True(t, ok)
	var pub any
	require.NoError(t, jwk.Export(key, &pub))
	require.IsType(t, ed25519.PublicKey{}, pub)
}

func TestParseJwksStillRejectsGarbage(t *testing.T) {
	// Leniency is about unknown JWK entries, not about accepting any bytes as
	// a JWKS: the provider-error fallback path depends on garbage failing.
	_, err := parseJwks([]byte("<html>502 Bad Gateway</html>"))
	require.Error(t, err)
}

func TestByKeyIDIgnoresUndecodableJwksEntries(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"
	source := NewMockJwksSource([]byte(jwksWithUndecodableEntry))
	finder := &PublicKeyFinder{JwksFunc: source.Fetch}

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "good-es256", false)
	require.NoError(t, err, "A JWKS with one undecodable entry should still resolve its usable keys")
	require.Equal(t, "ES256", pubkeyRecord.Alg)
	require.IsType(t, &ecdsa.PublicKey{}, pubkeyRecord.PublicKey)
	require.False(t, pubkeyRecord.WasCached)
}

func TestByKeyIDKidMatchingOnlyUndecodableEntryFails(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"
	source := NewMockJwksSource([]byte(jwksWithUndecodableEntry))
	finder := &PublicKeyFinder{JwksFunc: source.Fetch}

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "broken-ec", false)
	require.Error(t, err, "A kid that only matches a retained entry has no usable key behind it")
	require.ErrorContains(t, err, "unsupported")
	require.Nil(t, pubkeyRecord.PublicKey)
}

func TestByJKTSearchesPastUndecodableJwksEntries(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"
	source := NewMockJwksSource([]byte(jwksWithUndecodableEntry))
	finder := &PublicKeyFinder{JwksFunc: source.Fetch}

	jwks, err := parseJwks([]byte(jwksWithUndecodableEntry))
	require.NoError(t, err)
	good, ok := jwks.LookupKeyID("good-es256")
	require.True(t, ok)
	thumbprint, err := good.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	jkt := string(util.Base64EncodeForJWT(thumbprint))

	pubkeyRecord, err := finder.ByJKT(ctx, issuer, jkt, false)
	require.NoError(t, err, "A retained undecodable entry must not abort the jkt search")
	require.Equal(t, "ES256", pubkeyRecord.Alg)
	require.IsType(t, &ecdsa.PublicKey{}, pubkeyRecord.PublicKey)
}

func TestByKeyIDResolvesOkpKeyWithEd25519Alg(t *testing.T) {
	source := NewMockJwksSource([]byte(jwksWithEd25519Alg))
	finder := &PublicKeyFinder{JwksFunc: source.Fetch}

	pubkeyRecord, err := finder.ByKeyID(context.Background(), "testIssuer", "ed25519-as-alg", false)
	require.NoError(t, err)
	require.Equal(t, "Ed25519", pubkeyRecord.Alg)
	require.IsType(t, ed25519.PublicKey{}, pubkeyRecord.PublicKey)
}

const goodEs256JwksEntry = `{"kty":"EC","crv":"P-256","x":"7pyPlY0DYYm78D-BugKXrNDxXn2NfOibB-wV3IMGBRg","y":"i_A-q4Sbk1nIDFJobjyOkrMvcinsacTWFa8bL8BfOLs","alg":"ES256","kid":"good-es256","use":"sig"}`

func TestByKeyIDWithEntriesJwxCannotDecode(t *testing.T) {
	testCases := []struct {
		name     string
		entry    string
		kid      string
		expError string
	}{
		{name: "unknown key type",
			entry:    `{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA","kid":"bad"}`,
			kid:      "bad",
			expError: "invalid key type from JSON (AKP)"},
		{name: "unknown alg on a known key type",
			entry:    `{"kty":"RSA","n":"xmlLIdOgNutTVqp1OjhWlpdJpKofW6CBsV4BtKH1fYagLexPWe2FGKgUdl8YbD25ty7xnCy7NAOLaJjmcH7jvKBChbH4jnSeZqFjURjtDmP4vN4sMyayDg-7F3iYNHRduoenDOWsVpWn201zTIgV5-hyfJVJEYs6zN8eCI-PCmud0BeI5cDUI-mPrN8weH3upi6V7PYUeQgxtMLhVWTLl1AYAr0LXt_hJhlgCQFhaVgkPjuEQr76CroCXJn2NkdbOcFH1yIax83OssaLtfzcr6X9cy_meYW2peGYkgjw3xUPYjYR8TrabRWwlTVBheXTaL-bz3eW81lIQL3qChxGaw","e":"AQAB","alg":"RS999","kid":"bad"}`,
			kid:      "bad",
			expError: "invalid key algorithm"},
		{name: "RSA key under 2048 bits",
			entry:    `{"kty":"RSA","n":"1z7H3pupnByazSiPAZquWgicfDHChB-3OnWKSxz49zKZbAjAc9ioMf-M5c5uZGbJ-4EcokGiBWj_2SBBkGmVit7r02NneQPmu8JkRHjbN7A5d3_aepa_KkcdgSN7dOMGi-4Dlj1uOGE7mT7mYvZ60vHZZha4jW_AEBPyQ9tJOyk","e":"AQAB","alg":"RS256","kid":"bad"}`,
			kid:      "bad",
			expError: "rsa modulus too small"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwks := `{"keys":[` + tc.entry + `,` + goodEs256JwksEntry + `]}`
			finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource([]byte(jwks)).Fetch}

			pubkeyRecord, err := finder.ByKeyID(context.Background(), "testIssuer", "good-es256", false)
			require.NoError(t, err, "The other keys in the JWKS must stay usable")
			require.Equal(t, "ES256", pubkeyRecord.Alg)

			_, err = finder.ByKeyID(context.Background(), "testIssuer", tc.kid, false)
			require.ErrorContains(t, err, tc.expError)
		})
	}
}

func TestCachedJwksWithUndecodableEntry(t *testing.T) {
	source := NewMockJwksSource([]byte(jwksWithUndecodableEntry))
	finder := NewPubkeyFinderWithCache(source.Fetch, NewMapDiscoveryCache(), time.Hour)

	for i, wantCached := range []bool{false, true} {
		pubkeyRecord, err := finder.ByKeyID(context.Background(), "testIssuer", "good-es256", true)
		require.NoError(t, err, "lookup %d", i)
		require.Equal(t, wantCached, pubkeyRecord.WasCached, "lookup %d", i)
		require.IsType(t, &ecdsa.PublicKey{}, pubkeyRecord.PublicKey)
	}
}

func publicJwkEntry(t *testing.T, pubKey crypto.PublicKey, alg string, kid string) string {
	key, err := jwk.PublicKeyOf(pubKey)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.AlgorithmKey, alg))
	if kid != "" {
		require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	}
	entry, err := json.Marshal(key)
	require.NoError(t, err)
	return string(entry)
}

func jwksOf(entries ...string) []byte {
	return []byte(`{"keys":[` + strings.Join(entries, ",") + `]}`)
}

const unknownKtyEntrySharedKid = `{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA","kid":"shared"}`

func TestByKeyIDSharedKidSkipsUnusableEntry(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	goodEntry := publicJwkEntry(t, ecKey.Public(), "ES256", "shared")

	testCases := []struct {
		name string
		jwks []byte
	}{
		{name: "unusable entry first", jwks: jwksOf(unknownKtyEntrySharedKid, goodEntry)},
		{name: "unusable entry last", jwks: jwksOf(goodEntry, unknownKtyEntrySharedKid)},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var warnings bytes.Buffer
			finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(tc.jwks).Fetch}
			finder.SetErrWriter(&warnings)

			pubkeyRecord, err := finder.ByKeyID(context.Background(), "testIssuer", "shared", false)
			require.NoError(t, err, "An unusable entry must not hide a usable key with the same kid")
			require.Equal(t, ecKey.Public(), pubkeyRecord.PublicKey)
			require.Contains(t, warnings.String(), `kid "shared": skipping unusable key`)
			require.Contains(t, warnings.String(), "invalid key type from JSON (AKP)")
		})
	}
}

func TestByKeyIDSharedKidAllUnusable(t *testing.T) {
	smallRsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	smallRsaEntry := fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB","alg":"RS256","kid":"shared"}`,
		util.Base64EncodeForJWT(smallRsaKey.N.Bytes()))
	jwks := jwksOf(unknownKtyEntrySharedKid, smallRsaEntry)
	finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(jwks).Fetch}

	_, err = finder.ByKeyID(context.Background(), "testIssuer", "shared", false)
	require.ErrorContains(t, err, "invalid key type from JSON (AKP)")
	require.ErrorContains(t, err, "rsa modulus too small")
}

func TestByTokenFiltersByAlgThenKid(t *testing.T) {
	issuer := "testIssuer"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwks := jwksOf(
		publicJwkEntry(t, rsaKey.Public(), "RS256", "shared"),
		publicJwkEntry(t, ecKey.Public(), "ES256", "shared"),
		publicJwkEntry(t, edKey.Public(), "Ed25519", "shared"),
	)
	var warnings bytes.Buffer
	finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(jwks).Fetch}
	finder.SetErrWriter(&warnings)

	testCases := []struct {
		tokenAlg string
		signer   crypto.Signer
		expError string
	}{
		{tokenAlg: "RS256", signer: rsaKey},
		{tokenAlg: "ES256", signer: ecKey},
		{tokenAlg: "Ed25519", signer: edKey},
		{tokenAlg: "EdDSA", signer: edKey},
		{tokenAlg: "PS256", signer: rsaKey,
			expError: `no key with kid "shared" is published for alg PS256 (published for: RS256, ES256, Ed25519)`},
	}
	for _, tc := range testCases {
		t.Run(tc.tokenAlg, func(t *testing.T) {
			token := CreateIDToken(t, issuer, tc.signer, tc.tokenAlg, "shared")
			pubkeyRecord, err := finder.ByToken(context.Background(), issuer, token, false)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.signer.Public(), pubkeyRecord.PublicKey)
		})
	}
	require.Empty(t, warnings.String(), "Keys sharing a kid but published for different algs are not duplicates for a token")

	pubkeyRecord, err := finder.ByKeyID(context.Background(), issuer, "shared", false)
	require.NoError(t, err)
	require.Equal(t, rsaKey.Public(), pubkeyRecord.PublicKey, "Without a token alg the first usable key is returned")
	require.Contains(t, warnings.String(), `has 3 keys with kid "shared"`)
}

func TestByTokenRequiresKeyPublishedForTokenAlg(t *testing.T) {
	issuer := "testIssuer"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		signer   crypto.Signer
		keyAlg   string
		tokenAlg string
		expError string
	}{
		{name: "RS256 key, RS256 token", signer: rsaKey, keyAlg: "RS256", tokenAlg: "RS256"},
		{name: "RS256 key, PS256 token", signer: rsaKey, keyAlg: "RS256", tokenAlg: "PS256",
			expError: `no key with kid "k" is published for alg PS256 (published for: RS256)`},
		{name: "PS256 key, RS256 token", signer: rsaKey, keyAlg: "PS256", tokenAlg: "RS256",
			expError: `no key with kid "k" is published for alg RS256 (published for: PS256)`},
		{name: "key without alg, RS256 token", signer: rsaKey, keyAlg: "", tokenAlg: "RS256"},
		{name: "key without alg, PS256 token", signer: rsaKey, keyAlg: "", tokenAlg: "PS256",
			expError: `no key with kid "k" is published for alg PS256 (published for: RS256)`},
		{name: "EdDSA key, Ed25519 token", signer: edKey, keyAlg: "EdDSA", tokenAlg: "Ed25519"},
		{name: "Ed25519 key, EdDSA token", signer: edKey, keyAlg: "Ed25519", tokenAlg: "EdDSA"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwks := jwksWithoutAlg(t, tc.signer.Public(), "k")
			if tc.keyAlg != "" {
				jwks = jwksOf(publicJwkEntry(t, tc.signer.Public(), tc.keyAlg, "k"))
			}
			finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(jwks).Fetch}
			token := CreateIDToken(t, issuer, tc.signer, tc.tokenAlg, "k")

			pubkeyRecord, err := finder.ByToken(context.Background(), issuer, token, false)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.signer.Public(), pubkeyRecord.PublicKey)
		})
	}
}

func jwksWithoutAlg(t *testing.T, pubKey crypto.PublicKey, kid string) []byte {
	key, err := jwk.PublicKeyOf(pubKey)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	entry, err := json.Marshal(key)
	require.NoError(t, err)
	return jwksOf(string(entry))
}

func TestByTokenWithoutKidFiltersByAlg(t *testing.T) {
	issuer := "testIssuer"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks := jwksOf(
		publicJwkEntry(t, rsaKey.Public(), "RS256", ""),
		publicJwkEntry(t, ecKey.Public(), "ES256", ""),
	)
	finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(jwks).Fetch}

	token := CreateIDToken(t, issuer, ecKey, "ES256", "")
	pubkeyRecord, err := finder.ByToken(context.Background(), issuer, token, false)
	require.NoError(t, err, "Only one key is published for the token's alg")
	require.Equal(t, ecKey.Public(), pubkeyRecord.PublicKey)

	_, err = finder.ByKeyID(context.Background(), issuer, "", false)
	require.ErrorContains(t, err, "no matching public key found for kid ", "Without an alg both keys are candidates")
}

func TestByKeyIDWithoutKidCountsOnlyUsableKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherEcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	unknownKtyEntry := `{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA"}`

	testCases := []struct {
		name     string
		jwks     []byte
		expKey   crypto.PublicKey
		expError string
		expWarn  string
	}{
		{name: "one usable key and one unusable entry",
			jwks:    jwksOf(unknownKtyEntry, publicJwkEntry(t, ecKey.Public(), "ES256", "")),
			expKey:  ecKey.Public(),
			expWarn: "token has no kid: skipping unusable key"},
		{name: "two usable keys",
			jwks:     jwksOf(publicJwkEntry(t, ecKey.Public(), "ES256", ""), publicJwkEntry(t, otherEcKey.Public(), "ES256", "")),
			expError: "no matching public key found for kid "},
		{name: "only an unusable entry",
			jwks:     jwksOf(unknownKtyEntry),
			expError: "invalid key type from JSON (AKP)"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var warnings bytes.Buffer
			finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(tc.jwks).Fetch}
			finder.SetErrWriter(&warnings)

			pubkeyRecord, err := finder.ByKeyID(context.Background(), "testIssuer", "", false)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expKey, pubkeyRecord.PublicKey)
			require.Contains(t, warnings.String(), tc.expWarn)
		})
	}
}

func TestByTokenSharedKidUsesOriginalAlgOfGQToken(t *testing.T) {
	issuer := "testIssuer"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks := jwksOf(
		publicJwkEntry(t, ecKey.Public(), "ES256", "shared"),
		publicJwkEntry(t, rsaKey.Public(), "RS256", "shared"),
	)
	finder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(jwks).Fetch}

	idToken := CreateIDToken(t, issuer, rsaKey, "RS256", "shared")
	gqToken, err := gq.GQ256SignJWT(&rsaKey.PublicKey, idToken)
	require.NoError(t, err)

	pubkeyRecord, err := finder.ByToken(context.Background(), issuer, gqToken, false)
	require.NoError(t, err)
	require.Equal(t, rsaKey.Public(), pubkeyRecord.PublicKey)

	psFinder := &PublicKeyFinder{JwksFunc: NewMockJwksSource(jwksOf(publicJwkEntry(t, rsaKey.Public(), "PS256", "shared"))).Fetch}
	_, err = psFinder.ByToken(context.Background(), issuer, gqToken, false)
	require.ErrorContains(t, err, "is published for alg RS256 (published for: PS256)", "A GQ token needs a key published for RS256")
}
