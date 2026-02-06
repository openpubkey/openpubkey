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
	"fmt"
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

	for i := 0; i < 4; i++ {
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

	mockJwks, err := MockGetJwksByIssuer(publicKeys, keyIDs, algs)
	require.NoError(t, err)

	finder := &PublicKeyFinder{
		JwksFunc: mockJwks,
	}

	for i := 0; i < len(publicKeys); i++ {
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, keyIDs[i])
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := 0; i < len(publicKeys); i++ {
		pubkeyRecord, err := finder.ByToken(ctx, issuer, idTokens[i])
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := 0; i < len(publicKeys); i++ {
		jwk, err := jwk.Import(publicKeys[i])
		require.NoError(t, err)
		jkt, err := jwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jktB64 := util.Base64EncodeForJWT(jkt)

		pubkeyRecord, err := finder.ByJKT(ctx, issuer, string(jktB64))
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	// Test failure cases
	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "not-a-key-id")
	require.Error(t, err)
	require.Nil(t, pubkeyRecord)

	wrongSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongIdToken := CreateIDToken(t, issuer, wrongSigner, "RS256", "not-a-key-id")
	pubkeyRecord, err = finder.ByToken(ctx, issuer, wrongIdToken)
	require.EqualError(t, err, "no matching public key found for kid not-a-key-id")
	require.Nil(t, pubkeyRecord)

	// Tests we don't return the wrong Public Key even if not kid is supplied
	wrongIdToken2 := CreateIDToken(t, issuer, wrongSigner, "RS256", "")
	pubkeyRecord, err = finder.ByToken(ctx, issuer, wrongIdToken2)
	require.EqualError(t, err, "no matching public key found for kid ")
	require.Nil(t, pubkeyRecord)

	wrongJKT := "not-a-jkt"
	pubkeyRecord, err = finder.ByJKT(ctx, issuer, wrongJKT)
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

	finder := &PublicKeyFinder{
		JwksFunc: mockJwks,
	}

	for i := 0; i < len(publicKeys); i++ {
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234")
		require.EqualError(t, err, "no matching public key found for kid 1234", "no kid (keyID) ByKeyID should return nothing")
		require.Nil(t, pubkeyRecord)
	}

	for i := 0; i < len(publicKeys); i++ {
		pubkeyRecord, err := finder.ByToken(ctx, issuer, idTokens[i])
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := 0; i < len(publicKeys); i++ {
		jwk, err := jwk.Import(publicKeys[i])
		require.NoError(t, err)
		jkt, err := jwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jktB64 := util.Base64EncodeForJWT(jkt)

		pubkeyRecord, err := finder.ByJKT(ctx, issuer, string(jktB64))
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

	for i := 0; i < 4; i++ {
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

	finder := &PublicKeyFinder{
		JwksFunc: mockJwks,
	}

	for i := 0; i < len(publicKeys); i++ {
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, keyIDs[i])
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := 0; i < len(publicKeys); i++ {
		pubkeyRecord, err := finder.ByToken(ctx, issuer, idTokens[i])
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}

	for i := 0; i < len(publicKeys); i++ {
		jwk, err := jwk.Import(publicKeys[i])
		require.NoError(t, err)
		jkt, err := jwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jktB64 := util.Base64EncodeForJWT(jkt)

		pubkeyRecord, err := finder.ByJKT(ctx, issuer, string(jktB64))
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
