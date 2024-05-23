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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
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
			expectedAlg: jwa.RS256.String(),
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
			expectedAlg: jwa.ES256.String(),
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
			expectedAlg: jwa.RS256.String(),
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

			gotPublicKeyRecord, err := NewPublicKeyRecord(key, commonIssuer)

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
	algs = append(algs, string(jwa.ES256))
	idToken := CreateIDToken(t, issuer, signer, string(jwa.ES256), "ABCDEF")
	idTokens = append(idTokens, idToken)

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
		jwk, err := jwk.FromRaw(publicKeys[i])
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
		jwk, err := jwk.FromRaw(publicKeys[i])
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
		jwk, err := jwk.FromRaw(publicKeys[i])
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

	idToken, err := jws.Sign(
		payloadBytes,
		jws.WithKey(
			jwa.KeyAlgorithmFrom(alg),
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
	require.NoError(t, err)

	return idToken

}
