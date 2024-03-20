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

		pubkeyRecord, err := finder.ByJTK(ctx, issuer, string(jktB64))
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

	wrongJTK := "not-a-jkt"
	pubkeyRecord, err = finder.ByJTK(ctx, issuer, wrongJTK)
	require.EqualError(t, err, "no matching public key found for jtk not-a-jkt")
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

		pubkeyRecord, err := finder.ByJTK(ctx, issuer, string(jktB64))
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

		pubkeyRecord, err := finder.ByJTK(ctx, issuer, string(jktB64))
		require.NoError(t, err)
		require.Equal(t, publicKeys[i], pubkeyRecord.PublicKey)
		require.Equal(t, algs[i], pubkeyRecord.Alg)
		require.Equal(t, issuer, pubkeyRecord.Issuer)
	}
}

func CreateIDToken(t *testing.T, issuer string, signer crypto.Signer, alg string, kid string) []byte {
	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, alg)

	// This lets us test JKT behavior when there is no kid
	if kid != "" {
		headers.Set(jws.KeyIDKey, kid)
	}
	headers.Set(jws.TypeKey, "JWT")

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
