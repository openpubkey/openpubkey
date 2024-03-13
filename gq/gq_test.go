// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gq

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyJWT(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	require.NoError(t, err)

	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	require.NoError(t, err)

	gqToken, err := signerVerifier.SignJWT(idToken)
	require.NoError(t, err)

	ok := signerVerifier.VerifyJWT(gqToken)
	require.True(t, ok, "signature verification failed")
}

func TestGQ256SignJWT(t *testing.T) {
	for i := 0; i < 100; i++ {
		oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		idToken, err := createOIDCToken(oidcPrivKey, "test")
		require.NoError(t, err)

		gqToken1, err := GQ256SignJWT(&oidcPrivKey.PublicKey, idToken)
		require.NoError(t, err)
		ok, err := GQ256VerifyJWT(&oidcPrivKey.PublicKey, gqToken1)
		require.NoError(t, err)
		require.True(t, ok)

		// Test that we throw the correct error if the wrong RSA public key is sent to SignJWT
		oidcPrivKeyWrong, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		require.NotEqual(t, oidcPrivKey, oidcPrivKeyWrong)

		gqToken2, err := GQ256SignJWT(&oidcPrivKeyWrong.PublicKey, idToken)
		require.EqualError(t, err, "incorrect public key supplied when GQ signing jwt: could not verify message using any of the signatures or keys")
		require.Nil(t, gqToken2)
	}
}

func TestVerifyModifiedIdPayload(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	require.NoError(t, err)

	// modify the ID Token payload to detect IdP signature invalidity via GQ verify
	modifiedToken, err := modifyTokenPayload(idToken, "fail")
	require.NoError(t, err)

	_, err = jws.Verify(modifiedToken, jws.WithKey(jwa.RS256, oidcPubKey))
	require.Error(t, err, "ID token signature should fail for modified token")

	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	require.NoError(t, err)
	gqToken, err := signerVerifier.SignJWT(modifiedToken)
	require.NoError(t, err)

	ok := signerVerifier.VerifyJWT(gqToken)
	require.False(t, ok, "GQ signature verification passed for invalid payload")
}

func TestVerifyModifiedGqPayload(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	require.NoError(t, err)

	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	require.NoError(t, err)
	gqToken, err := signerVerifier.SignJWT(idToken)
	require.NoError(t, err)
	// modify the ID Token payload to detect GQ signature invalidity
	modifiedToken, err := modifyTokenPayload(gqToken, "fail")
	require.NoError(t, err)

	ok := signerVerifier.VerifyJWT(modifiedToken)
	require.False(t, ok, "GQ signature verification passed for invalid payload")

}

func modifyTokenPayload(token []byte, audience string) ([]byte, error) {
	headers, _, signature, err := jws.SplitCompact(token)
	if err != nil {
		return nil, err
	}
	newPayload := map[string]any{
		"sub": "1",
		"iss": "test",
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	modifiedPayload, err := json.Marshal(newPayload)
	if err != nil {
		return nil, err
	}
	newToken := util.JoinJWTSegments(headers, util.Base64EncodeForJWT(modifiedPayload), signature)
	return newToken, nil
}

func createOIDCToken(oidcPrivKey *rsa.PrivateKey, audience string) ([]byte, error) {
	alg := jwa.RS256 // RSASSA-PKCS-v1.5 using SHA-256

	oidcHeader := jws.NewHeaders()
	err := oidcHeader.Set(jws.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}
	err = oidcHeader.Set(jws.TypeKey, "JWT")
	if err != nil {
		return nil, err
	}

	oidcPayload := map[string]any{
		"sub": "1",
		"iss": "test",
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(oidcPayload)
	if err != nil {
		return nil, err
	}

	return jws.Sign(
		payloadBytes,
		jws.WithKey(
			alg,
			oidcPrivKey,
			jws.WithProtectedHeaders(oidcHeader),
		),
	)
}
