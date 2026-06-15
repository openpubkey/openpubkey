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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
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
	require.ErrorContains(t, err, "incorrect public key supplied when GQ signing jwt")
	require.ErrorContains(t, err, "could not verify message using any of the signatures or keys")
	require.Nil(t, gqToken2)

	// Test specifying with extra claims
	expKey1 := "key1" // Expected claim keys, values
	expValue1 := "value1"
	expKey2 := "key2"
	expValue2 := "value2"

	gqTokenExtraClaims, err := GQ256SignJWT(&oidcPrivKey.PublicKey, idToken,
		WithExtraClaim(expKey1, expValue1),
		WithExtraClaim(expKey2, expValue2))
	require.NoError(t, err)

	retValue1, ok, err := getClaimInProtected(expKey1, gqTokenExtraClaims)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, expValue1, retValue1)

	retValue2, ok, err := getClaimInProtected(expKey2, gqTokenExtraClaims)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, expValue2, retValue2)

	// Test that we don't find a claim we didn't add
	retClaimValue, ok, err := getClaimInProtected("noSuchKey", gqTokenExtraClaims)
	require.NoError(t, err)
	require.False(t, ok, "we didn't add this claim, yet somehow it was in the protected header")
	require.Nil(t, retClaimValue)

	// Test that we throw the correct error if reserved header is used
	gqTokenReservedClaim, err := GQ256SignJWT(&oidcPrivKey.PublicKey, idToken,
		WithExtraClaim("alg", "ES256"))
	require.Error(t, err, "use of reserved claim name, alg, should throw an error")
	require.EqualError(t, err,
		"error creating GQ signature: use of reserved header name, alg, in additional headers",
		"incorrect error throw")
	require.Nil(t, gqTokenReservedClaim)
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

	_, err = jws.Verify(modifiedToken, jws.WithKey(jwa.RS256(), oidcPubKey))
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

func TestNewSignerVerifierRejectsInvalidExponents(t *testing.T) {
	for _, e := range []int{0, 1, 2, 4, 6} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		key.E = e
		sv, err := NewSignerVerifier(&key.PublicKey, 256)
		if err == nil {
			t.Errorf("NewSignerVerifier(E=%d) should have returned an error", e)
		}
		if sv != nil {
			t.Errorf("NewSignerVerifier(E=%d) should have returned nil SignerVerifier", e)
		}
	}
}

func TestTComputationForSoundness(t *testing.T) {
	// t = ceil(256 / floor(log2(E))), computed via integer arithmetic.
	tests := []struct {
		name     string
		exponent int
		wantT    int
	}{
		{"E=65537 standard", 65537, 16}, // ceil(256 / 16) = 16
		{"E=257", 257, 32},              // ceil(256 / 8) = 32
		{"E=17", 17, 64},                // ceil(256 / 4) = 64
		{"E=5", 5, 128},                 // ceil(256 / 2) = 128
		{"E=3 small exponent", 3, 256},  // ceil(256 / 1) = 256
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			key.E = tt.exponent
			sv, err := NewSignerVerifier(&key.PublicKey, 256)
			require.NoError(t, err)
			svImpl := sv.(*signerVerifier)
			if svImpl.t != tt.wantT {
				t.Errorf("NewSignerVerifier(E=%d, securityParam=256).t = %d, want %d", tt.exponent, svImpl.t, tt.wantT)
			}
		})
	}
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
	alg := jwa.RS256() // RSASSA-PKCS-v1.5 using SHA-256

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

func getClaimInProtected(claimKey string, token []byte) (any, bool, error) {
	headersB64, _, _, err := jws.SplitCompact(token)
	if err != nil {
		return nil, false, err
	}

	headersJson, err := util.Base64DecodeForJWT(headersB64)
	if err != nil {
		return nil, false, err
	}

	headers := jws.NewHeaders()
	err = json.Unmarshal(headersJson, &headers)
	if err != nil {
		return nil, false, err
	}

	var claimValue string
	err = headers.Get(claimKey, &claimValue)
	if err != nil {
		// swallow error and communicate via bool instead
		return nil, false, nil
	}
	return claimValue, true, nil
}
