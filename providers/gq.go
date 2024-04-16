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

package providers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
)

func CreateGQToken(ctx context.Context, idToken []byte, op OpenIdProvider) ([]byte, error) {
	return createGQTokenAllParams(ctx, idToken, op, "", false)
}

func CreateGQBoundToken(ctx context.Context, idToken []byte, op OpenIdProvider, cicHash string) ([]byte, error) {
	return createGQTokenAllParams(ctx, idToken, op, cicHash, true)
}

func createGQTokenAllParams(ctx context.Context, idToken []byte, op OpenIdProvider, cicHash string, gqCommitment bool) ([]byte, error) {
	if cicHash != "" && !gqCommitment {
		// If gqCommitment is false, we will ignore the cicHash. This is a
		// misconfiguration, and we should fail because the caller is likely
		// expecting the cicHash to be included in the token.
		return nil, fmt.Errorf("misconfiguration, cicHash is set but gqCommitment is false, set gqCommitment to true to include cicHash in the gq signature")
	}
	headersB64, _, _, err := jws.SplitCompact(idToken)
	if err != nil {
		return nil, fmt.Errorf("error splitting compact ID Token: %w", err)
	}

	// TODO: We should create a util function for extracting headers from tokens
	headersJson, err := util.Base64DecodeForJWT(headersB64)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding ID Token headers: %w", err)
	}
	headers := jws.NewHeaders()
	err = json.Unmarshal(headersJson, &headers)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling ID Token headers: %w", err)
	}

	if headers.Algorithm() != "RS256" {
		return nil, fmt.Errorf("gq signatures require ID Token have signed with an RSA key, ID Token alg was (%s)", headers.Algorithm())
	}

	opKey, err := op.PublicKeyByToken(ctx, idToken)
	if err != nil {
		return nil, err
	}

	if opKey.Alg != "RS256" {
		return nil, fmt.Errorf("gq signatures require original provider to have signed with an RSA key, jWK.alg was (%s)", opKey.Alg)
	}

	rsaKey, ok := opKey.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("gq signatures require original provider to have signed with an RSA key")
	}
	jktB64, err := createJkt(rsaKey)
	if err != nil {
		return nil, err
	}

	if cicHash == "" {
		return gq.GQ256SignJWT(rsaKey, idToken, gq.WithExtraClaim("jkt", jktB64))
	} else {
		return gq.GQ256SignJWT(rsaKey, idToken, gq.WithExtraClaim("jkt", jktB64), gq.WithExtraClaim("cic", cicHash))
	}
}

func createJkt(publicKey crypto.PublicKey) (string, error) {
	jwkKey, err := jwk.PublicKeyOf(publicKey)
	if err != nil {
		return "", err
	}
	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return string(util.Base64EncodeForJWT(thumbprint)), nil
}
