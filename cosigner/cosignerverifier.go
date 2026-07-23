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

package cosigner

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
)

type DefaultCosignerVerifier struct {
	issuer  string
	options CosignerVerifierOpts
}

type CosignerVerifierOpts struct {
	// Strict specifies whether or not a pk token MUST contain a signature by this cosigner.
	// Defaults to true.
	Strict *bool
	// Allows users to set custom function for discovering public key of Cosigner
	DiscoverPublicKey *discover.PublicKeyFinder
}

func NewCosignerVerifier(issuer string, options CosignerVerifierOpts) *DefaultCosignerVerifier {
	v := &DefaultCosignerVerifier{
		issuer:  issuer,
		options: options,
	}

	// If no custom DiscoverPublicKey function is set, set default
	if v.options.DiscoverPublicKey == nil {
		v.options.DiscoverPublicKey = discover.DefaultPubkeyFinder()
	}

	// If strict is not set, then default it to true
	if v.options.Strict == nil {
		v.options.Strict = new(bool)
		*v.options.Strict = true
	}

	return v
}

func (v *DefaultCosignerVerifier) Issuer() string {
	return v.issuer
}

func (v *DefaultCosignerVerifier) Strict() bool {
	return *v.options.Strict
}

func (v *DefaultCosignerVerifier) VerifyCosigner(ctx context.Context, pkt *pktoken.PKToken) error {
	if pkt.Cos == nil {
		return fmt.Errorf("no cosigner signature")
	}

	// Parse our header
	header, err := pkt.ParseCosignerClaims()
	if err != nil {
		return err
	}

	if v.issuer != header.Issuer {
		return fmt.Errorf("cosigner issuer (%s) doesn't match expected issuer (%s)", header.Issuer, v.issuer)
	}

	wasCached, err := v.tryVerifyCosigner(ctx, pkt, header, true)
	if !wasCached || err == nil {
		// either no error, or we fetched a fresh key and still got an error
		return err
	}
	// if we get to here then there was an error verifying with a cached key,
	// so try again without the cache
	_, err = v.tryVerifyCosigner(ctx, pkt, header, false)
	return err
}

func (v *DefaultCosignerVerifier) tryVerifyCosigner(ctx context.Context, pkt *pktoken.PKToken, header *pktoken.CosignerClaims, mayUseCache bool) (bool, error) {
	keyRecord, wasCached, err := v.options.DiscoverPublicKey.ByKeyID(ctx, v.issuer, header.KeyID, mayUseCache)
	if err != nil {
		return wasCached, err
	}
	key := keyRecord.PublicKey
	alg := keyRecord.Alg

	// Check if it's expired
	if time.Now().After(time.Unix(header.Expiration, 0)) {
		return wasCached, fmt.Errorf("cosigner signature expired")
	}
	if header.Algorithm != alg {
		return wasCached, fmt.Errorf("key (kid=%s) has alg (%s) which doesn't match alg (%s) in protected", header.KeyID, alg, header.Algorithm)
	}
	parsedAlg, err := jwa.KeyAlgorithmFrom(alg)
	if err != nil {
		return wasCached, fmt.Errorf("failed to parse key algorithm from %s: %w", alg, err)
	}
	jwsPubkey := jws.WithKey(parsedAlg, key)
	_, err = jws.Verify(pkt.CosToken, jwsPubkey)

	return wasCached, err
}
