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

package verifier

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

type ProviderVerifier interface {
	// Returns the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
	Issuer() string
	VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error
}

type ProviderVerifierExpires struct {
	ProviderVerifier
	Expiration ExpirationPolicy
}

func (p ProviderVerifierExpires) ExpirationPolicy() ExpirationPolicy {
	return p.Expiration
}

type RefreshableProviderVerifier interface {
	VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error
}

type CosignerVerifier interface {
	Issuer() string
	Strict() bool // Whether or not a given cosigner MUST be present for successful verification
	VerifyCosigner(ctx context.Context, pkt *pktoken.PKToken) error
}

type VerifierOpts func(*Verifier) error

// RequireRefreshedIDToken instructs the verifier to check that
// an unexpired, refreshed ID token is set on the PKToken.
func RequireRefreshedIDToken() VerifierOpts {
	return func(v *Verifier) error {
		v.requireRefreshedIDToken = true
		return nil
	}
}

func WithExpirationPolicy(expirationPolicy ExpirationPolicy) VerifierOpts {
	return func(v *Verifier) error {
		v.defaultExpirationPolicy = &expirationPolicy
		return nil
	}
}

func WithCosignerVerifiers(verifiers ...*cosigner.DefaultCosignerVerifier) VerifierOpts {
	return func(v *Verifier) error {
		for _, verifier := range verifiers {
			if _, ok := v.cosigners[verifier.Issuer()]; ok {
				return fmt.Errorf("cosigner verifier found with duplicate issuer: %s", verifier.Issuer())
			}
			v.cosigners[verifier.Issuer()] = verifier
		}
		return nil
	}
}

type Check func(*Verifier, *pktoken.PKToken) error

func GQOnly() Check {
	return func(_ *Verifier, pkt *pktoken.PKToken) error {
		alg, ok := pkt.ProviderAlgorithm()
		if !ok {
			return fmt.Errorf("missing provider algorithm header")
		}

		if alg != gq.GQ256 {
			return fmt.Errorf("non-GQ signatures are not supported")
		}
		return nil
	}
}

type Verifier struct {
	providers map[string]ProviderVerifier
	cosigners map[string]CosignerVerifier
	// Sets the default expiration policy to use
	defaultExpirationPolicy *ExpirationPolicy
	requireRefreshedIDToken bool
}

func New(verifier ProviderVerifier, options ...VerifierOpts) (*Verifier, error) {
	return NewFromMany([]ProviderVerifier{verifier}, options...)
}

func NewFromMany(verifiers []ProviderVerifier, options ...VerifierOpts) (*Verifier, error) {
	v := &Verifier{
		providers: map[string]ProviderVerifier{},
		cosigners: map[string]CosignerVerifier{},
		// For user access we override the ID Token expiration claim
		// and instead have tokens expire after 24 hours so that
		// users don't have log back in every hour.
		defaultExpirationPolicy: &ExpirationPolicies.MAX_AGE_24HOURS,
	}

	for _, verifier := range verifiers {
		if _, ok := v.providers[verifier.Issuer()]; ok {
			return nil, fmt.Errorf("provider verifier found with duplicate issuer: %s", verifier.Issuer())
		}
		v.providers[verifier.Issuer()] = verifier
	}

	for _, option := range options {
		if err := option(v); err != nil {
			return nil, err
		}
	}

	if v.defaultExpirationPolicy == nil {
		// Default to 24 hours if no expiration policy is set
		v.defaultExpirationPolicy = &ExpirationPolicies.MAX_AGE_24HOURS
	}

	return v, nil
}

// Verifies whether a PK token is valid and matches all expected claims.
//
// extraChecks: Allows for optional specification of additional checks
func (v *Verifier) VerifyPKToken(
	ctx context.Context,
	pkt *pktoken.PKToken,
	extraChecks ...Check,
) error {
	// Don't even bother doing anything if the user's isn't valid
	if err := verifyCicSignature(pkt); err != nil {
		return fmt.Errorf("error verifying client signature on PK Token: %w", err)
	}

	issuer, err := pkt.Issuer()
	if err != nil {
		return err
	}

	providerVerifier, ok := v.providers[issuer]
	if !ok {
		var knownIssuers []string
		for k := range v.providers {
			knownIssuers = append(knownIssuers, k)
		}
		return fmt.Errorf("unrecognized issuer: %s, issuers known: %v", issuer, knownIssuers)
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}
	if err := providerVerifier.VerifyIDToken(ctx, pkt.OpToken, cic); err != nil {
		return err
	}

	// If expiration has been set for this provider verifier use it to check expiration
	if providerVerifierExpires, ok := providerVerifier.(ProviderVerifierExpires); ok {
		if err := providerVerifierExpires.ExpirationPolicy().CheckExpiration(pkt); err != nil {
			return err
		}
	} else if err := v.defaultExpirationPolicy.CheckExpiration(pkt); err != nil {
		// Otherwise use the default expiration policy
		return err
	}

	if v.requireRefreshedIDToken {
		if reProviderVerifier, ok := providerVerifier.(RefreshableProviderVerifier); !ok {
			return fmt.Errorf("refreshed ID Token verification required but provider verifier (issuer=%s) does not support it", issuer)
		} else {
			if pkt.FreshIDToken == nil {
				return fmt.Errorf("no refreshed ID Token set")
			}
			if err := reProviderVerifier.VerifyRefreshedIDToken(ctx, pkt.OpToken, pkt.FreshIDToken); err != nil {
				return err
			}
		}
	}

	if len(v.cosigners) > 0 {
		if pkt.Cos == nil {
			// If there's no cosigner signature and any provided cosigner verifiers are strict, then return error
			for _, cosignerVerifier := range v.cosigners {
				if cosignerVerifier.Strict() {
					return fmt.Errorf("missing required cosigner signature by %s", cosignerVerifier.Issuer())
				}
			}
		} else {
			cosignerClaims, err := pkt.ParseCosignerClaims()
			if err != nil {
				return err
			}

			cosignerVerifier, ok := v.cosigners[cosignerClaims.Issuer]
			if !ok {
				// If other cosigners are present, do we accept?
				return fmt.Errorf("unrecognized cosigner %s", cosignerClaims.Issuer)
			}

			// Verify cosigner signature
			if err := cosignerVerifier.VerifyCosigner(ctx, pkt); err != nil {
				return err
			}

			// If any other cosigner verifiers are set to strict but aren't present, then return error
			for _, cosignerVerifier := range v.cosigners {
				if cosignerVerifier.Strict() && cosignerVerifier.Issuer() != cosignerClaims.Issuer {
					return fmt.Errorf("missing required cosigner signature by %s", cosignerVerifier.Issuer())
				}
			}
		}
	}
	// Cycles through any provided additional checks and returns the first error, if any.
	for _, check := range extraChecks {
		if err := check(v, pkt); err != nil {
			return err
		}
	}

	return nil
}

func verifyCicSignature(pkt *pktoken.PKToken) error {
	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}

	_, err = jws.Verify(pkt.CicToken, jws.WithKey(cic.PublicKey().Algorithm(), cic.PublicKey()))
	return err
}
