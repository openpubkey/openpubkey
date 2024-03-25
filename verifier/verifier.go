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

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
)

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")

type ProviderVerifier interface {
	// Returns the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
	Issuer() string
	VerifyProvider(ctx context.Context, pkt *pktoken.PKToken) error
}

type CosignerVerifier interface {
	Issuer() string
	Strict() bool // Whether or not a given cosigner MUST be present for successful verification
	VerifyCosigner(ctx context.Context, pkt *pktoken.PKToken) error
}

type VerifierOpts func(*Verifier) error

func WithCosignerVerifiers(verifiers ...*DefaultCosignerVerifier) VerifierOpts {
	return func(v *Verifier) error {
		for _, verifier := range verifiers {
			if _, ok := v.cosigners[verifier.Issuer()]; ok {
				return fmt.Errorf("cosigner verifier found with duplicate issuer: %s", verifier.Issuer())
			}
			v.cosigners[verifier.issuer] = verifier
		}
		return nil
	}
}

func AddProviderVerifiers(verifiers ...ProviderVerifier) VerifierOpts {
	return func(v *Verifier) error {
		for _, verifier := range verifiers {
			if _, ok := v.providers[verifier.Issuer()]; ok {
				return fmt.Errorf("provider verifier found with duplicate issuer: %s", verifier.Issuer())
			}
			v.providers[verifier.Issuer()] = verifier
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
			return ErrNonGQUnsupported
		}
		return nil
	}
}

type Verifier struct {
	providers map[string]ProviderVerifier
	cosigners map[string]CosignerVerifier
}

func New(verifier ProviderVerifier, options ...VerifierOpts) (*Verifier, error) {
	v := &Verifier{
		providers: map[string]ProviderVerifier{
			verifier.Issuer(): verifier,
		},
		cosigners: map[string]CosignerVerifier{},
	}

	for _, option := range options {
		if err := option(v); err != nil {
			return nil, err
		}
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
	issuer, err := pkt.Issuer()
	if err != nil {
		return err
	}

	providerVerifier, ok := v.providers[issuer]
	if !ok {
		return fmt.Errorf("unrecognized issuer: %s", issuer)
	}

	if err := providerVerifier.VerifyProvider(ctx, pkt); err != nil {
		return err
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
