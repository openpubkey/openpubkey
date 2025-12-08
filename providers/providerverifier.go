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

package providers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

const AudPrefixForGQCommitment = "OPENPUBKEY-PKTOKEN:"

type DefaultProviderVerifier struct {
	issuer     string
	commitType CommitType
	options    ProviderVerifierOpts
}

type ProviderVerifierOpts struct {
	// If ClientID is specified, then verification will require that the ClientID
	// be present in the audience ("aud") claim of the PK token payload
	ClientID string
	// Describes the place where the cicHash is committed to in the the ID token.
	// For instance the nonce payload claim name where the cicHash was stored during issuance
	CommitType CommitType
	// Specifies whether to skip the Client ID check, defaults to false
	SkipClientIDCheck bool
	// Custom function for discovering public key of Provider
	DiscoverPublicKey *discover.PublicKeyFinder
	// Only allows GQ signatures, a provider signature under any other algorithm
	// is seen as an error
	GQOnly bool
	// GQAudiencePrefix is the required prefix for the audience claim in GQ commitments.
	// If empty (not set), defaults to AudPrefixForGQCommitment ("OPENPUBKEY-PKTOKEN:").
	// Set to a custom value to use a different prefix.
	GQAudiencePrefix string
}

// Creates a new ProviderVerifier with required fields
//
// issuer: Is the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
// commitmentClaim: the ID token payload claim name where the cicHash was stored during issuance
func NewProviderVerifier(issuer string, options ProviderVerifierOpts) *DefaultProviderVerifier {
	v := &DefaultProviderVerifier{
		issuer:     issuer,
		commitType: options.CommitType,
		options:    options,
	}

	// If no custom DiscoverPublicKey function is set, set default
	if v.options.DiscoverPublicKey == nil {
		v.options.DiscoverPublicKey = discover.DefaultPubkeyFinder()
	}

	// Initialize GQ audience prefix with default if not set
	if v.options.GQAudiencePrefix == "" {
		v.options.GQAudiencePrefix = AudPrefixForGQCommitment
	}

	return v
}

func (v *DefaultProviderVerifier) Issuer() string {
	return v.issuer
}

func (v *DefaultProviderVerifier) VerifyIDToken(ctx context.Context, idToken []byte, cic *clientinstance.Claims) error {
	// Sanity check that if GQCommitment is enabled then the other options
	// are set correctly for doing GQ commitment verification. The intention is
	// to catch misconfigurations early and provide meaningful error messages.
	if v.options.CommitType.GQCommitment {
		if !v.options.GQOnly {
			return fmt.Errorf("GQCommitment requires that GQOnly is true, but GQOnly is (%t)", v.options.GQOnly)
		}
		if v.commitType.Claim != "" {
			return fmt.Errorf("GQCommitment requires that commitmentClaim is empty but commitmentClaim is (%s)", v.commitType.Claim)
		}
		if !v.options.SkipClientIDCheck {
			// When we bind the commitment to the ID Token using GQ Signatures,
			// We require that the audience is prefixed with
			// "OPENPUBKEY-PKTOKEN:". Thus, the audience can't be the client-id
			// If you are hitting this error of set SkipClientIDCheck to true
			return fmt.Errorf("GQCommitment requires that audience (aud) is not set to client-id")
		}
	} else {
		// If GQAudiencePrefix is set but this isn't a GQ ProviderVerifier, fail
		if v.options.GQAudiencePrefix != "" && v.options.GQAudiencePrefix != AudPrefixForGQCommitment {
			return fmt.Errorf("GQAudiencePrefix is set but CommitType does not use GQCommitment")
		}
	}

	idt, err := oidc.NewJwt(idToken)
	if err != nil {
		return err
	}

	// Check whether Audience claim matches provided Client ID
	// No error is thrown if option is set to skip client ID check
	if err := verifyAudience(idt, v.options.ClientID); err != nil && !v.options.SkipClientIDCheck {
		return err
	}

	algStr := idt.GetSignature().GetProtectedClaims().Alg
	if algStr == "" {
		return fmt.Errorf("provider algorithm type missing")
	}
	alg := jwa.NewSignatureAlgorithm(algStr)
	if alg.String() != jose.GQ256 && v.options.GQOnly {
		return fmt.Errorf("non-GQ signatures are not supported")
	}

	switch alg.String() {
	case jose.GQ256:
		// GQ signatures need special handling (extract original headers, etc.)
		if err := v.verifyGQSig(ctx, idt); err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}
	default:
		// Generic verification for RS256, ES256, EdDSA, and future algorithms
		pubKeyRecord, err := v.providerPublicKey(ctx, idToken)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		// Validate that key type matches the algorithm in the token
		switch alg {
		case jwa.RS256():
			if _, ok := pubKeyRecord.PublicKey.(*rsa.PublicKey); !ok {
				return fmt.Errorf("algorithm %s requires RSA key, got %T", alg, pubKeyRecord.PublicKey)
			}
		case jwa.ES256():
			if _, ok := pubKeyRecord.PublicKey.(*ecdsa.PublicKey); !ok {
				return fmt.Errorf("algorithm %s requires ECDSA key, got %T", alg, pubKeyRecord.PublicKey)
			}
		case jwa.EdDSA():
			if _, ok := pubKeyRecord.PublicKey.(ed25519.PublicKey); !ok {
				return fmt.Errorf("algorithm %s requires Ed25519 key, got %T", alg, pubKeyRecord.PublicKey)
			}
		default:
			return fmt.Errorf("unsupported signature algorithm %s", alg)
		}

		// jws.Verify handles all algorithms generically
		if _, err := jws.Verify(idToken, jws.WithKey(alg, pubKeyRecord.PublicKey)); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	if err := v.verifyCommitment(idt, cic); err != nil {
		return err
	}

	return nil
}

// This function takes in an OIDC Provider created ID token or GQ-signed modification of one and returns
// the associated public key
func (v *DefaultProviderVerifier) providerPublicKey(ctx context.Context, idToken []byte) (*discover.PublicKeyRecord, error) {
	return v.options.DiscoverPublicKey.ByToken(ctx, v.Issuer(), idToken)
}

func (v *DefaultProviderVerifier) verifyCommitment(idt *oidc.Jwt, cic *clientinstance.Claims) error {
	var claims map[string]any
	payload, err := util.Base64DecodeForJWT([]byte(idt.GetPayload()))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return err
	}

	idtTyp := idt.GetSignature().GetProtectedClaims().Type
	if idtTyp == KEYBOUND_TYP && v.commitType != CommitTypesEnum.KEY_BOUND {
		return fmt.Errorf("expected commitment type %v but got key-bound ID token (typ=%v)", v.commitType.Claim, idtTyp)
	}
	if idtTyp != KEYBOUND_TYP && v.commitType == CommitTypesEnum.KEY_BOUND {
		return fmt.Errorf("expected key-bound ID token (typ=%v) but got ID Token (typ=%v)", KEYBOUND_TYP, idtTyp)
	}

	expectedCommitment, err := cic.Hash()
	if err != nil {
		return err
	}

	var commitment any
	var commitmentFound bool
	if v.options.CommitType.GQCommitment {
		aud, ok := claims["aud"]
		if !ok {
			return fmt.Errorf("require audience claim prefix missing in PK Token's GQCommitment")
		}

		// To prevent attacks where a attacker takes someone else's ID Token
		// and turns it into a PK Token using a GQCommitment, we require that
		// all GQ commitments explicitly signal they want to be used as
		// PK Tokens. To signal this, they prefix the audience (aud)
		// claim with a configured prefix (default: "OPENPUBKEY-PKTOKEN:").
		// We reject all GQ commitment PK Tokens that don't have this prefix
		// in the aud claim.
		if _, ok := strings.CutPrefix(aud.(string), v.options.GQAudiencePrefix); !ok {
			return fmt.Errorf("audience claim in PK Token's GQCommitment must be prefixed by (%s), got (%s) instead",
				v.options.GQAudiencePrefix, aud.(string))
		}

		// Get the commitment from the GQ signed protected header claim "cic" in the ID Token
		commitment = idt.GetSignature().GetProtectedClaims().CIC
		if commitment == "" {
			return fmt.Errorf("missing GQ commitment")
		}
	} else if v.options.CommitType == CommitTypesEnum.KEY_BOUND {
		if idt.GetClaims().Cnf == nil {
			return fmt.Errorf("expected key-bound ID token but cnf claim is missing")
		}
		if len(idt.GetClaims().Cnf.Jwk) == 0 {
			return fmt.Errorf("expected key-bound ID token but cnf claim does not contain a jwk")
		}

		cnfJwkStr, err := json.Marshal(idt.GetClaims().Cnf.Jwk)
		if err != nil {
			return fmt.Errorf("error marshalling jwk in cnf claim: %w", err)
		}
		cicPublicKey, err := cic.PublicKey()
		if err != nil {
			return fmt.Errorf("error getting public key from CIC: %w", err)
		}
		cicJwkStr, err := json.Marshal(cicPublicKey)
		if err != nil {
			return fmt.Errorf("error marshalling jwk in CIC: %w", err)
		}
		if bytes.Equal(cicJwkStr, cnfJwkStr) {
			return nil
		}
		// TODO: Is this the correct way to compare for equality?
		// Given that we now store crypto.PublicKey and jwk.Key the JSON representation
		// no longer matches.
		return fmt.Errorf("jwk in cnf claim does not match public key in CIC, got %s, expected %s", string(cnfJwkStr), string(cicJwkStr))
	} else {
		if v.commitType.Claim == "" {
			return fmt.Errorf("verifier configured with empty commitment claim")
		}

		commitment, commitmentFound = claims[v.commitType.Claim]
		if !commitmentFound {
			return fmt.Errorf("missing commitment claim %s", v.commitType.Claim)
		}
	}

	if commitment != string(expectedCommitment) {
		return fmt.Errorf("commitment claim doesn't match, got %q, expected %s", commitment, string(expectedCommitment))
	}
	return nil
}

// verifyGQSig verifies the signature of a PK token with a GQ signature. The
// parameter issuer should be the issuer of the ProviderVerifier not the
// issuer of the PK Token
func (v *DefaultProviderVerifier) verifyGQSig(ctx context.Context, idt *oidc.Jwt) error {
	algStr := idt.GetSignature().GetProtectedClaims().Alg
	if algStr == "" {
		return fmt.Errorf("missing provider algorithm header")
	}
	if algStr != jose.GQ256 {
		return fmt.Errorf("signature is not of type GQ")
	}

	origHeaders, err := originalTokenHeaders(idt.GetRaw())
	if err != nil {
		return fmt.Errorf("malformed ID Token headers: %w", err)
	}

	origAlg, ok := origHeaders.Algorithm()
	if !ok {
		return fmt.Errorf("missing algorithm in original headers")
	}
	if origAlg != jwa.RS256() {
		return fmt.Errorf("expected original headers to contain RS256 alg, got %s", origAlg)
	}

	if idt.GetClaims().Issuer == "" {
		return fmt.Errorf("missing issuer in payload: %s", idt.GetPayload())
	}
	if idt.GetClaims().Issuer != v.issuer {
		return fmt.Errorf("issuer of ID Token (%s) doesn't match expected issuer (%s)", idt.GetClaims().Issuer, v.issuer)
	}

	publicKeyRecord, err := v.options.DiscoverPublicKey.ByToken(ctx, v.Issuer(), idt.GetRaw())
	if err != nil {
		return fmt.Errorf("failed to get provider public key: %w", err)
	}

	rsaKey, ok := publicKeyRecord.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("jwk is not an RSA key")
	}
	ok, err = gq.GQ256VerifyJWT(rsaKey, idt.GetRaw())
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}
	return nil
}

func originalTokenHeaders(token []byte) (jws.Headers, error) {
	origHeadersB64, err := gq.OriginalJWTHeaders(token)
	if err != nil {
		return nil, fmt.Errorf("malformatted PK token headers: %w", err)
	}

	origHeaders, err := util.Base64DecodeForJWT(origHeadersB64)
	if err != nil {
		return nil, fmt.Errorf("error decoding original token headers: %w", err)
	}

	headers := jws.NewHeaders()
	err = json.Unmarshal(origHeaders, &headers)
	if err != nil {
		return nil, fmt.Errorf("error parsing segment: %w", err)
	}

	return headers, nil
}

func verifyAudience(idt *oidc.Jwt, clientID string) error {

	if idt.GetClaims().Audience == "" {
		return fmt.Errorf("missing audience claim")
	}

	for _, audience := range strings.Split(idt.GetClaims().Audience, ",") {
		if audience == clientID {
			return nil
		}
	}
	return fmt.Errorf("audience does not contain clientID %s, aud = %v", clientID, idt.GetClaims().Audience)
}
