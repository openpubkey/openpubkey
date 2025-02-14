// Copyright 2025 OpenPubkey
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
	"fmt"
	"time"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
)

type ExpirationPolicy struct {
	maxAge         time.Duration
	checkMaxAge    bool
	checkExpClaim  bool
	checkRefreshed bool
}

var ExpirationPolicies = struct {
	OIDC            ExpirationPolicy // This uses the OpenID Connect expiration claim
	OIDC_REFRESHED  ExpirationPolicy // This uses the OpenID Connect expiration claim on the ID Token, if that has expired. It checks the expiration on the refreshed ID Token, a.k.a., the fresh ID Token
	MAX_AGE_24HOURS ExpirationPolicy // This replaces the OpenID Connect expiration claim with OpenPubkey 24 expiration
	MAX_AGE_48HOURS ExpirationPolicy
	MAX_AGE_1WEEK   ExpirationPolicy
	NEVER_EXPIRE    ExpirationPolicy // ID Token will never expire until the OpenID Provider rotates the ID Token
}{
	OIDC:            ExpirationPolicy{maxAge: 0, checkMaxAge: false, checkExpClaim: true},
	OIDC_REFRESHED:  ExpirationPolicy{maxAge: 0, checkMaxAge: false, checkExpClaim: false, checkRefreshed: true},
	MAX_AGE_24HOURS: ExpirationPolicy{maxAge: 24 * time.Hour, checkMaxAge: true, checkExpClaim: false},
	MAX_AGE_48HOURS: ExpirationPolicy{maxAge: 2 * 24 * time.Hour, checkMaxAge: true, checkExpClaim: false},
	MAX_AGE_1WEEK:   ExpirationPolicy{maxAge: 7 * 24 * time.Hour, checkMaxAge: true, checkExpClaim: false},
	NEVER_EXPIRE:    ExpirationPolicy{maxAge: 0, checkMaxAge: false, checkExpClaim: false},
}

// CheckExpiration checks the expiration of the PK Token against the expiration
// policy.
func (ep ExpirationPolicy) CheckExpiration(pkt *pktoken.PKToken) error {
	idt, err := oidc.NewJwt(pkt.OpToken)
	if err != nil {
		return err
	}
	idtClaims := idt.GetClaims()

	if ep.checkExpClaim {
		_, err := verifyNotExpired(idtClaims.Expiration)
		if err != nil {
			return err
		}
	}
	if ep.checkRefreshed {
		expired, err := verifyNotExpired(idtClaims.Expiration)

		// If the id token is expired, verify against the refreshed id token
		if expired {
			if pkt.FreshIDToken == nil {
				return fmt.Errorf("ID token is expired and no refresh token found")
			}
			freshIdt, err := oidc.NewJwt(pkt.FreshIDToken)
			if err != nil {
				return err
			}
			_, err = verifyNotExpired(freshIdt.GetClaims().Expiration)
			if err != nil {
				return err
			}
		} else if err != nil { // an non-expiration error occurred
			return err
		}
	}

	if ep.checkMaxAge {
		_, err := checkMaxAge(idtClaims.IssuedAt, int64(ep.maxAge.Seconds()))
		if err != nil {
			return err
		}
	}
	return nil
}

// verifyNotExpired checks the expiration of the ID Token using the exp claim.
// If expired, returns true and set an error. If an error prevents checking
// expiration it return false and the error.
func verifyNotExpired(expiration int64) (bool, error) {
	if expiration == 0 {
		return false, fmt.Errorf("missing expiration claim")
	}
	if expiration < 0 {
		return false, fmt.Errorf("expiration must be must be greater than zero (issuedAt = %v)", expiration)
	}

	// JWT expiration is "Seconds Since the Epoch"
	// RFC-7519 -Section 2 https://www.rfc-editor.org/rfc/rfc7519#section-2
	expirationTime := time.Unix(expiration, 0)
	if time.Now().After(expirationTime) {
		return true, fmt.Errorf("the ID token has expired (exp = %v)", expiration)
	}
	return false, nil
}

// checkMaxAge checks the max age of the ID Token using the issuedAt claim.
// If expired, returns true and set an error. If an error prevents checking
// expiration it return false and the error.
func checkMaxAge(issuedAt int64, maxAge int64) (bool, error) {
	if issuedAt == 0 {
		return false, fmt.Errorf("missing issuedAt claim")
	}
	if issuedAt < 0 {
		return false, fmt.Errorf("issuedAt must be must be greater than zero (issuedAt = %v)", issuedAt)
	}
	if !(maxAge > 0) {
		return false, fmt.Errorf("maxAge configuration must be greater than zero (maxAge = %v)", maxAge)
	}
	// Ensure we throw an error is something goes wrong and we get parameters so large they overflow
	if (issuedAt + maxAge) < issuedAt {
		return false, fmt.Errorf("invalid values (issuedAt = %v, maxAge = %v)", issuedAt, maxAge)
	}
	expirationTime := time.Unix(issuedAt+maxAge, 0)
	if time.Now().After(expirationTime) {
		return true, fmt.Errorf("the PK token has expired based on maxAge (issuedAt = %v, maxAge = %v, expiratedAt = %v)", issuedAt, maxAge, expirationTime)
	}
	return false, nil
}
