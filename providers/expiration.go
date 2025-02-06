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

package providers

import (
	"fmt"
	"time"

	"github.com/openpubkey/openpubkey/oidc"
)

type ExpirationPolicy struct {
	maxAge        time.Duration
	checkMaxAge   bool
	checkExpClaim bool
}

var ExpirationPolicies = struct {
	OIDC            ExpirationPolicy // This uses the OpenID Connect expiration claim
	MAX_AGE_24HOURS ExpirationPolicy // This replaces the OpenID Connect expiration claim with OpenPubkey 24 expiration
	MAX_AGE_48HOURS ExpirationPolicy
	MAX_AGE_1WEEK   ExpirationPolicy
	NEVER_EXPIRE    ExpirationPolicy // ID Token will never expire until the OpenID Provider rotates the ID Token
}{
	OIDC:            ExpirationPolicy{maxAge: 0, checkMaxAge: false, checkExpClaim: true},
	MAX_AGE_24HOURS: ExpirationPolicy{maxAge: 24 * time.Hour, checkMaxAge: true, checkExpClaim: false},
	MAX_AGE_48HOURS: ExpirationPolicy{maxAge: 2 * 24 * time.Hour, checkMaxAge: true, checkExpClaim: false},
	MAX_AGE_1WEEK:   ExpirationPolicy{maxAge: 7 * 24 * time.Hour, checkMaxAge: true, checkExpClaim: false},
	NEVER_EXPIRE:    ExpirationPolicy{maxAge: 0, checkMaxAge: false, checkExpClaim: false},
}

func (ep ExpirationPolicy) CheckExpiration(claims oidc.OidcClaims) error {
	if ep.checkExpClaim {
		err := verifyNotExpired(claims.Expiration)
		if err != nil {
			return err
		}
	}
	if ep.checkMaxAge {
		err := checkMaxAge(claims.IssuedAt, int64(ep.maxAge.Seconds()))
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyNotExpired(expiration int64) error {
	if expiration == 0 {
		return fmt.Errorf("missing expiration claim")
	}
	if expiration < 0 {
		return fmt.Errorf("expiration must be must be greater than zero (issuedAt = %v)", expiration)
	}

	// JWT expiration is "Seconds Since the Epoch"
	// RFC-7519 -Section 2 https://www.rfc-editor.org/rfc/rfc7519#section-2
	expirationTime := time.Unix(expiration, 0)
	if !time.Now().Before(expirationTime) {
		return fmt.Errorf("the ID token has expired (exp = %v)", expiration)
	}
	return nil
}

func checkMaxAge(issuedAt int64, maxAge int64) error {
	if issuedAt == 0 {
		return fmt.Errorf("missing issuedAt claim")
	}
	if issuedAt < 0 {
		return fmt.Errorf("issuedAt must be must be greater than zero (issuedAt = %v)", issuedAt)
	}
	if !(maxAge > 0) {
		return fmt.Errorf("maxAge configuration must be greater than zero (maxAge = %v)", maxAge)
	}
	// Ensure we throw an error is something goes wrong and we get parameters so large they overflow
	if (issuedAt + maxAge) < issuedAt {
		return fmt.Errorf("invalid values (issuedAt = %v, maxAge = %v)", issuedAt, maxAge)
	}
	expirationTime := time.Unix(issuedAt+maxAge, 0)
	if !time.Now().Before(expirationTime) {
		return fmt.Errorf("the PK token has expired based on maxAge (issuedAt = %v, maxAge = %v, expiratedAt = %v)", issuedAt, maxAge, expirationTime)
	}
	return nil
}
