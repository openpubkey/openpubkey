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
	"math"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/stretchr/testify/require"
)

func TestExpirationPolicy(t *testing.T) {
	claims := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-1 * time.Hour).Unix(),
	}
	err := ExpirationPolicies.OIDC.CheckExpiration(claims)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(claims)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(claims)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(claims)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(claims)
	require.NoError(t, err)

	claimsOidcExpired := oidc.OidcClaims{
		Expiration: time.Now().Add(-1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-2 * time.Hour).Unix(),
	}
	err = ExpirationPolicies.OIDC.CheckExpiration(claimsOidcExpired)
	require.ErrorContains(t, err, "the ID token has expired")
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(claims)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(claims)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(claims)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(claims)
	require.NoError(t, err)

	claimsMaxAge1Day := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-25 * time.Hour).Unix(),
	}
	err = ExpirationPolicies.OIDC.CheckExpiration(claimsMaxAge1Day)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(claimsMaxAge1Day)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(claimsMaxAge1Day)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(claimsMaxAge1Day)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(claimsMaxAge1Day)
	require.NoError(t, err)

	claimsMaxAge2Day := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-3 * 24 * time.Hour).Unix(),
	}
	err = ExpirationPolicies.OIDC.CheckExpiration(claimsMaxAge1Day)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(claimsMaxAge2Day)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(claimsMaxAge2Day)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(claimsMaxAge2Day)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(claimsMaxAge2Day)
	require.NoError(t, err)

	claimsMaxAge1Week := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-8 * 24 * time.Hour).Unix(),
	}
	err = ExpirationPolicies.OIDC.CheckExpiration(claimsMaxAge1Week)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(claimsMaxAge1Week)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(claimsMaxAge1Week)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(claimsMaxAge1Week)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(claimsMaxAge1Week)
	require.NoError(t, err)

	claimsBothExpire := oidc.OidcClaims{
		Expiration: time.Now().Add(-10 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-8000 * 24 * time.Hour).Unix(),
	}
	err = ExpirationPolicies.OIDC.CheckExpiration(claimsBothExpire)
	require.ErrorContains(t, err, "the ID token has expired")
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(claimsBothExpire)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(claimsBothExpire)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(claimsBothExpire)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(claimsBothExpire)
	require.NoError(t, err)
}

func TestIDTokenExpiration(t *testing.T) {
	oneHourFromNow := time.Now().Add(1 * time.Hour)
	err := verifyNotExpired(oneHourFromNow.Unix())
	require.NoError(t, err)

	oneHourAgo := time.Now().Add(-1 * time.Hour)
	err = verifyNotExpired(oneHourAgo.Unix())
	require.ErrorContains(t, err, "the ID token has expired")

	err = verifyNotExpired(0)
	require.ErrorContains(t, err, "missing expiration claim")

	err = verifyNotExpired(-1)
	require.ErrorContains(t, err, "expiration must be must be greater than zero")
}

func TestMaxAgeExpiration(t *testing.T) {
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	maxAgeThreeHours := int64(3 * 60 * 60) // 3 hours in seconds
	err := checkMaxAge(twoHoursAgo.Unix(), maxAgeThreeHours)
	require.NoError(t, err)

	maxAgeOneHour := int64(1 * 60 * 60) // 3 hours in seconds
	err = checkMaxAge(twoHoursAgo.Unix(), maxAgeOneHour)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")

	err = checkMaxAge(0, 1)
	require.ErrorContains(t, err, "missing issuedAt claim")

	err = checkMaxAge(-1, 1)
	require.ErrorContains(t, err, "issuedAt must be must be greater than zero")

	err = checkMaxAge(twoHoursAgo.Unix(), 0)
	require.ErrorContains(t, err, "maxAge configuration must be greater than zero")

	err = checkMaxAge(math.MaxInt64, math.MaxInt64)
	require.ErrorContains(t, err, "invalid values")
}
