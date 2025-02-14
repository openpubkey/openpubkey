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
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestExpirationPolicy(t *testing.T) {
	claimsUnexpired := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-1 * time.Hour).Unix(),
	}
	unexpiredPkt := &pktoken.PKToken{}
	unexpiredPkt.OpToken = CreateCompact(t, claimsUnexpired)

	err := ExpirationPolicies.OIDC.CheckExpiration(unexpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(unexpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(unexpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(unexpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(unexpiredPkt)
	require.NoError(t, err)

	claimsOidcExpired := oidc.OidcClaims{
		Expiration: time.Now().Add(-1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-2 * time.Hour).Unix(),
	}
	oidcExpiredPkt := &pktoken.PKToken{}
	oidcExpiredPkt.OpToken = CreateCompact(t, claimsOidcExpired)

	err = ExpirationPolicies.OIDC.CheckExpiration(oidcExpiredPkt)
	require.ErrorContains(t, err, "the ID token has expired")
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(oidcExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(oidcExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(oidcExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(oidcExpiredPkt)
	require.NoError(t, err)

	claimsMaxAge1Day := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-25 * time.Hour).Unix(),
	}
	maxAge1DayExpiredPkt := &pktoken.PKToken{}
	maxAge1DayExpiredPkt.OpToken = CreateCompact(t, claimsMaxAge1Day)

	err = ExpirationPolicies.OIDC.CheckExpiration(maxAge1DayExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(maxAge1DayExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(maxAge1DayExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(maxAge1DayExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(maxAge1DayExpiredPkt)
	require.NoError(t, err)

	claimsMaxAge2Day := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-3 * 24 * time.Hour).Unix(),
	}
	maxAge2DayExpiredPkt := &pktoken.PKToken{}
	maxAge2DayExpiredPkt.OpToken = CreateCompact(t, claimsMaxAge2Day)
	err = ExpirationPolicies.OIDC.CheckExpiration(maxAge2DayExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(maxAge2DayExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(maxAge2DayExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(maxAge2DayExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(maxAge2DayExpiredPkt)
	require.NoError(t, err)

	claimsMaxAge1Week := oidc.OidcClaims{
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-8 * 24 * time.Hour).Unix(),
	}
	maxAge1WeekExpiredPkt := &pktoken.PKToken{}
	maxAge1WeekExpiredPkt.OpToken = CreateCompact(t, claimsMaxAge1Week)

	err = ExpirationPolicies.OIDC.CheckExpiration(maxAge1WeekExpiredPkt)
	require.NoError(t, err)
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(maxAge1WeekExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(maxAge1WeekExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(maxAge1WeekExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(maxAge1WeekExpiredPkt)
	require.NoError(t, err)

	claimsBothExpire := oidc.OidcClaims{
		Expiration: time.Now().Add(-10 * time.Hour).Unix(),
		IssuedAt:   time.Now().Add(-8000 * 24 * time.Hour).Unix(),
	}
	bothExpiredPkt := &pktoken.PKToken{}
	bothExpiredPkt.OpToken = CreateCompact(t, claimsBothExpire)
	err = ExpirationPolicies.OIDC.CheckExpiration(bothExpiredPkt)
	require.ErrorContains(t, err, "the ID token has expired")
	err = ExpirationPolicies.MAX_AGE_24HOURS.CheckExpiration(bothExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_48HOURS.CheckExpiration(bothExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.MAX_AGE_1WEEK.CheckExpiration(bothExpiredPkt)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	err = ExpirationPolicies.NEVER_EXPIRE.CheckExpiration(bothExpiredPkt)
	require.NoError(t, err)

	noClaimsPkt := &pktoken.PKToken{}
	err = ExpirationPolicies.OIDC.CheckExpiration(noClaimsPkt)
	require.ErrorContains(t, err, "invalid number of segments")

	// OIDC Refreshed tests
	err = ExpirationPolicies.OIDC_REFRESHED.CheckExpiration(bothExpiredPkt)
	require.ErrorContains(t, err, "ID token is expired and no refresh token found")

	refreshedPkt := &pktoken.PKToken{}
	refreshedPkt.OpToken = CreateCompact(t, claimsBothExpire)
	refreshedPkt.FreshIDToken = CreateCompact(t, claimsUnexpired)

	refreshedPkt.FreshIDToken = CreateCompact(t, claimsUnexpired)
	err = ExpirationPolicies.OIDC_REFRESHED.CheckExpiration(refreshedPkt)
	require.NoError(t, err)

	refreshedPkt.FreshIDToken = CreateCompact(t, claimsBothExpire)
	err = ExpirationPolicies.OIDC_REFRESHED.CheckExpiration(refreshedPkt)
	require.ErrorContains(t, err, "the ID token has expired")

	zeroExp := oidc.OidcClaims{
		Expiration: 0,
	}
	refreshedPkt.FreshIDToken = CreateCompact(t, zeroExp)
	err = ExpirationPolicies.OIDC_REFRESHED.CheckExpiration(refreshedPkt)
	require.ErrorContains(t, err, "missing expiration claim")

	refreshedPkt.FreshIDToken = []byte("")
	err = ExpirationPolicies.OIDC_REFRESHED.CheckExpiration(refreshedPkt)
	require.ErrorContains(t, err, "invalid number of segments")

	refreshedPkt.OpToken = CreateCompact(t, zeroExp)
	refreshedPkt.FreshIDToken = CreateCompact(t, claimsUnexpired)
	err = ExpirationPolicies.OIDC_REFRESHED.CheckExpiration(refreshedPkt)
	require.ErrorContains(t, err, "missing expiration claim")
}

func TestIDTokenExpiration(t *testing.T) {
	oneHourFromNow := time.Now().Add(1 * time.Hour)
	expired, err := verifyNotExpired(oneHourFromNow.Unix())
	require.NoError(t, err)
	require.False(t, expired)

	oneHourAgo := time.Now().Add(-1 * time.Hour)
	expired, err = verifyNotExpired(oneHourAgo.Unix())
	require.ErrorContains(t, err, "the ID token has expired")
	require.True(t, expired)

	expired, err = verifyNotExpired(0)
	require.ErrorContains(t, err, "missing expiration claim")
	require.False(t, expired)

	expired, err = verifyNotExpired(-1)
	require.ErrorContains(t, err, "expiration must be must be greater than zero")
	require.False(t, expired)
}

func TestMaxAgeExpiration(t *testing.T) {
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	maxAgeThreeHours := int64(3 * 60 * 60) // 3 hours in seconds
	expired, err := checkMaxAge(twoHoursAgo.Unix(), maxAgeThreeHours)
	require.NoError(t, err)
	require.False(t, expired)

	maxAgeOneHour := int64(1 * 60 * 60) // 3 hours in seconds
	expired, err = checkMaxAge(twoHoursAgo.Unix(), maxAgeOneHour)
	require.ErrorContains(t, err, "the PK token has expired based on maxAge")
	require.True(t, expired)

	expired, err = checkMaxAge(0, 1)
	require.ErrorContains(t, err, "missing issuedAt claim")
	require.False(t, expired)

	expired, err = checkMaxAge(-1, 1)
	require.ErrorContains(t, err, "issuedAt must be must be greater than zero")
	require.False(t, expired)

	expired, err = checkMaxAge(twoHoursAgo.Unix(), 0)
	require.ErrorContains(t, err, "maxAge configuration must be greater than zero")
	require.False(t, expired)

	expired, err = checkMaxAge(math.MaxInt64, math.MaxInt64)
	require.ErrorContains(t, err, "invalid values")
	require.False(t, expired)
}

func CreateCompact(t *testing.T, claims oidc.OidcClaims) []byte {
	claimsJson, err := json.Marshal(claims)
	require.NoError(t, err)
	claimsB64 := util.Base64EncodeForJWT(claimsJson)
	return util.JoinJWTSegments([]byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ"), claimsB64, []byte("ZmFrZXNpZ25hdHVyZQ=="))
}
