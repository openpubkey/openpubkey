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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthIDs(t *testing.T) {
	hmacKey := []byte{0x1, 0x2, 0x3}

	aid := NewAuthIDIssuer(hmacKey)

	// Test if we get the same value if we supply exact the same time
	unixTime := uint64(5)
	authID1, err := aid.CreateAuthID(unixTime)
	require.NoError(t, err, "failed to create auth ID")

	authID2, err := aid.CreateAuthID(unixTime)
	require.NoError(t, err, "failed to create auth ID")
	require.NotEqualValues(t, authID1, authID2)

	require.Equal(t, "644117927902f52d3949804c7ce417509d9437eb1240a9bf75725c9f61d5b424", authID1)
	require.Equal(t, "f7d16adcef9f7d0e72139f0edae98db64c2db1f0cb8b59468d4766e91126f4eb", authID2)
}
