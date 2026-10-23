// Copyright 2026 OpenPubkey
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

package mocks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/require"
)

// An uncompressed P-256 point whose X coordinate starts with a zero byte.
const p256PointWithLeadingZeroX = "04" +
	"0002dbd4a2e2f6a66761d31324ab18bf304ace05d144df129e65dffac9795c29" +
	"b3cdf6ec19a506cb7a581a55a53a698ccdcb03b24406727fbddfee6ca1c508a2"

func TestP256CoordinatesKeepLeadingZeros(t *testing.T) {
	point, err := hex.DecodeString(p256PointWithLeadingZeroX)
	require.NoError(t, err)
	pubkey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	require.NoError(t, err)

	x, y, err := p256Coordinates(pubkey)
	require.NoError(t, err)
	require.Equal(t, point[1:33], x)
	require.Equal(t, point[33:], y)
}

func TestP256CoordinatesRejectsOtherCurves(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, _, err = p256Coordinates(&key.PublicKey)
	require.ErrorContains(t, err, "expected a P-256 key")
}

func TestNewWebauthnDeviceEncodesCOSEKey(t *testing.T) {
	device, err := NewWebauthnDevice("example.com")
	require.NoError(t, err)

	var cose webauthncose.EC2PublicKeyData
	require.NoError(t, webauthncbor.Unmarshal(device.PubkeyCbor, &cose))
	require.Equal(t, int64(webauthncose.EllipticKey), cose.KeyType)
	require.Equal(t, int64(webauthncose.AlgES256), cose.Algorithm)
	require.Equal(t, int64(webauthncose.P256), cose.Curve)

	point, err := device.signer.Public().(*ecdsa.PublicKey).Bytes()
	require.NoError(t, err)
	require.Equal(t, point[1:33], cose.XCoord)
	require.Equal(t, point[33:], cose.YCoord)
}
