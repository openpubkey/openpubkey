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

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

func SKToX509Bytes(sk *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded}), nil

}

func WriteSKFile(fpath string, sk *ecdsa.PrivateKey) error {
	pemBytes, err := SKToX509Bytes(sk)
	if err != nil {
		return err
	}

	return os.WriteFile(fpath, pemBytes, 0600)
}

func ReadSKFile(fpath string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(pemBytes))
	return x509.ParseECPrivateKey(block.Bytes)
}

func GenKeyPair(alg jwa.KeyAlgorithm) (crypto.Signer, error) {
	switch alg {
	case jwa.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.RS256: // RSASSA-PKCS-v1.5 using SHA-256
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg.String())
	}
}

func B64SHA3_256(msg []byte) []byte {
	h := crypto.SHA3_256.New()
	h.Write(msg)
	image := h.Sum(nil)
	return Base64EncodeForJWT(image)
}
