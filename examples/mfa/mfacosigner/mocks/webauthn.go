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

package mocks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/util"
)

// For testing purposes we create a WebAuthn device to run the client part of the protocol
type WebAuthnDevice struct {
	signer     crypto.Signer
	PubkeyCbor []byte
	RpID       string
	RpIDHash   []byte
	Userhandle []byte
	RawID      []byte
	AuthFlags  byte
	Counter    uint32
}

func NewWebauthnDevice(rpID string) (*WebAuthnDevice, error) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	pubkey := signer.Public().(*ecdsa.PublicKey)
	pubkeyCbor := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.AlgES256),
		XCoord: pubkey.X.Bytes(),
		YCoord: pubkey.Y.Bytes(),
	}
	pubkeyCborBytes, err := webauthncbor.Marshal(pubkeyCbor)
	if err != nil {
		return nil, err
	}

	rpIDHash := sha256.Sum256([]byte(rpID))

	return &WebAuthnDevice{
		signer:     signer,
		PubkeyCbor: pubkeyCborBytes,
		RpID:       rpID,
		RpIDHash:   rpIDHash[:],

		// Checked by Webauthn RP to distinguish between different
		// users accounts sharing the same device with the same RP.
		// userHandle == user.WebAuthnID()?
		//
		// Not all devices can store a user handle it is allowed to be null
		// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/userHandle
		//
		// In OpenPubkey MFA Cosigner RP we set this to the ID Token sub
		Userhandle: nil,

		// The ID of the public key credential held by the device
		RawID: []byte{5, 1, 1, 1, 1},

		// 	Flag 0x41 has two bits set. 0b001 and 0b101
		//  FlagUserPresent Bit 00000001 - the user is present (UP flag)
		//  FlagUserVerified Bit 00000100 - user is verified using a biometric or PIN (UV flag)
		AuthFlags: 0x41,

		// Signature counter, used to identify cloned devices  see https://www.w3.org/TR/webauthn/#signature-counter
		Counter: 0,
	}, nil
}

func (wa *WebAuthnDevice) RegResp(createCreation *protocol.CredentialCreation) (*protocol.ParsedCredentialCreationData, error) {
	wa.Userhandle = []byte(createCreation.Response.User.ID.(protocol.URLEncodedBase64))

	return &protocol.ParsedCredentialCreationData{
		Response: protocol.ParsedAttestationResponse{
			CollectedClientData: protocol.CollectedClientData{
				Type:      protocol.CeremonyType("webauthn.create"),
				Challenge: createCreation.Response.Challenge.String(),
				Origin:    createCreation.Response.RelyingParty.ID,
			},
			AttestationObject: protocol.AttestationObject{
				Format: "none",
				AuthData: protocol.AuthenticatorData{
					RPIDHash: wa.RpIDHash,
					Counter:  wa.Counter,
					Flags:    protocol.AuthenticatorFlags(wa.AuthFlags),
					AttData: protocol.AttestedCredentialData{
						AAGUID:              make([]byte, 16),
						CredentialID:        wa.RawID,
						CredentialPublicKey: wa.PubkeyCbor,
					},
				},
			},
			Transports: []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC, "fake"},
		},
	}, nil
}

func (wa *WebAuthnDevice) LoginResp(credAssert *protocol.CredentialAssertion) (*protocol.ParsedCredentialAssertionData, error) {
	loginRespData := &protocol.ParsedCredentialAssertionData{
		ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
			// Checked by Webauthn RP to see if public key supplied is on the
			// allowlist of public keys for this user:
			// parsedResponse.RawID == session.AllowedCredentialIDs?
			RawID: wa.RawID,
		},
		Response: protocol.ParsedAssertionResponse{
			CollectedClientData: protocol.CollectedClientData{
				Type:      protocol.CeremonyType("webauthn.get"),
				Challenge: credAssert.Response.Challenge.String(),
				Origin:    wa.RpID,
			},
			AuthenticatorData: protocol.AuthenticatorData{
				RPIDHash: wa.RpIDHash,
				Counter:  wa.Counter,
				Flags:    protocol.AuthenticatorFlags(wa.AuthFlags),
			},
			UserHandle: wa.Userhandle, // Not a required field:
		},
	}

	return wa.SignLoginChallenge(loginRespData)
}

func (wa *WebAuthnDevice) SignLoginChallenge(loginRespData *protocol.ParsedCredentialAssertionData) (*protocol.ParsedCredentialAssertionData, error) {
	clientDataHash := sha256.Sum256(loginRespData.Raw.AssertionResponse.ClientDataJSON)
	sigData := append(loginRespData.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)
	sigHash := sha256.Sum256(sigData)
	sigWebauthn, err := wa.signer.Sign(rand.Reader, sigHash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	loginRespData.Response.Signature = sigWebauthn
	return loginRespData, nil
}
