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
	"context"
	"fmt"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers/backend"
)

const mockOpIssuer = "https://accounts.example.com"

type MockOpOpts struct {
	Issuer              string
	ClientID            string
	SignGQ              bool
	GQCommitment        bool
	CommitmentClaimName string
	// We keep VerifierOpts as a variable separate to let us test failures
	// where the mock op does something which causes a verification failure
	VerifierOpts ProviderVerifierOpts
}

func DefaultMockOpOpts() MockOpOpts {
	clientID := "test_client_id"
	return MockOpOpts{
		Issuer:              "https://accounts.example.com",
		ClientID:            clientID,
		SignGQ:              false,
		GQCommitment:        false,
		CommitmentClaimName: "nonce",
		VerifierOpts: ProviderVerifierOpts{
			ClientID:          clientID,
			SkipClientIDCheck: false,
			GQOnly:            false,
			GQCommitment:      false,
		},
	}
}

type MockOp struct {
	options                  MockOpOpts
	issuer                   string
	publicKeyFinder          discover.PublicKeyFinder
	requestTokenOverrideFunc func(string) ([]byte, error)
}

// NewMockProvider creates a new mock provider with a random signing key and a random key ID. It returns the provider,
// the mock backend, and the ID token template. Tests can use the mock backend to look up keys issued by the mock provider.
// Tests can use the ID token template to create ID tokens and test the provider's behavior when verifying incorrectly set ID Tokens.
func NewMockProvider(opOpts MockOpOpts) (OpenIdProvider, *backend.ProviderOverride, *backend.IDTokenTemplate, error) {
	if opOpts.Issuer == "" {
		opOpts.Issuer = mockOpIssuer
	}
	provider, mockBackend, err := NewMockProviderAndBackend(opOpts)
	if err != nil {
		return nil, nil, nil, err
	}

	providerSigner, keyID, record := mockBackend.RandomSigningKey()
	commitmentFunc := backend.NoClaimCommit
	if opOpts.CommitmentClaimName == "nonce" {
		commitmentFunc = backend.AddNonceCommit
	} else if opOpts.CommitmentClaimName == "aud" {
		commitmentFunc = backend.AddAudCommit
	}
	idTokenTemplate := &backend.IDTokenTemplate{
		CommitmentFunc: commitmentFunc,
		Issuer:         provider.Issuer(),
		Nonce:          "empty",
		NoNonce:        false,
		Aud:            opOpts.ClientID,
		KeyID:          keyID,
		NoKeyID:        false,
		Alg:            record.Alg,
		NoAlg:          false,
		SigningKey:     providerSigner,
	}
	if opOpts.GQCommitment {
		idTokenTemplate.Aud = AudPrefixForGQCommitment
	}

	mockBackend.SetIDTokenTemplate(idTokenTemplate)
	return provider, mockBackend, idTokenTemplate, nil
}

func NewMockProviderAndBackend(opOpts MockOpOpts) (OpenIdProvider, *backend.ProviderOverride, error) {
	if opOpts.Issuer == "" {
		opOpts.Issuer = mockOpIssuer
	}
	numKeys := 2
	mockBackend, err := backend.NewMockProviderBackend(opOpts.Issuer, numKeys)
	if err != nil {
		return nil, nil, err
	}
	mockProvider := &MockOp{
		options:                  opOpts,
		issuer:                   mockBackend.Issuer,
		requestTokenOverrideFunc: mockBackend.RequestTokenOverrideFunc,
		publicKeyFinder:          mockBackend.PublicKeyFinder,
	}
	return mockProvider, mockBackend, nil
}

// TODO: Delete this function once all tests are using NewMockProvider
// func NewMockOp(opBackend *backend.ProviderOverride, opOpts MockOpOpts) OpenIdProvider {
// 	return &MockOp{
// 		options:                  opOpts,
// 		issuer:                   opBackend.Issuer,
// 		requestTokenOverrideFunc: opBackend.RequestTokenOverrideFunc,
// 		publicKeyFinder:          opBackend.PublicKeyFinder,
// 	}
// }

var _ OpenIdProvider = (*MockOp)(nil)

func (m *MockOp) requestTokens(_ context.Context, cicHash string) ([]byte, error) {
	return m.requestTokenOverrideFunc(cicHash)
}

func (m *MockOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error) {
	if m.options.GQCommitment && !m.options.SignGQ {
		// Catch misconfigurations in tests
		return nil, fmt.Errorf("if GQCommitment is true then GQSign must also be true")
	}

	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	idToken, err := m.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, err
	}
	if m.options.GQCommitment {
		return CreateGQBoundToken(ctx, idToken, m, string(cicHash))
	}
	if m.options.SignGQ {
		return CreateGQToken(ctx, idToken, m)
	}
	return idToken, nil
}
func (m *MockOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByToken(ctx, m.issuer, token)
}

func (m *MockOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByKeyID(ctx, m.issuer, keyID)
}

func (m *MockOp) PublicKeyByJTK(ctx context.Context, jtk string) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByJTK(ctx, m.issuer, jtk)
}
func (m *MockOp) Issuer() string {
	return m.issuer
}

func (m *MockOp) VerifyProvider(ctx context.Context, pkt *pktoken.PKToken) error {
	m.options.VerifierOpts.DiscoverPublicKey = &m.publicKeyFinder //TODO: this should be set in the constructor once we have constructors for each OP
	if m.options.GQCommitment {
		return NewProviderVerifier(m.Issuer(), "", m.options.VerifierOpts).VerifyProvider(ctx, pkt)
	}
	claimName := m.options.CommitmentClaimName
	return NewProviderVerifier(m.Issuer(), claimName, m.options.VerifierOpts).VerifyProvider(ctx, pkt)
}
