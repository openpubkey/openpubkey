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
	"context"
	"fmt"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/backend"
)

const mockProviderIssuer = "https://accounts.example.com"

var _ providers.OpenIdProvider = (*MockProvider)(nil)

type MockProviderOpts struct {
	Issuer     string
	ClientID   string
	SignGQ     bool
	CommitType providers.CommitType
	// We keep VerifierOpts as a variable separate to let us test failures
	// where the mock op does something which causes a verification failure
	VerifierOpts providers.ProviderVerifierOpts
}

func DefaultMockProviderOpts() MockProviderOpts {
	clientID := "test_client_id"
	return MockProviderOpts{
		Issuer:     "https://accounts.example.com",
		ClientID:   clientID,
		SignGQ:     false,
		CommitType: providers.CommitTypesEnum.NONCE_CLAIM,
		VerifierOpts: providers.ProviderVerifierOpts{
			CommitType:        providers.CommitTypesEnum.NONCE_CLAIM,
			ClientID:          clientID,
			SkipClientIDCheck: false,
			GQOnly:            false,
		},
	}
}

type MockProvider struct {
	options                  MockProviderOpts
	issuer                   string
	publicKeyFinder          discover.PublicKeyFinder
	requestTokenOverrideFunc func(string) ([]byte, error)
}

// NewMockProvider creates a new mock provider with a random signing key and a random key ID. It returns the provider,
// the mock backend, and the ID token template. Tests can use the mock backend to look up keys issued by the mock provider.
// Tests can use the ID token template to create ID tokens and test the provider's behavior when verifying incorrectly set ID Tokens.
func NewMockProvider(opts MockProviderOpts) (providers.OpenIdProvider, *backend.MockProviderBackend, *backend.IDTokenTemplate, error) {
	if opts.Issuer == "" {
		opts.Issuer = mockProviderIssuer
	}
	numKeys := 2
	mockBackend, err := backend.NewMockProviderBackend(opts.Issuer, numKeys)
	if err != nil {
		return nil, nil, nil, err
	}
	provider := &MockProvider{
		options:                  opts,
		issuer:                   mockBackend.Issuer,
		requestTokenOverrideFunc: mockBackend.RequestTokenOverrideFunc,
		publicKeyFinder:          mockBackend.PublicKeyFinder,
	}

	providerSigner, keyID, record := mockBackend.RandomSigningKey()
	commitmentFunc := backend.NoClaimCommit
	if opts.CommitType.Claim == "nonce" {
		commitmentFunc = backend.AddNonceCommit
	} else if opts.CommitType.Claim == "aud" {
		commitmentFunc = backend.AddAudCommit
	}
	idTokenTemplate := &backend.IDTokenTemplate{
		CommitFunc: commitmentFunc,
		Issuer:     provider.Issuer(),
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        opts.ClientID,
		KeyID:      keyID,
		NoKeyID:    false,
		Alg:        record.Alg,
		NoAlg:      false,
		SigningKey: providerSigner,
	}
	if opts.CommitType.GQCommitment {
		idTokenTemplate.Aud = providers.AudPrefixForGQCommitment
	}

	mockBackend.SetIDTokenTemplate(idTokenTemplate)
	return provider, mockBackend, idTokenTemplate, nil
}

func (m *MockProvider) requestTokens(_ context.Context, cicHash string) ([]byte, error) {
	return m.requestTokenOverrideFunc(cicHash)
}

func (m *MockProvider) RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error) {
	if m.options.CommitType.GQCommitment && !m.options.SignGQ {
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
	if m.options.CommitType.GQCommitment {
		return providers.CreateGQBoundToken(ctx, idToken, m, string(cicHash))
	}
	if m.options.SignGQ {
		return providers.CreateGQToken(ctx, idToken, m)
	}
	return idToken, nil
}
func (m *MockProvider) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByToken(ctx, m.issuer, token)
}

func (m *MockProvider) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByKeyID(ctx, m.issuer, keyID)
}

func (m *MockProvider) PublicKeyByJTK(ctx context.Context, jtk string) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByJTK(ctx, m.issuer, jtk)
}
func (m *MockProvider) Issuer() string {
	return m.issuer
}

func (m *MockProvider) VerifyProvider(ctx context.Context, pkt *pktoken.PKToken) error {
	m.options.VerifierOpts.DiscoverPublicKey = &m.publicKeyFinder //TODO: this should be set in the constructor once we have constructors for each OP
	return providers.NewProviderVerifier(m.Issuer(), m.options.VerifierOpts).VerifyProvider(ctx, pkt)
}
