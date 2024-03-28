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
	"github.com/openpubkey/openpubkey/providers/override"
)

const mockOpIssuer = "https://accounts.example.com"

type MockOpOpts struct {
	SignGQ              bool
	GQCommitment        bool
	ClaimCommitment     bool
	CommitmentClaimName string
	// We keep VerifierOpts as a variable separate to let us test failures
	// where the mock op does something which causes a verification failure
	VerifierOpts ProviderVerifierOpts
}

type MockOp struct {
	options                  MockOpOpts
	issuer                   string
	publicKeyFinder          discover.PublicKeyFinder
	requestTokenOverrideFunc func(string) ([]byte, error)
}

func NewMockOpAndBackend(opOpts MockOpOpts) (OpenIdProvider, *override.ProviderOverride, error) {
	mockBackend, err := override.NewMockProviderOverride(mockOpIssuer, 2)
	if err != nil {
		return nil, nil, err
	}
	return NewMockOp(mockBackend, opOpts), mockBackend, nil
}

func NewMockOp(opBackend *override.ProviderOverride, opOpts MockOpOpts) OpenIdProvider {
	return &MockOp{
		options:                  opOpts,
		issuer:                   opBackend.Issuer,
		requestTokenOverrideFunc: opBackend.RequestTokenOverrideFunc,
		publicKeyFinder:          opBackend.PublicKeyFinder,
	}
}

var _ OpenIdProvider = (*MockOp)(nil)

func (m *MockOp) requestTokens(_ context.Context, cicHash string) ([]byte, error) {
	return m.requestTokenOverrideFunc(cicHash)
}

func (m *MockOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error) {
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
