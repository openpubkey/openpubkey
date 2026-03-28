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

// Package simpleop provides a simple OpenID Provider for end-to-end testing.
// It implements the providers.OpenIdProvider interface with minimal setup,
// making it easy to create test versions of any provider by simply
// changing the issuer.
package simpleop

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
)

// SimpleOP is a simple OpenID Provider for testing. It implements the
// providers.OpenIdProvider interface and can be used anywhere a real
// provider would be used.
type SimpleOP struct {
	issuer          string
	clientID        string
	commitType      providers.CommitType
	gqSign          bool
	backend         *mocks.MockProviderBackend
	idTokenTemplate *mocks.IDTokenTemplate
	verifierOpts    providers.ProviderVerifierOpts
}

var _ providers.OpenIdProvider = (*SimpleOP)(nil)

// Option configures a SimpleOP.
type Option func(*config)

type config struct {
	clientID   string
	alg        string
	numKeys    int
	gqSign     bool
	commitType providers.CommitType
}

func defaults() config {
	return config{
		clientID:   "test_client_id",
		alg:        "RS256",
		numKeys:    2,
		gqSign:     false,
		commitType: providers.CommitTypesEnum.NONCE_CLAIM,
	}
}

// WithClientID sets the client ID for the provider.
func WithClientID(clientID string) Option {
	return func(c *config) {
		c.clientID = clientID
	}
}

// WithAlg sets the signing algorithm (e.g. "RS256", "ES256", "EdDSA").
func WithAlg(alg string) Option {
	return func(c *config) {
		c.alg = alg
	}
}

// WithNumKeys sets the number of signing keys to generate.
func WithNumKeys(n int) Option {
	return func(c *config) {
		c.numKeys = n
	}
}

// WithGQSign enables GQ signature mode.
func WithGQSign(gqSign bool) Option {
	return func(c *config) {
		c.gqSign = gqSign
	}
}

// WithCommitType sets the commitment type (e.g. NONCE_CLAIM, AUD_CLAIM, GQ_BOUND).
func WithCommitType(ct providers.CommitType) Option {
	return func(c *config) {
		c.commitType = ct
	}
}

// New creates a new SimpleOP with the given issuer and options.
// It automatically configures the verifier options based on the commit type.
func New(issuer string, opts ...Option) (*SimpleOP, error) {
	cfg := defaults()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Auto-enable GQ signing when using GQ_BOUND commitment
	if cfg.commitType.GQCommitment {
		cfg.gqSign = true
	}

	mockBackend, err := mocks.NewMockProviderBackend(issuer, cfg.alg, cfg.numKeys)
	if err != nil {
		return nil, err
	}

	providerSigner, keyID, record := mockBackend.RandomSigningKey()

	commitmentFunc := mocks.NoClaimCommit
	switch cfg.commitType.Claim {
	case "nonce":
		commitmentFunc = mocks.AddNonceCommit
	case "aud":
		commitmentFunc = mocks.AddAudCommit
	}

	aud := cfg.clientID
	if cfg.commitType.GQCommitment {
		aud = providers.AudPrefixForGQCommitment
	}

	idTokenTemplate := &mocks.IDTokenTemplate{
		CommitFunc: commitmentFunc,
		Issuer:     issuer,
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        aud,
		KeyID:      keyID,
		NoKeyID:    false,
		Alg:        record.Alg,
		NoAlg:      false,
		SigningKey: providerSigner,
	}
	mockBackend.SetIDTokenTemplate(idTokenTemplate)

	// Auto-derive verifier options from commit type
	verifierOpts := providers.ProviderVerifierOpts{
		CommitType:        cfg.commitType,
		ClientID:          cfg.clientID,
		SkipClientIDCheck: false,
		GQOnly:            false,
	}
	if cfg.commitType.GQCommitment {
		verifierOpts.SkipClientIDCheck = true
		verifierOpts.GQOnly = true
	}
	if cfg.commitType.Claim == "aud" {
		// When the CIC hash is committed via the aud claim,
		// the audience value is the hash, not the client ID.
		verifierOpts.SkipClientIDCheck = true
	}

	return &SimpleOP{
		issuer:          issuer,
		clientID:        cfg.clientID,
		commitType:      cfg.commitType,
		gqSign:          cfg.gqSign,
		backend:         mockBackend,
		idTokenTemplate: idTokenTemplate,
		verifierOpts:    verifierOpts,
	}, nil
}

func (s *SimpleOP) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	if s.commitType.GQCommitment && !s.gqSign {
		return nil, fmt.Errorf("if GQCommitment is true then GQSign must also be true")
	}

	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}

	tokens, err := s.backend.RequestTokensOverrideFunc(string(cicHash))
	if err != nil {
		return nil, err
	}

	if s.commitType.GQCommitment {
		if tokens.IDToken, err = providers.CreateGQBoundToken(ctx, tokens.IDToken, s, string(cicHash)); err != nil {
			return nil, err
		}
	} else if s.gqSign {
		if tokens.IDToken, err = providers.CreateGQToken(ctx, tokens.IDToken, s); err != nil {
			return nil, err
		}
	}

	return tokens, nil
}

func (s *SimpleOP) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return s.backend.PublicKeyFinder.ByToken(ctx, s.issuer, token)
}

func (s *SimpleOP) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return s.backend.PublicKeyFinder.ByKeyID(ctx, s.issuer, keyID)
}

func (s *SimpleOP) Issuer() string {
	return s.issuer
}

func (s *SimpleOP) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	verifierOpts := s.verifierOpts
	verifierOpts.DiscoverPublicKey = &s.backend.PublicKeyFinder
	return providers.NewProviderVerifier(s.issuer, verifierOpts).VerifyIDToken(ctx, idt, cic)
}

func (s *SimpleOP) RefreshTokens(ctx context.Context, _ []byte) (*simpleoidc.Tokens, error) {
	return s.backend.RequestTokensOverrideFunc("")
}

func (s *SimpleOP) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}

	pkr, err := s.backend.PublicKeyFinder.ByToken(ctx, s.issuer, reIdt)
	if err != nil {
		return err
	}
	alg := jwa.NewSignatureAlgorithm(pkr.Alg)
	if _, err := jws.Verify(reIdt, jws.WithKey(alg, pkr.PublicKey)); err != nil {
		return err
	}

	return nil
}
