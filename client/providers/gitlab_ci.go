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

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/client/providers/discover"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/verifier"
)

const gitlabIssuer = "https://gitlab.com"

type GitlabOp struct {
	issuer          string // Change issuer to point this to a test issuer
	publicKeyFinder discover.PublicKeyFinder
	getTokensFunc   func(string) (string, error)
}

func NewGitlabOpFromEnvironment() (*GitlabOp, error) {
	op := &GitlabOp{
		issuer:          gitlabIssuer,
		publicKeyFinder: *discover.DefaultPubkeyFinder(),
		getTokensFunc:   getEnvVar,
	}
	return op, nil
}

func (g *GitlabOp) Verifier() verifier.ProviderVerifier {
	return verifier.NewProviderVerifier(g.issuer, "", verifier.ProviderVerifierOpts{GQOnly: true, GQCommitment: true, SkipClientIDCheck: true})
}

func (g *GitlabOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByToken(ctx, g.issuer, token)
}

func (g *GitlabOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByKeyID(ctx, g.issuer, keyID)
}

func (g *GitlabOp) PublicKeyByJTK(ctx context.Context, jtk string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByJTK(ctx, g.issuer, jtk)
}

func (g *GitlabOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}

	idToken, err := g.getTokensFunc("OPENPUBKEY-JWT")
	if err != nil {
		return nil, err
	}
	idTokenLB := memguard.NewBufferFromBytes([]byte(idToken))

	// idTokenLB is the ID Token in a memguard LockedBuffer, this is done
	// because the ID Token contains the OPs RSA signature which is a secret
	// in GQ signatures. For non-GQ signatures OPs RSA signature is considered
	// a public value.
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}
	defer idTokenLB.Destroy()
	gqToken, err := CreateGQBoundToken(ctx, idTokenLB.Bytes(), g, string(cicHash))

	return gqToken, err
}
