// Copyright 2025 OpenPubkey
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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

// forgejoIssuerPathSuffix is the path under which a Forgejo instance serves
// its Actions OIDC endpoints. The issuer in ID Tokens is always the instance
// URL followed by this suffix, e.g. https://codeberg.org/api/actions.
const forgejoIssuerPathSuffix = "/api/actions"

// ForgejoOp is an OpenIdProvider for Forgejo Actions (e.g. Codeberg). Forgejo
// runners issue ID Tokens the same way GitHub Actions runners do, using the
// ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN environment
// variables. The issuer is per instance, so it is derived from the token
// request URL rather than being a fixed value.
type ForgejoOp struct {
	issuer                    string
	rawTokenRequestURL        string
	tokenRequestAuthToken     string
	publicKeyFinder           discover.PublicKeyFinder
	requestTokensOverrideFunc func(string) (*simpleoidc.Tokens, error)
}

var _ OpenIdProvider = (*ForgejoOp)(nil)

// NewForgejoOp creates a Forgejo Actions provider for the given issuer, e.g.
// https://codeberg.org/api/actions. tokenURL and token are the values of the
// ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN environment
// variables; they may be empty when the provider is only used to verify ID
// Tokens.
func NewForgejoOp(issuer string, tokenURL string, token string) *ForgejoOp {
	return &ForgejoOp{
		issuer:                strings.TrimSuffix(issuer, "/"),
		rawTokenRequestURL:    tokenURL,
		tokenRequestAuthToken: token,
		publicKeyFinder:       *discover.DefaultPubkeyFinder(),
	}
}

// NewForgejoOpFromEnvironment creates a Forgejo Actions provider from the
// environment variables injected by the Forgejo runner. The issuer is derived
// from the token request URL, so this works on any Forgejo instance without
// additional configuration.
func NewForgejoOpFromEnvironment() (*ForgejoOp, error) {
	tokenURL, err := getEnvVar("ACTIONS_ID_TOKEN_REQUEST_URL")
	if err != nil {
		return nil, err
	}
	token, err := getEnvVar("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if err != nil {
		return nil, err
	}
	issuer, err := ForgejoIssuerFromTokenRequestURL(tokenURL)
	if err != nil {
		return nil, err
	}
	return NewForgejoOp(issuer, tokenURL, token), nil
}

// IsForgejoIssuer reports whether issuer looks like a Forgejo Actions issuer,
// i.e. an instance URL followed by "/api/actions".
func IsForgejoIssuer(issuer string) bool {
	return strings.HasSuffix(strings.TrimSuffix(issuer, "/"), forgejoIssuerPathSuffix)
}

// ForgejoIssuerFromTokenRequestURL derives the instance issuer from the
// ACTIONS_ID_TOKEN_REQUEST_URL set by the Forgejo runner. For example
// https://codeberg.org/api/actions/_apis/pipelines/workflows/42/idtoken?placeholder=true
// yields https://codeberg.org/api/actions. It returns an error if the URL does
// not contain the Forgejo Actions token endpoint path, for example when
// running in GitHub Actions.
func ForgejoIssuerFromTokenRequestURL(tokenRequestURL string) (string, error) {
	parsedURL, err := url.Parse(tokenRequestURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse token request URL: %w", err)
	}
	idx := strings.Index(parsedURL.Path, forgejoIssuerPathSuffix+"/")
	if idx == -1 || parsedURL.Host == "" {
		return "", fmt.Errorf("token request URL (%s) does not contain %s, not a Forgejo Actions environment", tokenRequestURL, forgejoIssuerPathSuffix)
	}
	return parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path[:idx] + forgejoIssuerPathSuffix, nil
}

func (o *ForgejoOp) Issuer() string {
	return o.issuer
}

func (o *ForgejoOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return o.publicKeyFinder.ByKeyID(ctx, o.issuer, keyID)
}

func (o *ForgejoOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return o.publicKeyFinder.ByToken(ctx, o.issuer, token)
}

func (o *ForgejoOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	// Commit to the client instance claims by requesting an ID Token whose
	// audience is the hash of those claims.
	commitment, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}

	// idTokenLB is the ID Token in a memguard LockedBuffer, this is done
	// because the ID Token contains the OPs RSA signature which is a secret
	// in GQ signatures. For non-GQ signatures OPs RSA signature is considered
	// a public value.
	idTokenLB, err := o.requestTokens(ctx, string(commitment))
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}
	defer idTokenLB.Destroy()

	gqToken, err := CreateGQToken(ctx, idTokenLB.Bytes(), o)
	if err != nil {
		return nil, err
	}
	return &simpleoidc.Tokens{IDToken: gqToken}, nil
}

func (o *ForgejoOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(o.issuer, ProviderVerifierOpts{
		CommitType:        CommitTypesEnum.AUD_CLAIM,
		DiscoverPublicKey: &o.publicKeyFinder,
		GQOnly:            true,
		SkipClientIDCheck: true,
	})
	return vp.VerifyIDToken(ctx, idt, cic)
}

func (o *ForgejoOp) requestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	if o.requestTokensOverrideFunc != nil {
		tokens, err := o.requestTokensOverrideFunc(cicHash)
		if err != nil {
			return nil, err
		}
		return memguard.NewBufferFromBytes(tokens.IDToken), nil
	}

	tokenURL, err := buildTokenURL(o.rawTokenRequestURL, cicHash)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+o.tokenRequestAuthToken)

	var httpClient http.Client
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 from jwt api: %s", http.StatusText(response.StatusCode))
	}

	rawBody, err := memguard.NewBufferFromEntireReader(response.Body)
	if err != nil {
		return nil, err
	}
	defer rawBody.Destroy()

	var jwt struct {
		Value json.RawMessage
	}
	if err := json.Unmarshal(rawBody.Bytes(), &jwt); err != nil {
		return nil, err
	}
	defer memguard.WipeBytes([]byte(jwt.Value))

	if len(jwt.Value) < 2 {
		return nil, fmt.Errorf("no ID Token in response from jwt api")
	}
	// json.RawMessage leaves the " (quotes) on the string. We need to remove the quotes
	return memguard.NewBufferFromBytes(jwt.Value[1 : len(jwt.Value)-1]), nil
}
