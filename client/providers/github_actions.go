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
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client/providers/discover"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/verifier"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

type GithubOp struct {
	rawTokenRequestURL    string
	tokenRequestAuthToken string
}

var _ OpenIdProvider = (*GithubOp)(nil)

func NewGithubOpFromEnvironment() (*GithubOp, error) {
	tokenURL, err := getEnvVar("ACTIONS_ID_TOKEN_REQUEST_URL")
	if err != nil {
		return nil, err
	}
	token, err := getEnvVar("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if err != nil {
		return nil, err
	}

	return NewGithubOp(tokenURL, token), nil
}

func getEnvVar(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%q environment variable not set", name)
	}
	return value, nil
}

func NewGithubOp(tokenURL string, token string) *GithubOp {
	return &GithubOp{
		rawTokenRequestURL:    tokenURL,
		tokenRequestAuthToken: token,
	}
}

func buildTokenURL(rawTokenURL, audience string) (string, error) {
	parsedURL, err := url.Parse(rawTokenURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	if audience == "" {
		return "", fmt.Errorf("audience is required")
	}

	query := parsedURL.Query()
	query.Set("audience", audience)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

func (g *GithubOp) Verifier() verifier.ProviderVerifier {
	return verifier.NewProviderVerifier(githubIssuer, "aud", verifier.ProviderVerifierOpts{GQOnly: true, SkipClientIDCheck: true})
}

func (g *GithubOp) PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error) {
	return discover.ProviderPublicKey(ctx, headers, githubIssuer)
}

func (g *GithubOp) requestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	tokenURL, err := buildTokenURL(g.rawTokenRequestURL, cicHash)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Bearer "+g.tokenRequestAuthToken)

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
	err = json.Unmarshal(rawBody.Bytes(), &jwt)
	if err != nil {
		return nil, err
	}
	defer memguard.WipeBytes([]byte(jwt.Value))

	// json.RawMessage leaves the " (quotes) on the string. We need to remove the quotes
	return memguard.NewBufferFromBytes(jwt.Value[1 : len(jwt.Value)-1]), nil
}

func (g *GithubOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error) {
	// Define our commitment as the hash of the client instance claims
	commitment, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}

	// Use the commitment nonce to complete the OIDC flow and get an ID token from the provider
	idTokenLB, err := g.requestTokens(ctx, string(commitment))
	// idTokenLB is the ID Token in a memguard LockedBuffer, this is done
	// because the ID Token contains the OPs RSA signature which is a secret
	// in GQ signatures. For non-GQ signatures OPs RSA signature is considered
	// a public value.
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}
	defer idTokenLB.Destroy()
	gqToken, err := CreateGQToken(ctx, idTokenLB.Bytes(), g)

	return gqToken, err
}
