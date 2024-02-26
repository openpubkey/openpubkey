package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/verifier"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

type GithubOp struct {
	rawTokenRequestURL    string
	tokenRequestAuthToken string
}

var _ client.OpenIdProvider = (*GithubOp)(nil)

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
	return verifier.NewProviderVerifier(githubIssuer, "aud", verifier.ProviderVerifierOpts{})
}

func (g *GithubOp) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
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

	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var jwt struct {
		Value *memguard.LockedBuffer
	}
	err = json.Unmarshal(rawBody, &jwt)
	memguard.WipeBytes(rawBody)

	return jwt.Value, err
}
