package parties

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"github.com/zitadel/oidc/v2/pkg/client"
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

func (g *GithubOp) PublicKey(idt []byte) (PublicKey, error) {
	j, err := jws.Parse(idt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}
	headers := j.Signatures()[0].ProtectedHeaders()
	alg, kid := headers.Algorithm(), headers.KeyID()
	if alg != jwa.RS256 {
		return nil, fmt.Errorf("expected RS256 alg claim, got %s", alg)
	}

	discConf, err := client.Discover(githubIssuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(context.TODO(), discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key %q isn't in JWKS", kid)
	}
	keyAlg := key.Algorithm()
	if keyAlg != jwa.RS256 {
		return nil, fmt.Errorf("expected RS256 key, got %s", keyAlg)
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}

func (g *GithubOp) RequestTokens(cicHash string) ([]byte, error) {
	tokenURL, err := buildTokenURL(g.rawTokenRequestURL, cicHash)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("GET", tokenURL, nil)
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
		Value string
	}
	err = json.Unmarshal(rawBody, &jwt)

	return []byte(jwt.Value), err
}

func (g *GithubOp) VerifyPKToken(pktJSON []byte, cosPk *ecdsa.PublicKey) (map[string]any, error) {
	pkt, err := pktoken.FromJSON(pktJSON)
	if err != nil {
		return nil, fmt.Errorf("error parsing PK Token: %w", err)
	}

	if !pkt.OpSigGQ {
		return nil, fmt.Errorf("non-GQ signatures not supported for github")
	}

	cicphJSON, err := util.Base64DecodeForJWT(pkt.CicPH)
	if err != nil {
		return nil, err
	}

	expectedAud := string(util.B64SHA3_256(cicphJSON))

	idt := pkt.OpJWSCompact()

	// TODO: this needs to get the public key from a log of historic public keys based on the iat time in the token
	pubKey, err := g.PublicKey(idt)
	if err != nil {
		return nil, fmt.Errorf("failed to get OP public key: %w", err)
	}

	rsaPubKey := pubKey.(*rsa.PublicKey)

	sv := gq.NewSignerVerifier(rsaPubKey, gqSecurityParameter)
	signingPayload, signature, err := util.SplitJWT(idt)
	if err != nil {
		return nil, fmt.Errorf("failed to split/decode JWT: %w", err)
	}
	ok := sv.Verify(signature, signingPayload, signingPayload)
	if !ok {
		return nil, fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}

	payloadB64 := bytes.Split(signingPayload, []byte{'.'})[1]
	payloadJSON, err := util.Base64DecodeForJWT(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload")
	}

	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload")
	}
	aud := payload["aud"]
	if aud != expectedAud {
		return nil, fmt.Errorf("aud doesn't match, got %q, expected %q", aud, expectedAud)
	}

	err = pkt.VerifyCicSig()
	if err != nil {
		return nil, fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
	}

	// Skip Cosigner signature verification if no cosigner pubkey is supplied
	if cosPk != nil {
		cosPkJwk, err := jwk.FromRaw(cosPk)
		if err != nil {
			return nil, fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
		}

		err = pkt.VerifyCosSig(cosPkJwk, jwa.KeyAlgorithmFrom("ES256"))
		if err != nil {
			return nil, fmt.Errorf("error verify cosigner signature on PK Token: %w", err)
		}
	}

	cicPH := make(map[string]any)
	err = json.Unmarshal(cicphJSON, &cicPH)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling CIC: %w", err)
	}

	return cicPH, nil
}
