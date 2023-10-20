package parties

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken"
)

type MockOp struct{}

func (m *MockOp) RequestTokens(cicHash string) ([]byte, error) {
	idtJws := &jws.Message{}
	idtJws.UnmarshalJSON(testIdtJson)
	return jws.Compact(idtJws)
}
func (m *MockOp) VerifyPKToken(pktJSON []byte, cosPk *ecdsa.PublicKey) (map[string]any, error) {
	return nil, nil
}
func (g *MockOp) PublicKey(idt []byte) (PublicKey, error) {
	jwk, _ := jwk.ParseKey(testIdtPubkeyJson)
	opPubkey := new(rsa.PublicKey)
	err := jwk.Raw(opPubkey)
	return opPubkey, err
}

var (
	testIdtJson, _ = json.Marshal(map[string]any{
		"payload": "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ4NTIwMDI0NDQ3NTQxMzYyNzEiLCJlbWFpbCI6ImFub24uYXV0aG9yLmFhcmR2YXJrQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiZjRWNVRIS3hXbUlSUVdvWVRwTEtLdyIsIm5vbmNlIjoicS9MMEg1RDFiWFlpcjQyc3paU3Q3TGZmTnEyUXF6ZHVGK1FjT3YzTnAwOCIsIm5hbWUiOiJBbm9ueW1vdXMgQXV0aG9yIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0pjVFV3RkRCX1dDLTdNQ2s2NTRlRHRaVm5xdkd6ejlSTS1VR1lpNHV5N21nPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkFub255bW91cyIsImZhbWlseV9uYW1lIjoiQXV0aG9yIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2OTc4MTA4NjEsImV4cCI6MTY5NzgxNDQ2MX0",
		"signatures": []any{
			map[string]any{
				"protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjdkMzM0NDk3NTA2YWNiNzRjZGVlZGFhNjYxODRkMTU1NDdmODM2OTMiLCJ0eXAiOiJKV1QifQ",
				"header": map[string]any{
					"sig_type": "oidc",
				},
				"signature": "LBF6lTYTrbFh6bE1faPySZU4qWR09eskDbbbM4JEOo8DZSZ9JTC_c14SKjA243o3ru-OeuWwtIzrMgVA47D9PZUr164dP7v5cVikfaXG_Zga49HMypDO-gzPpgK9hWcVi3JtxhxgHYPP2KDRUGZKijpNC2Vnmpo6XBkq4wIads1cq4FclY1FLClUWlPM4VfYDzkFVppJPb9NgMkZ1aZdeN7VtcHehF0DGc00hKD_HkG5OR0SjdN6u-WvLF7qTZPvk7D7CTXPKdjAH7xHNG4jm34OVKPtgdR1oKKR5rxxpECn8fbFCxbo05fVBuyJdobhnkDeO8wHv6JnLKGNSxxUhQ",
			},
		},
	})

	testIdtPubkeyJson, _ = json.Marshal(map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"n":   "keFudaSl4KpJ2xC-fIGOb4eD4hwmCVF3eWxginhvrcLNx3ygDjcN7wGRC-CkzJ12ymBGsTPnSBiTFTpwpa5LXEYi-wvN-RkwA8eptcFXIzCXn1k9TqFxaPfw5Qv8N2hj0ZnFR5KPMr1bgK8vktlBu_VbptXr9IKtUEpV0hQCMjmc0JAS61ZIgx9XhPWaRbuYUvmBVLN3ButKAoWqUuzdlP1arjC1R8bUWek3xKUuSSJmZ9oHIGU5omtTEgXRDiv442R3tle-gLcfcr57uPnaAh9bIgBJRZw2mjqP8uBZurq6YkuyUDFQb8NFkBxHigoEdE7di_OtEef2GFNLseE6mw",
		"e":   "AQAB",
		"use": "sig",
		"kid": "7d334497506acb74cdeedaa66184d15547f83693",
	})
)

func TestSigner(t *testing.T) {
	alg := "ES256"

	testCases := []struct {
		name string
		gq   bool
	}{
		{name: "without GQ", gq: false},
		{name: "with GQ", gq: true},
	}

	for _, tc := range testCases {
		op := &MockOp{}

		signer, err := pktoken.NewSigner("", alg, tc.gq, nil)
		if err != nil {
			t.Error(err)
		}

		client := OpkClient{
			Signer: signer,
			Op:     op,
		}
		pktJson, nil := client.OidcAuth()
		if err != nil {
			t.Error(err)
		}

		pkt, err := pktoken.FromJSON(pktJson)
		if err != nil {
			t.Error(err)
		}

		if tc.gq {
			// GQ signatures are randomized so we can not compare exact
			// values without better mocking in place. Instead we compare
			// length as a sanity test.
			// Assumption that current GQ signatures always have the same
			// length validated by looping this test 10000 times
			expectedGqSigLength := 5504
			if len(pkt.OpSig) != expectedGqSigLength {
				t.Errorf("OP GQ Signature length (%d), does not match expected GQ signature length (%d)",
					len(pkt.OpSig), expectedGqSigLength)
			}
		} else {
			expectedSig := []byte("LBF6lTYTrbFh6bE1faPySZU4qWR09eskDbbbM4JEOo8DZSZ9JTC_c14SKjA243o3ru-OeuWwtIzrMgVA47D9PZUr164dP7v5cVikfaXG_Zga49HMypDO-gzPpgK9hWcVi3JtxhxgHYPP2KDRUGZKijpNC2Vnmpo6XBkq4wIads1cq4FclY1FLClUWlPM4VfYDzkFVppJPb9NgMkZ1aZdeN7VtcHehF0DGc00hKD_HkG5OR0SjdN6u-WvLF7qTZPvk7D7CTXPKdjAH7xHNG4jm34OVKPtgdR1oKKR5rxxpECn8fbFCxbo05fVBuyJdobhnkDeO8wHv6JnLKGNSxxUhQ")
			if !bytes.Equal(pkt.OpSig, expectedSig) {
				t.Errorf("OP Signature (%s), does not match expected OP signature (%s)",
					string(pkt.OpSig), string(expectedSig))
			}
		}

	}
}
