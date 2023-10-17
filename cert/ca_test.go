package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

func TestCertCreation(t *testing.T) {
	caBytes, caPkSk, err := GenCAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pktJson, err := json.Marshal(map[string]any{
		"payload": "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ4NTIwMDI0NDQ3NTQxMzYyNzEiLCJlbWFpbCI6ImFub24uYXV0aG9yLmFhcmR2YXJrQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiVmFGaGtlTE9ITXBxVWQ0RU9ZdW84ZyIsIm5vbmNlIjoiNndXMTExY25BajBlZUxzUGFDOGc5WlVkOXRDS2o1ZGNNZkt6OUZYZUFzYyIsIm5hbWUiOiJBbm9ueW1vdXMgQXV0aG9yIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBY0hUdGRWR0Zab19aXzNoajY2ZFgzWjBHVklVUktLb2dCcGlKaDduLVhnPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkFub255bW91cyIsImZhbWlseV9uYW1lIjoiQXV0aG9yIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2ODUzOTU0MDEsImV4cCI6MTY4NTM5OTAwMX0",
		"signatures": []any{
			map[string]any{
				"protected": "eyJhbGciOiJFUzI1NiIsInJ6IjoiYzllYjhkMDc0MDA0NjJlNTk4MWY2MzU1MWI5NGRjNWVhMGI3MTJkYzUwMjczZjVmYTZjZjBiZmM0ZjU1YmFiMCIsInVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjZxX3I4TDdHaHlIbm1Oblg2dTFObWpNcE9iN1M4UGNDMGViTmw2SnBNLUEiLCJ5IjoiMVpkX0xUU0ctMHNEQ1FRcFZDUGZxNXZ3dVdxMGx5RVU1QUpqdWRVUHh4cyJ9fQ",
				"header": map[string]any{
					"sig_type": "cic",
				},
				"signature": "kXDYtLRj_wQ2MDgE7Fab5DcV0JhqZlC55CRDVz6GAxgR9mRcp1jwcIchtkf-TsAakEiAeHxcyu9kzw9ERAnKMA",
			},
			map[string]any{
				"protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwODNkZDU5ODE2NzNmNjYxZmRlOWRhZTY0NmI2ZjAzODBhMDE0NWMiLCJ0eXAiOiJKV1QifQ",
				"header": map[string]any{
					"sig_type": "oidc",
				},
				"signature": "oWEeXaAIS5YPjnrRQuPXx8TKcssMP55BEiLrdnQ3TYFRtt9SXlzB_vmT6vUlnCL_JGts8XGVS-5CpXm03Ai27-oo_oVqTXBCp3BJm_ZglaGgGHLHQBg98sbqtfLmm86L4g9EuPj8bqNHBIKeZIgYZuSpW9tVYnwZwbKBMVepjHHnpjwL8OgBaktHZAzDIj7JTEUuskLPbYrdyReNrxXCfip-nb0-rwFqB3_hi_6jCCBBm9I2WN_kB-80gE3LisCM_4MCfu4KwYg71WIDEpMaQumTQN7hZTjuC2y38qKSepeDyQdcZgo8Yxbpjj9OyjrAJ9XvZQSyaQJ0-qKkwPX6Ug",
			},
			map[string]any{
				"protected": "eyJhbGciOiJFUzI1NiIsImF1dGhfdGltZSI6MTY4NTM5NTQwMCwiY3NpZCI6Imh0dHBzOi8vY29zaWduZXIuZXhhbXBsZS5jb20iLCJlaWQiOiIxIiwiZXhwIjoxNjg1NDAyNjAwLCJpYXQiOjE2ODUzOTU0MDAsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6Ii01VVZVVW15YXh6Yl9UeFZpaHZ5Y2ppLUpyWmZqZ2pYZVBDdnhnQnpIcTAiLCJ5IjoiWkZIZzJYcUZ6Vk40U0V3VXJHTHM0QU8zY25LSUNzZ19hcW5EYnZrcXJ4dyJ9fQ",
				"header": map[string]any{
					"sig_type": "cos",
				},
				"signature": "P_JwaPD7VHNPq5WQADYu7EjjXoKTrU0xSLvmhDbfqr3R3VpAq2z44_r90Yl5u3zyTxvVQttJCLfXMkyooYNdbGoyC0aZrHqJYYQXGfiPGZ2xxZtP96yaEweyCw8_FI2x_-0Uc6drwnQR7AFCuLUQZZBfsKmXjxXy4X69fNkHFcZgX9cOYDwJsWKUEixSyHrSnhGPvkw0QdYS9l3tYiEtrfW6mYSVcJqKsv-bw32UG_1W4Lgg9lr_0T3xrtwfcJ35o4hntt5bi1jEzA62oXgfeBhskvFTdncCgV5kSc-gDF1-EXqoRue6QrT7qe4MOyVysR9PrXv_DwbbwnSuGeg",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	requiredAudience := "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"

	pemSubCert, err := PktTox509(pktJson, caBytes, caPkSk, requiredAudience)
	if err != nil {
		t.Fatal(err)
	}

	decodeBlock, _ := pem.Decode(pemSubCert)

	cc, err := x509.ParseCertificate(decodeBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certPubkey := cc.PublicKey.(*ecdsa.PublicKey)

	pkt, err := pktoken.FromJSON(pktJson)
	if err != nil {
		t.Fatal(err)
	}
	sigma := pkt.CicJWSCompact()

	_, err = jws.Verify(sigma, jws.WithKey(jwa.ES256, certPubkey))
	if err != nil {
		t.Fatal(err)
	}

	// Test writing and reading our certificate to and from disk
	certPath := path.Join(os.TempDir(), "cert.pem")
	err = util.WriteCertFile(certPath, cc.Raw)
	if err != nil {
		t.Fatal(err)
	}

	readCert, err := util.ReadCertFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(cc.Raw) != string(readCert.Raw) {
		t.Fatal(fmt.Errorf("did not read in same certificate as we wrote to file"))
	}
}
