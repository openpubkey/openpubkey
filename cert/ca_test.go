package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/pktoken"
)

// output SK
// sign object in rektor
// verify object in rektor using cert

func TestCertCreation(t *testing.T) {
	caBytes, caPkSk, err := GenCAKeyPair()
	if err != nil {
		t.Error(err)
	}

	pktCom := []byte("eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ4NTIwMDI0NDQ3NTQxMzYyNzEiLCJlbWFpbCI6ImFub24uYXV0aG9yLmFhcmR2YXJrQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiVmFGaGtlTE9ITXBxVWQ0RU9ZdW84ZyIsIm5vbmNlIjoiNndXMTExY25BajBlZUxzUGFDOGc5WlVkOXRDS2o1ZGNNZkt6OUZYZUFzYyIsIm5hbWUiOiJBbm9ueW1vdXMgQXV0aG9yIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBY0hUdGRWR0Zab19aXzNoajY2ZFgzWjBHVklVUktLb2dCcGlKaDduLVhnPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkFub255bW91cyIsImZhbWlseV9uYW1lIjoiQXV0aG9yIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2ODUzOTU0MDEsImV4cCI6MTY4NTM5OTAwMX0:eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwODNkZDU5ODE2NzNmNjYxZmRlOWRhZTY0NmI2ZjAzODBhMDE0NWMiLCJ0eXAiOiJKV1QifQ:oWEeXaAIS5YPjnrRQuPXx8TKcssMP55BEiLrdnQ3TYFRtt9SXlzB_vmT6vUlnCL_JGts8XGVS-5CpXm03Ai27-oo_oVqTXBCp3BJm_ZglaGgGHLHQBg98sbqtfLmm86L4g9EuPj8bqNHBIKeZIgYZuSpW9tVYnwZwbKBMVepjHHnpjwL8OgBaktHZAzDIj7JTEUuskLPbYrdyReNrxXCfip-nb0-rwFqB3_hi_6jCCBBm9I2WN_kB-80gE3LisCM_4MCfu4KwYg71WIDEpMaQumTQN7hZTjuC2y38qKSepeDyQdcZgo8Yxbpjj9OyjrAJ9XvZQSyaQJ0-qKkwPX6Ug:eyJhbGciOiJFUzI1NiIsInJ6IjoiYzllYjhkMDc0MDA0NjJlNTk4MWY2MzU1MWI5NGRjNWVhMGI3MTJkYzUwMjczZjVmYTZjZjBiZmM0ZjU1YmFiMCIsInVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjZxX3I4TDdHaHlIbm1Oblg2dTFObWpNcE9iN1M4UGNDMGViTmw2SnBNLUEiLCJ5IjoiMVpkX0xUU0ctMHNEQ1FRcFZDUGZxNXZ3dVdxMGx5RVU1QUpqdWRVUHh4cyJ9fQ:kXDYtLRj_wQ2MDgE7Fab5DcV0JhqZlC55CRDVz6GAxgR9mRcp1jwcIchtkf-TsAakEiAeHxcyu9kzw9ERAnKMA:eyJhbGciOiJFUzI1NiIsImF1dGhfdGltZSI6MTY4NTM5NTQwMCwiY3NpZCI6Imh0dHBzOi8vY29zaWduZXIuZXhhbXBsZS5jb20iLCJlaWQiOiIxIiwiZXhwIjoxNjg1NDAyNjAwLCJpYXQiOjE2ODUzOTU0MDAsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6Ii01VVZVVW15YXh6Yl9UeFZpaHZ5Y2ppLUpyWmZqZ2pYZVBDdnhnQnpIcTAiLCJ5IjoiWkZIZzJYcUZ6Vk40U0V3VXJHTHM0QU8zY25LSWMxVUlwanJFeDdVT0JSTSJ9LCJraWQiOiIiLCJtZmEiOiJub25lIiwicnVyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC8ifQ:P_JwaPD7VHNPq5WQADYu7EhO0poz-U-njw__z-swr1LzAr1R1uiJImzuVgL-TNCWelUygsCSoYCDGmR_rUXVYg")
	requiredAudience := "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"

	pemSubCert, err := PktTox509(pktCom, caBytes, caPkSk, requiredAudience)
	if err != nil {
		t.Error(err)
	}

	decodeBlock, _ := pem.Decode(pemSubCert)

	cc, err := x509.ParseCertificate(decodeBlock.Bytes)
	if err != nil {
		t.Error(err)
	}

	certPubkey := cc.PublicKey.(*ecdsa.PublicKey)

	pkt, err := pktoken.FromCompact(pktCom)
	if err != nil {
		t.Error(err)
	}
	sigma := pkt.CicJWSCompact()

	_, err = jws.Verify(sigma, jws.WithKey(jwa.ES256, certPubkey))
	if err != nil {
		t.Error(err)
	}
}
