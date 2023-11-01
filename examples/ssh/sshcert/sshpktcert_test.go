package sshcert

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

var (
	caSecretKey = testkey(
		`-----BEGIN OPENSSH TEST KEY: DO NOT REPORT-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAzIUpmKvLqHofAXVc/HU4eA9niB3l9mWztelMaa7lB5PSPco+Yw48
bQgg8l3ehBfe2/aLSQgz2nrE+6E23jgtOav57BK3Zs3QIYqpZL8qvSR5xWSvq5wQc1Df+Q
rxdAK40vK4tutYzlIvYiaZu0B3TBxOCIwgcsfX6KJYRjwfhWgBg/Im2+eMsklAA9D3w4rD
kkdArQBnLSC7g2zc/Hi/qGSSDE/g6Y77A0X3Sez+VM5vDzbcer9YhCQVoWVL5s6hFObyqu
JQqTf4JqhSYNhHujNhsLzG2RsTgQkEjwZbEYGKXkKZnc0w7cTpfq0zKkuvuGyMEnyL/6zv
LjR5d68cywAAA8D9LxhQ/S8YUAAAAAdzc2gtcnNhAAABAQDMhSmYq8uoeh8BdVz8dTh4D2
eIHeX2ZbO16UxpruUHk9I9yj5jDjxtCCDyXd6EF97b9otJCDPaesT7oTbeOC05q/nsErdm
zdAhiqlkvyq9JHnFZK+rnBBzUN/5CvF0ArjS8ri261jOUi9iJpm7QHdMHE4IjCByx9fool
hGPB+FaAGD8ibb54yySUAD0PfDisOSR0CtAGctILuDbNz8eL+oZJIMT+DpjvsDRfdJ7P5U
zm8PNtx6v1iEJBWhZUvmzqEU5vKq4lCpN/gmqFJg2Ee6M2GwvMbZGxOBCQSPBlsRgYpeQp
mdzTDtxOl+rTMqS6+4bIwSfIv/rO8uNHl3rxzLAAAAAwEAAQAAAQBKOOlnprE6a1dlSBp+
5Guh5rVECNW0HiSiGBDLKdWkclkSY5tQh5IWX6TVUIu4lJEkcs0JrBhlabijOVaYPvrquy
bwLbqxbG/kPFZNYbM5AUvP/0JhnTm7H9aoovgNig9ZPw0aFT8dYWYg0LFp63NgA8WuBGyi
OzR4ELLIinlGCFqsR8W8C2E3dgogXqJQvaGg4Q+E9xjpxeiySl9eKQCtnul4kJ8tz7adIl
ntdTTpi2K1OkIWGt+jjuOFAe33Vq77ub3TxolIPfh+1COx1YJ4dlTSTZTScRIdX5W3bQZn
681Vi0hqpmtMPkJ7F++38HDJzbd5yaQTcv7m7pXBh7aBAAAAgGyx/CNr3vt+WJKukHu8DZ
naQ/B3lz4GNaJwed0sMpEKuaLXYoaefJKXVPq6hSimC9ScctzOKCizjQf20Goa96Jju4kt
Zerw6y9vgufGL9prXVyjuCyHs4sxwKyOew7QuQzpu3ArVGMCgTfZE9tn0Ga6FfcjgKxvuJ
k+KkoqblEzAAAAgQDnmzWHBeU0oXyMyPt4SeMozqcCkDY6pM+FZspf0zAYfLcrK4Tni74K
enV8+ZyjNPpfNAWZ6roNZQ4HUz5tLs2OMI4OxG+ptWDHbm3nppYqfg0Qcy7jl1NBBh9XNM
AwX2CwpoGpqcKWkcnH3/ZmN/8QIoTjl6uv6U0hLwBbVvFyyQAAAIEA4g+hppjyRW+G2WSW
nCfwQSQ15QL43hQVbPXwZiokEcmaueRjC0s6i/5tjKgnV8eQa9A0BdoxUa67DKCVvthUs/
mFplwGXA0qGsvlqL9TYCm2wA4VLFzXW9bxvPLqI+0WuB79qmZn4V64PSj6XYYPOGdWHw5k
uw2Z5widzugx6PMAAAAHdGVzdF9jYQECAwQ=
-----END OPENSSH TEST KEY: DO NOT REPORT-----`)

	caPubkey, _, _, _, _ = ssh.ParseAuthorizedKey([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMhSmYq8uoeh8BdVz8dTh4D2eIHeX2ZbO16UxpruUHk9I9yj5jDjxtCCDyXd6EF97b9otJCDPaesT7oTbeOC05q/nsErdmzdAhiqlkvyq9JHnFZK+rnBBzUN/5CvF0ArjS8ri261jOUi9iJpm7QHdMHE4IjCByx9foolhGPB+FaAGD8ibb54yySUAD0PfDisOSR0CtAGctILuDbNz8eL+oZJIMT+DpjvsDRfdJ7P5Uzm8PNtx6v1iEJBWhZUvmzqEU5vKq4lCpN/gmqFJg2Ee6M2GwvMbZGxOBCQSPBlsRgYpeQpmdzTDtxOl+rTMqS6+4bIwSfIv/rO8uNHl3rxzL test_ca"))

	testMsg    = []byte("1234")
	badTestMsg = []byte("123X")

	testPktJson, _ = json.Marshal(map[string]any{
		"payload": "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ4NTIwMDI0NDQ3NTQxMzYyNzEiLCJlbWFpbCI6ImFub24uYXV0aG9yLmFhcmR2YXJrQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiVmFGaGtlTE9ITXBxVWQ0RU9ZdW84ZyIsIm5vbmNlIjoiNndXMTExY25BajBlZUxzUGFDOGc5WlVkOXRDS2o1ZGNNZkt6OUZYZUFzYyIsIm5hbWUiOiJBbm9ueW1vdXMgQXV0aG9yIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBY0hUdGRWR0Zab19aXzNoajY2ZFgzWjBHVklVUktLb2dCcGlKaDduLVhnPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkFub255bW91cyIsImZhbWlseV9uYW1lIjoiQXV0aG9yIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2ODUzOTU0MDEsImV4cCI6MTY4NTM5OTAwMX0",
		"signatures": []any{
			map[string]any{
				"protected": "eyJhbGciOiJFUzI1NiIsInJ6IjoiYzllYjhkMDc0MDA0NjJlNTk4MWY2MzU1MWI5NGRjNWVhMGI3MTJkYzUwMjczZjVmYTZjZjBiZmM0ZjU1YmFiMCIsInVwayI6eyJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2Iiwia3R5IjoiRUMiLCJ4IjoiNnFfcjhMN0doeUhubU5uWDZ1MU5tak1wT2I3UzhQY0MwZWJObDZKcE0tQSIsInkiOiIxWmRfTFRTRy0wc0RDUVFwVkNQZnE1dnd1V3EwbHlFVTVBSmp1ZFVQeHhzIn19",
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
)

func testkey(key string) []byte {
	return []byte(strings.ReplaceAll(key, "TEST KEY: DO NOT REPORT", "PRIVATE KEY"))
}

func TestCASignerCreation(t *testing.T) {
	caSigner, err := NewSshSignerFromPem(caSecretKey)
	if err != nil {
		t.Error(err)
	}

	sshSig, err := caSigner.Sign(rand.Reader, testMsg)
	if err != nil {
		t.Error(err)
	}
	err = caPubkey.Verify(badTestMsg, sshSig)
	if err == nil {
		t.Error(fmt.Errorf("expected for signature to fail as the wrong message is used"))
	}
}

func TestSshCertCreation(t *testing.T) {
	caSigner, err := NewSshSignerFromPem(caSecretKey)
	if err != nil {
		t.Error(err)
	}

	principals := []string{"guest", "dev"}
	var pkt *pktoken.PKToken
	err = json.Unmarshal(testPktJson, &pkt)
	if err != nil {
		t.Error(err)
	}

	cert, err := New(pkt, principals)
	if err != nil {
		t.Error(err)
	}

	sshCert, err := cert.SignCert(caSigner)

	if err := cert.VerifyCaSig(caPubkey); err != nil {
		t.Error(err)
	}

	checker := ssh.CertChecker{}
	if err = checker.CheckCert("guest", sshCert); err != nil {
		t.Error(err)
	}

	expectedKeyId := "anon.author.aardvark@gmail.com"
	if sshCert.KeyId != expectedKeyId {
		t.Error(fmt.Errorf("expected KeyId to be (%s) but was (%s)", expectedKeyId, sshCert.KeyId))
	}

	pktB64, ok := sshCert.Extensions["openpubkey-pkt"]
	if !ok {
		t.Error(err)
	}
	pktExtJson, err := util.Base64DecodeForJWT([]byte(pktB64))

	var pktExt *pktoken.PKToken
	err = json.Unmarshal(pktExtJson, &pktExt)
	if err != nil {
		t.Error(err)
	}

	upk, err := pktExt.GetCicPublicKey()
	if err != nil {
		t.Error(err)
	}

	cryptoCertKey := (sshCert.Key.(ssh.CryptoPublicKey)).CryptoPublicKey()
	jwkCertKey, err := jwk.FromRaw(cryptoCertKey)
	if !jwk.Equal(upk, jwkCertKey) {
		t.Error(fmt.Errorf("expected upk to be equal to the value in sshCert.Key"))
	}
}
