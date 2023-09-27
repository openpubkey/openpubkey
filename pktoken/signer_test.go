package pktoken

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
)

var (
	signerConfigPath = "test/clcfg"
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
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSigner(signerConfigPath, alg, tc.gq, nil)
			if err != nil {
				t.Error(err)
			}

			// TODO: test signer.CreatePkToken

			sigma, err := signer.Sign([]byte("abcdefgh"))
			if err != nil {
				t.Error(err)
			}

			err = signer.Verify(sigma)
			if err != nil {
				t.Error(err)
			}

			msg, err := jws.Parse(sigma)
			if err != nil {
				t.Error(err)
			}
			if msg == nil {
				t.Error("Message should not be nil, but is nil")
			}

			sigma2, err := signer.Sign([]byte("hgfedcba"))
			if err != nil {
				t.Error(err)
			}

			err = signer.Verify(sigma2)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestSignerReadWrite(t *testing.T) {
	pktComTest := []byte(`eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxODQ5NjgxMzg5MzgtZzFmZGRsNXRnbG83bW5sYmRhazhoYnNxaGhmNzlmMzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ4NTIwMDI0NDQ3NTQxMzYyNzEiLCJlbWFpbCI6ImFub24uYXV0aG9yLmFhcmR2YXJrQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoieklEUDA3WTdFaUhBMVpCdHBZUE5PUSIsIm5vbmNlIjoiTDVRSDBlNDdNaVloT0x1Q3VVeWk3OExMa2lxSEZLYVJ1bzFYQi9zNmVGQSIsIm5hbWUiOiJBbm9ueW1vdXMgQXV0aG9yIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBY0hUdGRWR0Zab19aXzNoajY2ZFgzWjBHVklVUktLb2dCcGlKaDduLVhnPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkFub255bW91cyIsImZhbWlseV9uYW1lIjoiQXV0aG9yIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2ODU1MDYwNzIsImV4cCI6MTY4NTUwOTY3Mn0:eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwODNkZDU5ODE2NzNmNjYxZmRlOWRhZTY0NmI2ZjAzODBhMDE0NWMiLCJ0eXAiOiJKV1QifQ:sFuPHUb8uADv7qcXrP7Y0jWG4rll9e6t38gheuJDkvMd5OkqM1tf7oIzY5KDP3hFct9otG9tHbIDljslVVqGiN6ZUgmWEJIorp4-jGozGwb9NGczAIa-G-gh2-qWBRAxajiSgx4vTP0tMmdRVjEKlF5s9t-v6NedWIFNvpUaSaV-awkQQ-h7AQ0MBsV1CuiEkOl_w8OWpI-W5LKvBwr0xoa7QjlQ2sDqrhnHa-OfdnTAUjobbCgY6EkaaYEBO7uzxfi3ARi7MXHASCbgoqmaMW7aXvKqyuXDrtLD9WK6BGy70vLkwQ70oF7FVSOoCgK6bXpiLeWQHxjrE9gOY4piSg:eyJhbGciOiJFUzI1NiIsInJ6IjoiODc2YzI3OGNjNDhmN2Y2YTVmOTdiZDM5NjY0MzU4ZTMzZWEyMDM4NTZhNzI1ZWJmODI1NzkyYmI5YTNmMGZjZiIsInVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6Ikhzb0dGR3E4NW51Z2k3WE03VElqYzk1bERGcXg1YTFqdnJzUGM2al9pNXciLCJ5IjoiNHliM2JnSVloUFdrSlNydUF1ZEwxSHhGdEFocFNTR1N1bEx2Y0lCNnpVWSJ9fQ:qDp0zTaZtU0TMJBRSdKXQ6Jgy3_U0KbjVAIBg_hSerfkHLFi4-tT8-htwE32LnL-B9K_1wm76kzZotBS7_TmPg:eyJhbGciOiJFUzI1NiIsImF1dGhfdGltZSI6MTY4NTUwNjA3MSwiY3NpZCI6Imh0dHBzOi8vY29zaWduZXIuZXhhbXBsZS5jb20iLCJlaWQiOiIxIiwiZXhwIjoxNjg1NTEzMjcxLCJpYXQiOjE2ODU1MDYwNzEsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6Ing2UVR3OU5Tb2NJNFNrZlptZzJRXzJpaWRyVlYyaVRIRGNyQkYwWkgxTWsiLCJ5IjoiVVhzSnktR1BJNXZ4RG5xTy1mLXVCQnMzX0VhRWlzbmZkR3ZWdllOcVJyOCJ9LCJraWQiOiIiLCJtZmEiOiJub25lIiwicnVyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9hdXRoY29kZSJ9:8hgx5pAnxklUuWwe9d11oebwSAQn6qWOzyUpt8AzOwvDTVB4lvXIiUPBILhgp18EGoLmx_57t-o3FAHZBJYq4A`)

	pkskTest := []byte("-----BEGIN PRIVATE KEY-----\n" +
		"MHcCAQEEIOQe/AVirDf2W/rJodCdUlFNUan95kb+qAR3mOAFnwUCoAoGCCqGSM49\n" +
		"AwEHoUQDQgAE1uVdQJfq/AHaSQ+di6BWQYaYZg9FncncMZXeNC8jDqpmUE4T2IeH\n" +
		"hfOsMCULsLBtsk8YhPe6e5Cl4oNKqfDrjA==\n" +
		"-----END PRIVATE KEY-----\n")

	pksk, err := util.SecretKeyFromBytes(pkskTest)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := LoadSigner(signerConfigPath, pktComTest, pksk, "ES256", false, nil)
	if err != nil {
		t.Fatal(err)
	}

	hashHex, _ := hex.DecodeString("1acdf4f17b921141300a225d9ca41c618890a4d3fff1ec39a7009c31dbb4ea04")
	_, err = signer.Pksk.Sign(rand.Reader, hashHex, crypto.SHA256)
	if err != nil {
		t.Errorf("Error when producing a signature")
		return
	}

	// fmt.Println("sk:" + string(pkskTest))
	// signer.WriteToFile([]byte("a.b.c.d.e"))
	// if err != nil {
	// 	t.Errorf("Error when producing a signature")
	// 	return
	// }
}
