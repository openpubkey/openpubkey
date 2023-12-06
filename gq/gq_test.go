package gq

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"filippo.io/bigmod"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
)

var vIso = new(big.Int).SetBytes([]byte(hexToBytes(nil, "010000000000000000000D")))
var messageIso = []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqo")
var sigISO = hexToBytes(nil, "99394F1D15924C0374CF80C7274CD9F232903A6423D9327156F69743EAEF03E1EFEDFDA8474C97F6570D9EF53C6CE2AE2BA68D01FFF9AA82068214BCD775B95CC297DDC38A63741AB3166B58275E0FB728D26DB18A2C3F14B621CF3863F8648B3149FE896348BE73D37E2F06E6E26C84C044984C09C658300B58EC2383E3B0A1F1390D62B772A69F37B5")

var pssEncodedId = func(k int, data []byte) []byte {
	return hexToBytes(nil, "3E641A22D0D0747D4ACC71884D3DFF2B2ADFDC1703B5A74EFD8333AB8C4377BB2A9B48E707F73409ABFBCD2DED69F52B16A145CE062FE6BD712C1952110DFB2316C5F3F321922ED375A4DEB8C41FA79BCAD86B0EA0D8FF02C9D0D5911BFF1E87DBCF073F71F18C08EB944AE84883A1E13FB1DEA123B5B1EFEA2A92635BD5D88F")
}

var randomISO = func(t int, n *bigmod.Modulus) ([]*bigmod.Nat, error) {
	ys := make([]*bigmod.Nat, t)

	rRaw := hexToBytes(nil, "487CDB0041BEED0323FDD3DEC8542584FA0E6CB990FAD5878DB34E9BEDDC95B65D22790C108E218407ED7F7D686657BAB5A28EF81C2E24985B56E37D9934E195A38A835CC02CEE8EBA2F56C87663E332976F5A3720DACA120BCD3DF0AEF6FD78582EBFCEE6D05E06172A871EAB0E8F5FC22DDB600F541B87CF8E147358374406")
	r, err := bigmod.NewNat().SetBytes(rRaw, n)
	if err != nil {
		return nil, err
	}

	ys[0] = r
	return ys, nil
}

// TODO:
var sha1Hash = func(byteCount int, data ...[]byte) ([]byte, error) {
	rng := sha1.New()
	for _, d := range data {
		rng.Write(d)
	}
	return rng.Sum(nil)[:byteCount], nil
}

func TestProveVerify(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	if err != nil {
		t.Fatal(err)
	}

	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	if err != nil {
		t.Fatal(err)
	}

	gqToken, err := signerVerifier.SignJWT(idToken)
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(gqToken)
	if !ok {
		t.Fatal("signature verification failed")
	}
}

func TestSignerISO(t *testing.T) {
	h := hash
	hash = sha1Hash

	rn := randomNumbers
	randomNumbers = randomISO

	defer func() {
		hash = h
		randomNumbers = rn
	}()

	sv := signerVerifierISO(t)
	Q := hexToBytes(t, "3BED38CEBB1219BC068774E0E2655CDEF67FE547BCF2D9FA9FE167B1E63B2F101A1483D38A8F24EDE365A3E44F4F10ADECEA7B30D042C14C162477B8184AE6CFAA78441B1FDFB0B223ABCD528B61F313D859FCF9C26FCAF9E4D9DA9BA83E9D2FDA041E8CCBF90056C31D654B546C1A7F6729A8DD8E68512F39E3B6F07959CE61")

	encodedSig, err := sv.Sign(Q, messageIso)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := util.Base64DecodeForJWT(encodedSig)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sig, sigISO) {
		t.Fatal("Signature does not match expected value")
	}
}

func TestVerifierISO(t *testing.T) {
	h := hash
	hash = sha1Hash

	e := encodePKCS1v15
	encodePKCS1v15 = pssEncodedId

	defer func() {
		hash = h
		encodePKCS1v15 = e
	}()

	sv := signerVerifierISO(t)
	encodedSig := util.Base64EncodeForJWT(sigISO)
	id := hexToBytes(t, "416C657820416D706C65")

	ok := sv.Verify(encodedSig, id, messageIso)

	if !ok {
		t.Fatal("signature verification failed")
	}
}

func TestVerifyModifiedIdPayload(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	if err != nil {
		t.Fatal(err)
	}

	// modify the ID Token payload to detect IdP signature invalidity via GQ verify
	modifiedToken, err := modifyTokenPayload(idToken, "fail")
	if err != nil {
		t.Fatal(err)
	}
	_, err = jws.Verify(modifiedToken, jws.WithKey(jwa.RS256, oidcPubKey))
	if err == nil {
		t.Fatal("ID token signature should fail for modified token")
	}
	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	if err != nil {
		t.Fatal(err)
	}
	gqToken, err := signerVerifier.SignJWT(modifiedToken)
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(gqToken)
	if ok {
		t.Fatal("GQ signature verification passed for invalid payload")
	}
}

func TestVerifyModifiedGqPayload(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	if err != nil {
		t.Fatal(err)
	}

	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	if err != nil {
		t.Fatal(err)
	}
	gqToken, err := signerVerifier.SignJWT(idToken)
	if err != nil {
		t.Fatal(err)
	}

	// modify the ID Token payload to detect GQ signature invalidity
	modifiedToken, err := modifyTokenPayload(gqToken, "fail")
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(modifiedToken)
	if ok {
		t.Fatal("GQ signature verification passed for invalid payload")
	}
}

func modifyTokenPayload(token []byte, audience string) ([]byte, error) {
	headers, _, signature, err := jws.SplitCompact(token)
	if err != nil {
		return nil, err
	}
	newPayload := map[string]any{
		"sub": "1",
		"iss": "test",
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	modifiedPayload, err := json.Marshal(newPayload)
	if err != nil {
		return nil, err
	}
	newToken := bytes.Join([][]byte{headers, util.Base64EncodeForJWT(modifiedPayload), signature}, []byte{'.'})
	return newToken, nil
}

func createOIDCToken(oidcPrivKey *rsa.PrivateKey, audience string) ([]byte, error) {
	alg := jwa.RS256 // RSASSA-PKCS-v1.5 using SHA-256

	oidcHeader := jws.NewHeaders()
	oidcHeader.Set("alg", alg.String())
	oidcHeader.Set("typ", "JWT")

	oidcPayload := map[string]any{
		"sub": "1",
		"iss": "test",
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(oidcPayload)
	if err != nil {
		return nil, err
	}

	jwt, err := jws.Sign(
		payloadBytes,
		jws.WithKey(
			alg,
			oidcPrivKey,
			jws.WithProtectedHeaders(oidcHeader),
		),
	)
	if err != nil {
		return nil, err
	}

	return jwt, nil
}

// FIXME: not sure about passing t here...
func hexToBytes(t *testing.T, hexStr string) []byte {
	bytes := make([]byte, hex.DecodedLen(len(hexStr)))
	_, err := hex.Decode(bytes, []byte(hexStr))
	if err != nil {
		t.Fatal(err)
	}

	return bytes
}

// TODO:
func signerVerifierISO(t *testing.T) signerVerifier {
	nBytes := hexToBytes(t, "D37B4534B4B788AE23E1E4719A395BBFF8A98EDBDCB3992306C513AAA95E9A335221998C20CD1344CA50C59193B84437FFC1E91E5EBEF9587615875102A7E83624DA4F72CAF28D1DF429652346D6F203E17C65288790F6F6D97835216B49F5932728A967D6D36561621FF38DFC185DFA5A160962E7C8E087CE90897B16EA4EA1")
	n, err := bigmod.NewModulusFromBig(new(big.Int).SetBytes(nBytes))
	if err != nil {
		t.Fatal(err)
	}

	nLen := n.BitLen()
	vLen := vIso.BitLen() - 1
	return signerVerifier{
		n:      n,
		v:      vIso,
		t:      1,
		nBytes: bytesForBits(nLen),
		vBytes: bytesForBits(vLen),
	}
}
