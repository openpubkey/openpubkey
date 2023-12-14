package gq

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"math/big"
	"testing"

	"filippo.io/bigmod"
	"github.com/openpubkey/openpubkey/util"
)

// The test vector specifies hex values for each of the signature scheme's data
// elements, as well as the expected content of the signature
const nHex = "D37B4534B4B788AE23E1E4719A395BBFF8A98EDBDCB3992306C513AAA95E9A335221998C20CD1344CA50C59193B84437FFC1E91E5EBEF9587615875102A7E83624DA4F72CAF28D1DF429652346D6F203E17C65288790F6F6D97835216B49F5932728A967D6D36561621FF38DFC185DFA5A160962E7C8E087CE90897B16EA4EA1"
const vHex = "010000000000000000000D"
const qHex = "3BED38CEBB1219BC068774E0E2655CDEF67FE547BCF2D9FA9FE167B1E63B2F101A1483D38A8F24EDE365A3E44F4F10ADECEA7B30D042C14C162477B8184AE6CFAA78441B1FDFB0B223ABCD528B61F313D859FCF9C26FCAF9E4D9DA9BA83E9D2FDA041E8CCBF90056C31D654B546C1A7F6729A8DD8E68512F39E3B6F07959CE61"
const idHex = "416C657820416D706C65"
const gHex = "3E641A22D0D0747D4ACC71884D3DFF2B2ADFDC1703B5A74EFD8333AB8C4377BB2A9B48E707F73409ABFBCD2DED69F52B16A145CE062FE6BD712C1952110DFB2316C5F3F321922ED375A4DEB8C41FA79BCAD86B0EA0D8FF02C9D0D5911BFF1E87DBCF073F71F18C08EB944AE84883A1E13FB1DEA123B5B1EFEA2A92635BD5D88F"
const rHex = "487CDB0041BEED0323FDD3DEC8542584FA0E6CB990FAD5878DB34E9BEDDC95B65D22790C108E218407ED7F7D686657BAB5A28EF81C2E24985B56E37D9934E195A38A835CC02CEE8EBA2F56C87663E332976F5A3720DACA120BCD3DF0AEF6FD78582EBFCEE6D05E06172A871EAB0E8F5FC22DDB600F541B87CF8E147358374406"
const sigHex = "99394F1D15924C0374CF80C7274CD9F232903A6423D9327156F69743EAEF03E1EFEDFDA8474C97F6570D9EF53C6CE2AE2BA68D01FFF9AA82068214BCD775B95CC297DDC38A63741AB3166B58275E0FB728D26DB18A2C3F14B621CF3863F8648B3149FE896348BE73D37E2F06E6E26C84C044984C09C658300B58EC2383E3B0A1F1390D62B772A69F37B5"

var mISO = []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqo")
var sigISO []byte
var qISO []byte
var idISO []byte
var svISO signerVerifier

// Test our signer using the values specified in ISO/IEC 14888-2:2008
func TestSignerISO(t *testing.T) {
	// The test vector specifies that h(W||M) use SHA-1
	h := hash
	hash = sha1Hash

	// Instead of a true random value for r, use the value from the test vector
	rn := randomNumbers
	randomNumbers = hardcodedRandomISO

	// restore default function definitions after the test
	defer func() {
		hash = h
		randomNumbers = rn
	}()

	encodedSig, err := svISO.Sign(qISO, mISO)
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

// Test our verifier using the values specified in ISO/IEC 14888-2:2008
func TestVerifierISO(t *testing.T) {
	// The test vector specifies that h(W||M) use SHA-1
	h := hash
	hash = sha1Hash

	// The test vector formats Id with PSS. Instead of implementing this
	// encoding ourselves, we hardcode the value for G given in the standard
	ep := encodePKCS1v15
	encodePKCS1v15 = pssEncodedId

	// restore default function definitions after the test
	defer func() {
		hash = h
		encodePKCS1v15 = ep
	}()

	encodedSigISO := util.Base64EncodeForJWT(sigISO)
	ok := svISO.Verify(encodedSigISO, idISO, mISO)

	if !ok {
		t.Fatal("signature verification failed")
	}
}

func init() {
	vBytes, err := hex.DecodeString(vHex)
	if err != nil {
		panic(err)
	}
	v := new(big.Int).SetBytes(vBytes)

	nBytes, err := hex.DecodeString(nHex)
	if err != nil {
		panic(err)
	}
	n, err := bigmod.NewModulusFromBig(new(big.Int).SetBytes(nBytes))
	if err != nil {
		panic(err)
	}

	svISO = signerVerifier{
		n:      n,
		v:      v,
		nBytes: 128,
		vBytes: 10,
		t:      1,
	}

	sigISO, err = hex.DecodeString(sigHex)
	if err != nil {
		panic(err)
	}

	qISO, err = hex.DecodeString(qHex)
	if err != nil {
		panic(err)
	}

	idISO, err = hex.DecodeString(idHex)
	if err != nil {
		panic(err)
	}
}

var pssEncodedId = func(k int, data []byte) []byte {
	em, _ := hex.DecodeString(gHex)
	return em
}

var hardcodedRandomISO = func(t int, n *bigmod.Modulus) ([]*bigmod.Nat, error) {
	ys := make([]*bigmod.Nat, 1)

	rRaw, err := hex.DecodeString(rHex)
	if err != nil {
		return nil, err
	}

	r, err := bigmod.NewNat().SetBytes(rRaw, n)
	if err != nil {
		return nil, err
	}

	ys[0] = r
	return ys, nil
}

var sha1Hash = func(byteCount int, data ...[]byte) ([]byte, error) {
	hash := sha1.New()
	for _, d := range data {
		hash.Write(d)
	}
	return hash.Sum(nil)[:byteCount], nil
}
