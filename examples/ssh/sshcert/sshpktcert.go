package sshcert

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"
)

type SshCa struct {
	Signer ssh.MultiAlgorithmSigner
}

func NewSshSignerFromFile(fpath string) (ssh.MultiAlgorithmSigner, error) {
	if pemBytes, err := os.ReadFile(fpath); err != nil {
		return nil, err
	} else {
		return NewSshSignerFromPem(pemBytes)
	}
}

func NewSshSignerFromPem(pemBytes []byte) (ssh.MultiAlgorithmSigner, error) {
	caKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	caSigner, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA256})
}

func (ca *SshCa) IssueCert(pktJson []byte, principals []string) (*ssh.Certificate, error) {
	if sshcert, err := BuildSshCert(pktJson, principals); err != nil {
		return nil, err
	} else {
		return sshcert.SignCert(ca.Signer)
	}
}

type CertIssuer func(pktJson []byte, principals []string) (*ssh.Certificate, error)

type OpkCert struct {
	Cert *ssh.Certificate
}

func BuildSshCert(pktJson []byte, principals []string) (*OpkCert, error) {
	emailOrSub, err := EmailOrSubFromPKTJson(pktJson)
	if err != nil {
		return nil, err
	}
	pubkeySsh, err := SshPubkeyFromPKT(pktJson)
	if err != nil {
		return nil, err
	}
	pktB64 := string(util.Base64EncodeForJWT(pktJson))
	opkcert := OpkCert{
		Cert: &ssh.Certificate{
			Key:             pubkeySsh,
			CertType:        ssh.UserCert,
			KeyId:           emailOrSub,
			ValidPrincipals: principals,
			ValidBefore:     ssh.CertTimeInfinity,
			Permissions: ssh.Permissions{
				Extensions: map[string]string{
					"permit-X11-forwarding":   "",
					"permit-agent-forwarding": "",
					"permit-port-forwarding":  "",
					"permit-pty":              "",
					"permit-user-rc":          "",
					"openpubkey-pkt":          pktB64,
				},
			},
		},
	}
	return &opkcert, nil
}

func NewSshCertFromBytes(certType string, cert64 string) (*OpkCert, error) {
	if certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certType + " " + cert64)); err != nil {
		return nil, err
	} else {
		opkcert := &OpkCert{
			Cert: certPubkey.(*ssh.Certificate),
		}
		return opkcert, nil
	}
}

func (o *OpkCert) SignCert(caSigner ssh.MultiAlgorithmSigner) (*ssh.Certificate, error) {
	if err := o.Cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, err
	}
	return o.Cert, nil
}

func (o *OpkCert) VerifyCaSig(caPubkey ssh.PublicKey) error {
	certCopy := *(o.Cert)
	certCopy.Signature = nil
	certBytes := certCopy.Marshal()
	certBytes = certBytes[:len(certBytes)-4] // Drops signature length bytes (see crypto.ssh.certs.go)
	if err := caPubkey.Verify(certBytes, o.Cert.Signature); err != nil {
		return err
	}
	return nil
}

func (o *OpkCert) GetPKToken() (*pktoken.PKToken, error) {
	pktB64, ok := o.Cert.Extensions["openpubkey-pkt"]
	if !ok {
		return nil, fmt.Errorf("cert is missing required openpubkey-pkt extension")
	}
	pktJson, err := util.Base64DecodeForJWT([]byte(pktB64))
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}
	return pktoken.FromJSON(pktJson)
}

func (o *OpkCert) VerifySshPktCert(op parties.OpenIdProvider) (*pktoken.PKToken, error) {
	pkt, err := o.GetPKToken()
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}

	_, err = op.VerifyPKToken(pkt, nil)
	if err != nil {
		return nil, err
	}

	_, _, upk, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}

	cryptoCertKey := (o.Cert.Key.(ssh.CryptoPublicKey)).CryptoPublicKey()
	jwkCertKey, err := jwk.FromRaw(cryptoCertKey)
	if err != nil {
		return nil, err
	}

	if jwk.Equal(jwkCertKey, upk) {
		return pkt, nil
	} else {
		return nil, fmt.Errorf("identity's public key, 'upk', does not match (cert.key') public key in certificate")
	}
}

// TODO: Collapse these three funcs into the pktoken object by adding a GetClaim(claimKey) func after PR #39 is merged
func EmailFromPKT(pkt *pktoken.PKToken) (string, error) {
	decodePayload, err := base64.RawStdEncoding.DecodeString(string(pkt.Payload))
	if err != nil {
		return "", err
	}
	var claims map[string]interface{}
	if err = json.Unmarshal(decodePayload, &claims); err != nil {
		return "", err
	}
	if email, ok := claims["email"]; ok {
		return email.(string), nil
	} else {
		return "", fmt.Errorf("ID Token does not contain the required email claim")
	}
}

func EmailOrSubFromPKTJson(pktJson []byte) (string, error) {
	pkt, err := pktoken.FromJSON(pktJson)
	if err != nil {
		return "", err
	}
	decodePayload, err := base64.RawStdEncoding.DecodeString(string(pkt.Payload))
	if err != nil {
		return "", err
	}
	var claims map[string]interface{}
	if err = json.Unmarshal(decodePayload, &claims); err != nil {
		return "", err
	}
	if email, ok := claims["email"]; ok {
		return email.(string), nil
	}
	if sub, ok := claims["sub"]; ok {
		return sub.(string), nil
	} else {
		return "", fmt.Errorf("ID Token does not contain the required sub claim")
	}
}

func SshPubkeyFromPKT(pktJson []byte) (ssh.PublicKey, error) {
	pkt, err := pktoken.FromJSON(pktJson)
	if err != nil {
		return nil, err
	}
	_, _, upk, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}

	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err := upk.Raw(&rawkey); err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(rawkey)
}

func CheckCert(userDesired string, cert *OpkCert, policyEnforcer PolicyCheck, op parties.OpenIdProvider) error {
	pkt, err := cert.VerifySshPktCert(op)
	if err != nil {
		return err
	}

	err = policyEnforcer(userDesired, pkt)
	if err != nil {
		return err
	}

	return nil
}

type PolicyCheck func(userDesired string, pkt *pktoken.PKToken) error

func AllowAllPolicyEnforcer(userDesired string, pkt *pktoken.PKToken) error {
	return nil
}

type SimpleFilePolicyEnforcer struct {
	PolicyFilePath string
}

func (p *SimpleFilePolicyEnforcer) ReadPolicyFile() (map[string][]string, error) {
	content, err := os.ReadFile(p.PolicyFilePath)
	if err != nil {
		return nil, err
	}
	rows := strings.Split(string(content), "\n")
	policyMap := make(map[string][]string)

	for i := range rows {
		row := strings.Fields(rows[i])
		if len(row) > 1 {
			email := row[0]
			allowedPrincipals := row[1:]
			policyMap[email] = allowedPrincipals
		}
	}
	return policyMap, nil
}

// TODO: Check file permissions on `/etc/opk/policy` to ensure it is only root writable
func (p *SimpleFilePolicyEnforcer) CheckPolicy(principalDesired string, pkt *pktoken.PKToken) error {
	policyMap, err := p.ReadPolicyFile()
	if err != nil {
		return err
	}
	email, err := EmailFromPKT(pkt)
	if err != nil {
		return err
	}
	if allowedPrincipals, ok := policyMap[email]; ok {
		if slices.Contains(allowedPrincipals, principalDesired) {
			return nil
		}
	}
	return fmt.Errorf("no policy to allow %s to assume %s, check policy config in %s", email, principalDesired, p.PolicyFilePath)
}
