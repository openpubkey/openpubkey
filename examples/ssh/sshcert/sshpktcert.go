package sshcert

import (
	"crypto/rand"
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

func (ca *SshCa) IssueCert(pkt *pktoken.PKToken, principals []string) (*ssh.Certificate, error) {
	if sshcert, err := BuildSshCert(pkt, principals); err != nil {
		return nil, err
	} else {
		return sshcert.SignCert(ca.Signer)
	}
}

type CertIssuer func(pkt *pktoken.PKToken, principals []string) (*ssh.Certificate, error)

type OpkSshCert struct {
	Cert *ssh.Certificate
}

func BuildSshCert(pkt *pktoken.PKToken, principals []string) (*OpkSshCert, error) {
	emailOrSub, err := EmailOrSubFromPKT(pkt)
	if err != nil {
		return nil, err
	}
	pubkeySsh, err := SshPubkeyFromPKT(pkt)
	if err != nil {
		return nil, err
	}
	pktJson, err := pkt.ToJSON()
	if err != nil {
		return nil, err
	}
	pktB64 := string(util.Base64EncodeForJWT(pktJson))
	opkcert := OpkSshCert{
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

func NewSshCertFromBytes(certType string, cert64 string) (*OpkSshCert, error) {
	if certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certType + " " + cert64)); err != nil {
		return nil, err
	} else {
		opkcert := &OpkSshCert{
			Cert: certPubkey.(*ssh.Certificate),
		}
		return opkcert, nil
	}
}

func (o *OpkSshCert) SignCert(caSigner ssh.MultiAlgorithmSigner) (*ssh.Certificate, error) {
	if err := o.Cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, err
	}
	return o.Cert, nil
}

func (o *OpkSshCert) VerifyCaSig(caPubkey ssh.PublicKey) error {
	certCopy := *(o.Cert)
	certCopy.Signature = nil
	certBytes := certCopy.Marshal()
	certBytes = certBytes[:len(certBytes)-4] // Drops signature length bytes (see crypto.ssh.certs.go)
	if err := caPubkey.Verify(certBytes, o.Cert.Signature); err != nil {
		return err
	}
	return nil
}

func (o *OpkSshCert) GetPKToken() (*pktoken.PKToken, error) {
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

func (o *OpkSshCert) VerifySshPktCert(op parties.OpenIdProvider) (*pktoken.PKToken, error) {
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

func EmailOrSubFromPKT(pkt *pktoken.PKToken) (string, error) {
	claims, err := pkt.GetClaimMap()
	if err != nil {
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

func SshPubkeyFromPKT(pkt *pktoken.PKToken) (ssh.PublicKey, error) {
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

func CheckCert(userDesired string, cert *OpkSshCert, policyEnforcer PolicyCheck, op parties.OpenIdProvider) error {
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
	email, err := pkt.GetClaim("email")
	if err != nil {
		return err
	}
	if allowedPrincipals, ok := policyMap[string(email)]; ok {
		if slices.Contains(allowedPrincipals, principalDesired) {
			return nil
		}
	}
	return fmt.Errorf("no policy to allow %s to assume %s, check policy config in %s", email, principalDesired, p.PolicyFilePath)
}
