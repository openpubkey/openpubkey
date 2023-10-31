package sshcert

import (
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

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

type PktSshCert struct {
	SshCert *ssh.Certificate
}

func BuildPktSshCert(pkt *pktoken.PKToken, principals []string) (*PktSshCert, error) {
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
	opkcert := PktSshCert{
		SshCert: &ssh.Certificate{
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

func NewSshCertFromBytes(certType string, cert64 string) (*PktSshCert, error) {
	if certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certType + " " + cert64)); err != nil {
		return nil, err
	} else {
		opkcert := &PktSshCert{
			SshCert: certPubkey.(*ssh.Certificate),
		}
		return opkcert, nil
	}
}

func (o *PktSshCert) SignCert(caSigner ssh.MultiAlgorithmSigner) (*ssh.Certificate, error) {
	if err := o.SshCert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, err
	}
	return o.SshCert, nil
}

func (o *PktSshCert) VerifyCaSig(caPubkey ssh.PublicKey) error {
	certCopy := *(o.SshCert)
	certCopy.Signature = nil
	certBytes := certCopy.Marshal()
	certBytes = certBytes[:len(certBytes)-4] // Drops signature length bytes (see crypto.ssh.certs.go)
	if err := caPubkey.Verify(certBytes, o.SshCert.Signature); err != nil {
		return err
	}
	return nil
}

func (o *PktSshCert) GetPKToken() (*pktoken.PKToken, error) {
	pktB64, ok := o.SshCert.Extensions["openpubkey-pkt"]
	if !ok {
		return nil, fmt.Errorf("cert is missing required openpubkey-pkt extension")
	}
	pktJson, err := util.Base64DecodeForJWT([]byte(pktB64))
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}
	return pktoken.FromJSON(pktJson)
}

func (o *PktSshCert) VerifySshPktCert(op parties.OpenIdProvider) (*pktoken.PKToken, error) {
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

	cryptoCertKey := (o.SshCert.Key.(ssh.CryptoPublicKey)).CryptoPublicKey()
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
