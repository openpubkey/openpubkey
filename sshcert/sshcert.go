package sshcert

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"

	// "github.com/openpubkey/openpubkey/parties"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

type SshCertSmuggler struct {
	SshCert *ssh.Certificate
}

func New(pkt *pktoken.PKToken, principals []string) (*SshCertSmuggler, error) {

	// TODO: assumes email exists in ID Token,
	// this will break for OPs like Azure that do not have email as a claim
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, err
	}

	pubkeySsh, err := sshPubkeyFromPKT(pkt)
	if err != nil {
		return nil, err
	}
	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, err
	}
	pktB64 := string(util.Base64EncodeForJWT(pktJson))
	sshSmuggler := SshCertSmuggler{
		SshCert: &ssh.Certificate{
			Key:             pubkeySsh,
			CertType:        ssh.UserCert,
			KeyId:           claims.Email,
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
	return &sshSmuggler, nil
}

func NewFromAuthorizedKey(certType string, certB64 string) (*SshCertSmuggler, error) {
	if certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certType + " " + certB64)); err != nil {
		return nil, err
	} else {
		opkcert := &SshCertSmuggler{
			SshCert: certPubkey.(*ssh.Certificate),
		}
		return opkcert, nil
	}
}

func (s *SshCertSmuggler) SignCert(signerMas ssh.MultiAlgorithmSigner) (*ssh.Certificate, error) {
	if err := s.SshCert.SignCert(rand.Reader, signerMas); err != nil {
		return nil, err
	}
	return s.SshCert, nil
}

func (s *SshCertSmuggler) VerifyCaSig(caPubkey ssh.PublicKey) error {
	certCopy := *(s.SshCert)
	certCopy.Signature = nil
	certBytes := certCopy.Marshal()
	certBytes = certBytes[:len(certBytes)-4] // Drops signature length bytes (see crypto.ssh.certs.go)
	return caPubkey.Verify(certBytes, s.SshCert.Signature)
}

func (s *SshCertSmuggler) GetPKToken() (*pktoken.PKToken, error) {
	pktB64, ok := s.SshCert.Extensions["openpubkey-pkt"]
	if !ok {
		return nil, fmt.Errorf("cert is missing required openpubkey-pkt extension")
	}
	pktJson, err := util.Base64DecodeForJWT([]byte(pktB64))
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}
	var pkt *pktoken.PKToken
	if err = json.Unmarshal(pktJson, &pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

func (s *SshCertSmuggler) VerifySshPktCert(op client.OpenIdProvider) (*pktoken.PKToken, error) {
	pkt, err := s.GetPKToken()
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}

	err = client.VerifyPKToken(context.Background(), pkt, op)
	if err != nil {
		return nil, err
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()

	cryptoCertKey := (s.SshCert.Key.(ssh.CryptoPublicKey)).CryptoPublicKey()
	jwkCertKey, err := jwk.FromRaw(cryptoCertKey)
	if err != nil {
		return nil, err
	}

	if jwk.Equal(jwkCertKey, upk) {
		return pkt, nil
	} else {
		return nil, fmt.Errorf("public key 'upk' in PK Token does not match public key in certificate")
	}
}

func sshPubkeyFromPKT(pkt *pktoken.PKToken) (ssh.PublicKey, error) {
	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()

	var rawkey any
	if err := upk.Raw(&rawkey); err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(rawkey)
}
