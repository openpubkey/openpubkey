package commands

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/bastionzero/opk-ssh/provider"
	"github.com/bastionzero/opk-ssh/sshcert"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/mixpanel/mixpanel-go"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

type loginResult struct {
	pkt        *pktoken.PKToken
	signer     crypto.Signer
	alg        jwa.SignatureAlgorithm
	principals []string
}

func login(ctx context.Context, provider client.OpenIdProvider) (*loginResult, error) {
	var err error
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	client := &client.OpkClient{
		Op: provider,
	}
	pkt, err := client.OidcAuth(ctx, signer, alg, map[string]any{}, false)
	if err != nil {
		return nil, err
	}
	trackLoginViaMixpanel(ctx, pkt)

	// If principals is empty the server does not enforce any principal. The OPK
	// verifier should use policy to make this decision.
	principals := []string{}
	certBytes, seckeySshPem, err := createSSHCert(ctx, pkt, signer, principals)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH cert: %w", err)
	}

	// Write ssh secret key and public key to filesystem
	if err := writeKeysToSSHDir(seckeySshPem, certBytes); err != nil {
		return nil, fmt.Errorf("failed to write SSH keys to filesystem: %w", err)
	}

	return &loginResult{
		pkt:        pkt,
		signer:     signer,
		alg:        alg,
		principals: principals,
	}, nil
}

// Login performs the OIDC login procedure and creates the SSH certs/keys in the
// default SSH key location.
func Login(ctx context.Context, provider client.OpenIdProvider) error {
	_, err := login(ctx, provider)
	return err
}

// LoginWithRefresh performs the OIDC login procedure, creates the SSH
// certs/keys in the default SSH key location, and continues to run and refresh
// the PKT (and create new SSH certs) indefinitely as its token expires. This
// function only returns if it encounters an error or if the supplied context is
// cancelled.
func LoginWithRefresh(ctx context.Context, provider provider.RefreshableOP) error {
	if loginResult, err := login(ctx, provider); err != nil {
		return err
	} else {
		var claims struct {
			Expiration int64 `json:"exp"`
		}
		if err := json.Unmarshal(loginResult.pkt.Payload, &claims); err != nil {
			return err
		}

		for {
			// Sleep until a minute before expiration to give us time to refresh
			// the token and minimize any interruptions
			untilExpired := time.Until(time.Unix(claims.Expiration, 0)) - time.Minute
			log.Printf("Waiting for %v before attempting to refresh id_token...", untilExpired)
			select {
			case <-time.After(untilExpired):
				log.Print("Refreshing id_token...")
			case <-ctx.Done():
				return ctx.Err()
			}

			refreshedIdToken, err := provider.Refresh(ctx)
			if err != nil {
				return err
			}

			loginResult.pkt.Op.PublicHeaders().Set("refreshed_id_token", refreshedIdToken.String())

			certBytes, seckeySshPem, err := createSSHCert(ctx, loginResult.pkt, loginResult.signer, loginResult.principals)
			if err != nil {
				return fmt.Errorf("failed to generate SSH cert: %w", err)
			}

			// Write ssh secret key and public key to filesystem
			if err := writeKeysToSSHDir(seckeySshPem, certBytes); err != nil {
				return fmt.Errorf("failed to write SSH keys to filesystem: %w", err)
			}

			_, payloadB64, _, err := jws.SplitCompactString(refreshedIdToken.String())
			if err != nil {
				return fmt.Errorf("malformed ID token: %w", err)
			}
			payload, err := base64.RawURLEncoding.DecodeString(string(payloadB64))
			if err != nil {
				return fmt.Errorf("refreshed ID token payload is not base64 encoded: %w", err)
			}

			if err = json.Unmarshal(payload, &claims); err != nil {
				return fmt.Errorf("malformed refreshed ID token payload: %w", err)
			}
		}
	}
}

func createSSHCert(ctx context.Context, pkt *pktoken.PKToken, signer crypto.Signer, principals []string) ([]byte, []byte, error) {
	cert, err := sshcert.New(pkt, principals)
	if err != nil {
		return nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, nil, err
	}

	signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		return nil, nil, err
	}

	sshCert, err := cert.SignCert(signerMas)
	if err != nil {
		return nil, nil, err
	}
	certBytes := ssh.MarshalAuthorizedKey(sshCert)
	// Remove newline character that MarshalAuthorizedKey() adds
	certBytes = certBytes[:len(certBytes)-1]

	seckeySsh, err := ssh.MarshalPrivateKey(signer, "openpubkey cert")
	if err != nil {
		return nil, nil, err
	}
	seckeySshBytes := pem.EncodeToMemory(seckeySsh)

	return certBytes, seckeySshBytes, nil
}

func writeKeysToSSHDir(seckeySshPem []byte, certBytes []byte) error {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshPath := filepath.Join(homePath, ".ssh")

	// Make ~/.ssh if folder does not exist
	err = os.MkdirAll(sshPath, os.ModePerm)
	if err != nil {
		return err
	}

	// For ssh to automatically find the key created by openpubkey when
	// connecting, we use one of the default ssh key paths. However, the file
	// might contain an existing key. We will overwrite the key if it was
	// generated by openpubkey  which we check by looking at the associated
	// comment. If the comment is equal to "openpubkey", we overwrite the file
	// with a new key.
	for _, keyFilename := range []string{"id_ecdsa", "id_dsa"} {
		seckeyPath := filepath.Join(sshPath, keyFilename)
		pubkeyPath := seckeyPath + ".pub"

		if !fileExists(seckeyPath) {
			// If ssh key file does not currently exist, we don't have to worry about overwriting it
			return writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
		} else if !fileExists(pubkeyPath) {
			continue
		} else {
			// If the ssh key file does exist, check if it was generated by openpubkey, if it was then it is safe to overwrite
			sshPubkey, err := os.ReadFile(pubkeyPath)
			if err != nil {
				log.Println("Failed to read:", pubkeyPath)
				continue
			}
			_, comment, _, _, err := ssh.ParseAuthorizedKey(sshPubkey)
			if err != nil {
				log.Println("Failed to parse:", pubkeyPath)
				continue
			}

			// If the key comment is "openpubkey" then we generated it
			if comment == "openpubkey" {
				return writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
			}
		}
	}
	return fmt.Errorf("no default ssh key file free for openpubkey")
}

func writeKeys(seckeyPath string, pubkeyPath string, seckeySshPem []byte, certBytes []byte) error {
	// Write ssh secret key to filesystem
	if err := os.WriteFile(seckeyPath, seckeySshPem, 0600); err != nil {
		return err
	}

	log.Printf("writing opk ssh public key to %s and corresponding secret key to %s", pubkeyPath, seckeyPath)

	certBytes = append(certBytes, []byte(" openpubkey")...)
	// Write ssh public key (certificate) to filesystem
	return os.WriteFile(pubkeyPath, certBytes, 0777)
}

func fileExists(fPath string) bool {
	_, err := os.Open(fPath)
	return !errors.Is(err, os.ErrNotExist)
}

func trackLoginViaMixpanel(ctx context.Context, pkt *pktoken.PKToken) {
	idt, err := pkt.Compact(pkt.Op)
	if err != nil {
		return
	}

	sub, _ := client.ExtractClaim(idt, "sub")
	issuer, _ := client.ExtractClaim(idt, "iss")
	if sub == "" || issuer == "" {
		return
	}

	userDistinctId := fmt.Sprintf("%s-%s", sub, issuer)
	email, _ := client.ExtractClaim(idt, "email")

	// This is the project token associated with our Mixpanel project
	// It is safe to hardcode -> https://stackoverflow.com/a/41730503
	mp := mixpanel.NewApiClient("981c739f510b69b7acc222f2a013d4bf")
	if err := mp.Track(ctx, []*mixpanel.Event{
		mp.NewEvent("User logged in", userDistinctId, map[string]any{
			"os": runtime.GOOS,
		}),
	}); err != nil {
		return
	}

	newUser := mixpanel.NewPeopleProperties(userDistinctId, map[string]any{
		"$email": email,
	})

	err = mp.PeopleSet(ctx,
		[]*mixpanel.PeopleProperties{
			newUser,
		},
	)
	if err != nil {
		return
	}
}
