// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/url"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

// FindAvailablePort attempts to open a listener on localhost until it finds one or runs out of redirectURIs to try
func FindAvailablePort(redirectURIs []string) (*url.URL, net.Listener, error) {
	var ln net.Listener
	var lnErr error
	for _, v := range redirectURIs {
		redirectURI, err := url.Parse(v)
		if err != nil {
			return nil, nil, fmt.Errorf("malformed redirectURI specified, redirectURI was %s", v)
		}

		// Check Hostname(), not Host: Host retains the ":port" suffix and,
		// for IPv6, the "[...]" brackets, which would make a bracketed
		// "[::1]" literal fail the checks below.
		//
		// Require an exact match against "localhost" or a parsed loopback IP
		// rather than a prefix match: strings.HasPrefix(host, "localhost") or
		// strings.HasPrefix(host, "127.0.0.1") would also accept lookalike
		// hostnames such as "localhost.attacker.com" or
		// "127.0.0.1.attacker.com". Those pass a prefix check but resolve via
		// DNS to whatever address an attacker's nameserver returns. Since this
		// host is used directly both to bind the callback listener and as the
		// browser navigation target below, that would let an attacker steer
		// either one off of loopback.
		host := redirectURI.Hostname()
		if host != "localhost" && !isLoopbackIP(host) {
			return nil, nil, fmt.Errorf("redirectURI must be localhost, redirectURI was %s", redirectURI.Host)
		}

		// Bind the redirect URI's actual host rather than a hardcoded
		// "localhost". "localhost" can resolve to both 127.0.0.1 and ::1, so a
		// hardcoded bind picks a single address family; a browser that
		// prefers the other family (most browsers try ::1 first) then
		// connects to a different socket and the OIDC callback is never
		// delivered. Honoring the configured host lets callers pin an IP
		// literal (e.g. 127.0.0.1) for a deterministic single-family bind
		// that the browser navigation below is guaranteed to match.
		ln, lnErr = net.Listen("tcp", redirectURI.Host)
		if lnErr == nil {
			return redirectURI, ln, nil
		}
	}
	return nil, nil, fmt.Errorf("failed to start a listener for the callback from the OP, got %w", lnErr)
}

func configCookieHandler() (*httphelper.CookieHandler, error) {
	// I've been unable to determine a scenario in which setting a hashKey and blockKey
	// on the cookie provide protection in the localhost redirect URI case. However I
	// see no harm in setting it.
	hashKey := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, hashKey); err != nil {
		return nil, fmt.Errorf("failed to generate random keys for cookie storage")
	}
	blockKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, blockKey); err != nil {
		return nil, fmt.Errorf("failed to generate random keys for cookie storage")
	}

	// OpenPubkey uses a localhost redirect URI to receive the authcode
	// from the OP. Localhost redirects use http not https. Thus, we should
	// not set these cookies as secure-only. This should be changed if
	// OpenPubkey added support for non-localhost redirect URIs.
	// WithUnsecure() is equivalent to not setting the 'secure' attribute
	// flag in an HTTP Set-Cookie header (see https://http.dev/set-cookie#secure)
	return httphelper.NewCookieHandler(hashKey, blockKey, httphelper.WithUnsecure()), nil
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
