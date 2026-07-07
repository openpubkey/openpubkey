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
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindAvailablePort(t *testing.T) {
	redirects := []string{
		"http://localhost:21111/login-callback",
		"http://localhost:21012/login-callback",
		"http://localhost:30125/login-callback",
	}

	testCases := []struct {
		name           string
		expRedirectURI string
		expError       string
		portsToBlock   int
	}{
		{name: "Happy case", expRedirectURI: "http://localhost:21111/login-callback",
			expError: "", portsToBlock: 0},
		{name: "Happy case: first port in use", expRedirectURI: "http://localhost:21012/login-callback",
			expError: "", portsToBlock: 1},
		{name: "Happy case: first and second port in use", expRedirectURI: "http://localhost:30125/login-callback",
			expError: "", portsToBlock: 2},
		{name: "Check error when all ports in use", expRedirectURI: "",
			expError: "failed to start a listener for the callback", portsToBlock: len(redirects)},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blockedPorts := []net.Listener{}
			// Simulate the case where a port is in use and the provider has to use a different redirect URI
			for i := 0; i < tc.portsToBlock; i++ {
				parsedUrl, err := url.Parse(redirects[i])
				require.NoError(t, err)
				lnStr := fmt.Sprintf("localhost:%s", parsedUrl.Port())
				ln, err := net.Listen("tcp", lnStr)
				require.NoError(t, err)
				blockedPorts = append(blockedPorts, ln)
			}

			foundURI, ln, err := FindAvailablePort(redirects)

			if tc.expError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expError)
				require.Nil(t, ln)
				require.Nil(t, foundURI)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expRedirectURI, foundURI.String())
				require.NotNil(t, ln)
				err = ln.Close()
				require.NoError(t, err)
			}

			for _, lis := range blockedPorts {
				err := lis.Close()
				require.NoError(t, err)
			}
		})
	}
}

// TestFindAvailablePortBindsConfiguredHost locks in the contract that
// FindAvailablePort binds the exact host from the redirect URI rather than a
// hardcoded "localhost". "localhost" can resolve to both 127.0.0.1 and ::1,
// so a hardcoded bind picks one address family while the browser (which
// typically prefers ::1) may connect to the other and lose the callback.
// Pinning an IP literal makes the bind and the browser callback
// deterministically agree.
func TestFindAvailablePortBindsConfiguredHost(t *testing.T) {
	// Port 0 lets the kernel pick a free port, so the test never collides with
	// whatever else is running locally.
	t.Run("IPv4 literal binds IPv4 loopback", func(t *testing.T) {
		foundURI, ln, err := FindAvailablePort([]string{"http://127.0.0.1:0/login/callback"})
		require.NoError(t, err)
		defer ln.Close() //nolint:errcheck
		require.Equal(t, "127.0.0.1", foundURI.Hostname())
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		require.True(t, ok)
		require.NotNil(t, tcpAddr.IP.To4(), "expected an IPv4 bind, got %s", tcpAddr.IP)
		require.True(t, tcpAddr.IP.IsLoopback())
	})

	// This case is what actually distinguishes the fixed behavior from the
	// old hardcoded "localhost" bind: on a typical host "localhost" resolves
	// to IPv4 first, so the old code would have bound 127.0.0.1 here and
	// failed the IPv6 assertions below.
	t.Run("IPv6 literal binds IPv6 loopback", func(t *testing.T) {
		probe, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		require.NoError(t, probe.Close())

		foundURI, ln, err := FindAvailablePort([]string{"http://[::1]:0/login/callback"})
		require.NoError(t, err)
		defer ln.Close() //nolint:errcheck
		require.Equal(t, "::1", foundURI.Hostname())
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		require.True(t, ok)
		require.Nil(t, tcpAddr.IP.To4(), "expected an IPv6 bind, got %s", tcpAddr.IP)
		require.True(t, tcpAddr.IP.IsLoopback())
	})
}

// TestFindAvailablePortRejectsNonLoopbackHost locks in that the redirect
// URI's host must be exactly "localhost" or a loopback IP literal. A
// prefix-based check (e.g. strings.HasPrefix(host, "127.0.0.1")) would wrongly
// accept lookalike hostnames such as "127.0.0.1.attacker.com" or
// "localhost.attacker.com", which resolve via DNS to whatever address an
// attacker's nameserver returns rather than to loopback.
func TestFindAvailablePortRejectsNonLoopbackHost(t *testing.T) {
	badRedirects := []string{
		"http://localhost.attacker.com:0/login/callback",
		"http://127.0.0.1.attacker.com:0/login/callback",
		"http://localhostevil.com:0/login/callback",
		"http://evil.com:0/login/callback",
		"http://8.8.8.8:0/login/callback",
	}
	for _, redirect := range badRedirects {
		t.Run(redirect, func(t *testing.T) {
			foundURI, ln, err := FindAvailablePort([]string{redirect})
			require.Error(t, err)
			require.ErrorContains(t, err, "redirectURI must be localhost")
			require.Nil(t, ln)
			require.Nil(t, foundURI)
		})
	}
}

func TestConfigCookieHandler(t *testing.T) {
	cookieHandler, err := configCookieHandler()
	require.NoError(t, err)
	require.NotNil(t, cookieHandler)
}
