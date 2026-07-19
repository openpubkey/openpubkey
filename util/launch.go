// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf16"
)

// https://stackoverflow.com/questions/39320371/how-start-web-server-to-open-page-in-browser-in-golang
// open opens the specified URL in the default browser of the user.
func OpenUrl(url string) error {
	switch runtime.GOOS {
	case "windows":
		return openWithPowerShell(url, false)

	case "darwin":
		return exec.Command("open", url).Start()

	default: // "linux", "freebsd", "openbsd", "netbsd"
		if isWSL() {
			return openWithPowerShell(url, true)
		}
		return exec.Command("xdg-open", url).Start()
	}
}

// validateHTTPURL rejects anything that isn't a hierarchical http(s) URL.
func validateHTTPURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("refusing to open non-http(s) URL: %q", rawURL)
	}
	// Reject opaque "scheme:data" URLs (no "//"), e.g. "http:C:\Windows\...".
	// url.Parse accepts these as valid with Scheme == "http", but they carry
	// no host and are not something a browser should ever be pointed at.
	if u.Host == "" {
		return fmt.Errorf("refusing to open URL with no host: %q", rawURL)
	}
	return nil
}

// openWithPowerShell launches url via PowerShell using -EncodedCommand.
// Only http/https URLs are accepted here, since Start-Process would
// otherwise happily launch a local executable or other registered protocol
// handler. The URL is passed through an environment variable rather than
// embedded in the script text, so it is never parsed as PowerShell syntax
// regardless of what characters it contains. -EncodedCommand is used instead
// of -Command because -Command re-joins and re-parses all trailing argv
// entries as a single script, which would otherwise require additional care
// to avoid argv-splitting ambiguity.
func openWithPowerShell(url string, wsl bool) error {
	if err := validateHTTPURL(url); err != nil {
		return err
	}

	// Internal-only pass-through, not a supported/documented configuration
	// variable: it exists solely to hand url to the child PowerShell process
	// without it ever being parsed as script text. Set on cmd.Env below, so
	// it is scoped to that one subprocess and never touches this process's
	// or any user's actual environment.
	const envVar = "OpenPubkeyBrowserURL"
	const script = `Start-Process "$Env:` + envVar + `"`

	u16 := utf16.Encode([]rune(script))
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	encoded := base64.StdEncoding.EncodeToString(buf)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-EncodedCommand", encoded)
	cmd.Env = append(os.Environ(), envVar+"="+url)
	// On WSL, Win32 processes only inherit Linux env vars listed in WSLENV.
	// Without that bridge, $Env:OpenPubkeyBrowserURL is empty in PowerShell
	// and Start-Process opens nothing. Scoped to this child only.
	// https://devblogs.microsoft.com/commandline/share-environment-vars-between-wsl-and-windows/
	if wsl {
		cmd.Env = append(cmd.Env, "WSLENV="+envVar+"/w")
	}
	return cmd.Start()
}

func isWSL() bool {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}

	release := strings.ToLower(string(data))
	return strings.Contains(release, "microsoft") || strings.Contains(release, "wsl")
}
