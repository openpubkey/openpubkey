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
		return openWithPowerShell(url)

	case "darwin":
		return exec.Command("open", url).Start()

	default: // "linux", "freebsd", "openbsd", "netbsd"
		if isWSL() {
			return openWithPowerShell(url)
		}
		return exec.Command("xdg-open", url).Start()
	}
}

// openWithPowerShell launches url via PowerShell using -EncodedCommand.
// The URL is embedded as a PowerShell single-quoted string literal with
// embedded single quotes escaped. This avoids injection through PowerShell
// metacharacters in the URL. -EncodedCommand is used instead of -Command
// because -Command re-joins and re-parses all trailing argv entries as a
// single script, which would otherwise require additional care to avoid
// argv-splitting ambiguity.
func openWithPowerShell(url string) error {
	script := fmt.Sprintf("Start-Process '%s'", strings.ReplaceAll(url, "'", "''"))

	u16 := utf16.Encode([]rune(script))
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	encoded := base64.StdEncoding.EncodeToString(buf)

	return exec.Command("powershell.exe", "-NoProfile", "-EncodedCommand", encoded).Start()
}

func isWSL() bool {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}

	release := strings.ToLower(string(data))
	return strings.Contains(release, "microsoft") || strings.Contains(release, "wsl")
}
