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
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// https://stackoverflow.com/questions/39320371/how-start-web-server-to-open-page-in-browser-in-golang
// open opens the specified URL in the default browser of the user.
// url must be trusted: on Windows/WSL it is passed to powershell.exe -Command, which is vulnerable to injection if url contains untrusted input.
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

func openWithPowerShell(url string) error {
	return exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-Command",
		"Start-Process",
		url,
	).Start()
}

func isWSL() bool {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}

	release := strings.ToLower(string(data))
	return strings.Contains(release, "microsoft") || strings.Contains(release, "wsl")
}
