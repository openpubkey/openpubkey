// Copyright 2026 OpenPubkey
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

package util

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOutOrErrWriterDefaultsToDiscard(t *testing.T) {
	w := &OutOrErrWriter{}
	require.Equal(t, io.Discard, w.OutWriter(), "unset OutputWriter should discard")
	require.Equal(t, io.Discard, w.ErrWriter(), "unset ErrorWriter should discard")
}

func TestOutOrErrWriterSetWriters(t *testing.T) {
	w := &OutOrErrWriter{}
	var out, err bytes.Buffer
	w.SetOutWriter(&out)
	w.SetErrWriter(&err)
	require.Same(t, &out, w.OutWriter())
	require.Same(t, &err, w.ErrWriter())
}

func TestOutOrErrWriterSetNilRestoresDiscard(t *testing.T) {
	w := &OutOrErrWriter{}
	var buf bytes.Buffer
	w.SetOutWriter(&buf)
	w.SetErrWriter(&buf)

	w.SetOutWriter(nil)
	w.SetErrWriter(nil)
	require.Equal(t, io.Discard, w.OutWriter())
	require.Equal(t, io.Discard, w.ErrWriter())
}

func TestOutOrErrWriterUseStdOutErr(t *testing.T) {
	w := &OutOrErrWriter{}
	w.UseStdOutErr()
	require.Same(t, os.Stdout, w.OutWriter())
	require.Same(t, os.Stderr, w.ErrWriter())
}

func TestOutOrErrWriterSetDefaultWritersDoesNotOverride(t *testing.T) {
	var explicitOut, explicitErr, fallbackOut, fallbackErr bytes.Buffer

	// Explicitly configured writers are preserved.
	w := &OutOrErrWriter{}
	w.SetOutWriter(&explicitOut)
	w.SetErrWriter(&explicitErr)
	w.SetDefaultWriters(&fallbackOut, &fallbackErr)
	require.Same(t, &explicitOut, w.OutWriter())
	require.Same(t, &explicitErr, w.ErrWriter())

	// Unset writers inherit the supplied defaults.
	unset := &OutOrErrWriter{}
	unset.SetDefaultWriters(&fallbackOut, &fallbackErr)
	require.Same(t, &fallbackOut, unset.OutWriter())
	require.Same(t, &fallbackErr, unset.ErrWriter())
}
