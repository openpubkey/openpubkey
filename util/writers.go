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
	"io"
	"os"
)

type OutOrErrWriter struct {
	// OutputWriter receives non-error, user-facing messages. If nil, output is
	// discarded (io.Discard).
	OutputWriter io.Writer
	// ErrorWriter receives non-fatal error and diagnostic messages. If nil,
	// output is discarded (io.Discard).
	ErrorWriter io.Writer
}

// SetOutWriter configures where non-fatal, user-facing messages are written.
// Passing nil restores the default of io.Discard.
func (w *OutOrErrWriter) SetOutWriter(writer io.Writer) {
	w.OutputWriter = writer
}

// SetErrWriter configures where non-fatal error and diagnostic messages are
// written. Passing nil restores the default of io.Discard.
func (w *OutOrErrWriter) SetErrWriter(writer io.Writer) {
	w.ErrorWriter = writer
}

// UseStdOutErr configures the writer to send user-facing messages to os.Stdout
// and error and diagnostic messages to os.Stderr. It is a convenience method
// for applications that want the library to log to the standard streams.
func (w *OutOrErrWriter) UseStdOutErr() {
	w.OutputWriter = os.Stdout
	w.ErrorWriter = os.Stderr
}

// SetDefaultWriters supplies inherited writers without replacing writers that
// were explicitly configured on the provider.
func (w *OutOrErrWriter) SetDefaultWriters(outWriter, errWriter io.Writer) {
	if w.OutputWriter == nil {
		w.OutputWriter = outWriter
	}
	if w.ErrorWriter == nil {
		w.ErrorWriter = errWriter
	}
}

func (w *OutOrErrWriter) OutWriter() io.Writer {
	if w.OutputWriter == nil {
		return io.Discard
	}
	return w.OutputWriter
}

func (w *OutOrErrWriter) ErrWriter() io.Writer {
	if w.ErrorWriter == nil {
		return io.Discard
	}
	return w.ErrorWriter
}
