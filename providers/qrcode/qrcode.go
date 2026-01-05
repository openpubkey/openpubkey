// Copyright 2025 OpenPubkey
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

package qrcode

import (
	"strings"

	"github.com/bits-and-blooms/bitset"
	"github.com/yeqown/go-qrcode/v2"
)

// Use ascii blocks to form the QR Code
const (
	halfBlockBlackWhite = "▄"
	halfBlockBlackBlack = " "
	halfBlockWhiteBlack = "▀"
	halfBlockWhiteWhite = "█"
)

type halfBlockWriter struct {
	builder *strings.Builder
}

var _ qrcode.Writer = &halfBlockWriter{}

func (w halfBlockWriter) Write(mat qrcode.Matrix) error {
	b := asBitSet(mat)

	ww, hh := mat.Width(), mat.Height()
	// white border top
	w.builder.WriteString(strings.Repeat(halfBlockWhiteWhite, ww+4))
	w.builder.WriteString("\n")

	for y := range hh {
		if y%2 == 1 {
			continue // skip every second row
		}

		for x := range ww {
			// white border left
			if x == 0 {
				w.builder.WriteString(halfBlockWhiteWhite)
				w.builder.WriteString(halfBlockWhiteWhite)
			}

			current := b.Test(uint((ww * y) + x))     // #nosec G115
			below := b.Test(uint((ww * (y + 1)) + x)) // #nosec G115

			switch {
			case current && below:
				w.builder.WriteString(halfBlockBlackBlack)
			case current && !below:
				w.builder.WriteString(halfBlockBlackWhite)
			case !current && !below:
				w.builder.WriteString(halfBlockWhiteWhite)
			default:
				w.builder.WriteString(halfBlockWhiteBlack)
			}

			// white border right
			if x == ww-1 {
				w.builder.WriteString(halfBlockWhiteWhite)
				w.builder.WriteString(halfBlockWhiteWhite)
				w.builder.WriteString("\n")
			}
		}
	}
	// white border bottom
	w.builder.WriteString(strings.Repeat(halfBlockWhiteWhite, ww+4))
	w.builder.WriteString("\n")
	return nil
}

func (w halfBlockWriter) Close() error {
	return nil
}

func asBitSet(mat qrcode.Matrix) *bitset.BitSet {
	var b bitset.BitSet

	ww := mat.Width()

	mat.Iterate(qrcode.IterDirection_ROW, func(x int, y int, state qrcode.QRValue) {
		i := uint((ww * y) + x) // #nosec G115

		b.SetTo(i, state.IsSet())
	})

	return &b
}

// Create returns a ascii qr code for the given text
func Create(text string) (string, error) {
	code, err := qrcode.NewWith(text, qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionHighest))
	if err != nil {
		return "", err
	}
	s := strings.Builder{}
	w := halfBlockWriter{&s}

	err = code.Save(w)
	if err != nil {
		return "", err
	}

	return s.String(), nil
}
