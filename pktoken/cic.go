// Copyright 2024 OpenPubkey
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

package pktoken

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

func (p *PKToken) GetCicValues() (*clientinstance.Claims, error) {
	cicPH, err := p.Cic.ProtectedHeaders().AsMap(context.TODO())
	if err != nil {
		return nil, err
	}

	return clientinstance.ParseClaims(cicPH)
}

func (p *PKToken) VerifyCicSig() error {
	cic, err := p.GetCicValues()
	if err != nil {
		return err
	}

	_, err = jws.Verify(p.CicToken, jws.WithKey(cic.PublicKey().Algorithm(), cic.PublicKey()))
	return err
}
