// Copyright 2026 OpenPubkey
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

// Package httpserver contains lifecycle helpers for HTTP servers owned by the
// library.
package httpserver

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Shutdown gives active handlers up to gracePeriod to finish, then forcibly
// closes the server. It always uses an independent context because the request
// context that triggered cleanup is commonly already canceled.
func Shutdown(server *http.Server, gracePeriod time.Duration) error {
	if server == nil {
		return nil
	}
	if gracePeriod <= 0 {
		return closeServer(server)
	}

	ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		if closeErr := closeServer(server); closeErr != nil {
			return errors.Join(err, closeErr)
		}
	}
	return nil
}

func closeServer(server *http.Server) error {
	err := server.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
