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

package httpserver

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShutdownForcesActiveHandlerClosedAfterGracePeriod(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	handlerStarted := make(chan struct{})
	handlerCanceled := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(handlerStarted)
		<-r.Context().Done()
		close(handlerCanceled)
	})}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- requestErr
	}()

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}

	started := time.Now()
	require.NoError(t, Shutdown(server, 20*time.Millisecond))
	require.Less(t, time.Since(started), time.Second)

	select {
	case <-handlerCanceled:
	case <-time.After(time.Second):
		t.Fatal("forced close did not cancel the active handler")
	}
	require.Error(t, <-requestDone)
	require.ErrorIs(t, <-serveDone, http.ErrServerClosed)

	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	connection, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err)
}

func TestShutdownTreatsAlreadyClosedServerAsSuccess(t *testing.T) {
	server := &http.Server{}
	require.NoError(t, server.Close())
	require.NoError(t, Shutdown(server, time.Second))
}
