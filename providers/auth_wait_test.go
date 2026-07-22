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

package providers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolveAuthWaitTimeout(t *testing.T) {
	t.Parallel()
	require.Equal(t, DefaultAuthWaitTimeout, ResolveAuthWaitTimeout(0))
	require.Equal(t, 2*time.Minute, ResolveAuthWaitTimeout(2*time.Minute))
	require.Equal(t, time.Duration(-1), ResolveAuthWaitTimeout(-1))
}

func TestWithAuthWaitTimeoutHonorsParentDeadline(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	authCtx, cancelAuth := WithAuthWaitTimeout(parent, time.Hour)
	defer cancelAuth()

	deadline, ok := authCtx.Deadline()
	require.True(t, ok)
	parentDeadline, ok := parent.Deadline()
	require.True(t, ok)
	require.Equal(t, parentDeadline, deadline)

	<-authCtx.Done()
	require.ErrorIs(t, authCtx.Err(), context.DeadlineExceeded)
	err := AuthWaitError(authCtx, time.Hour)
	require.Equal(t, context.DeadlineExceeded, err)
	require.NotContains(t, err.Error(), "authentication timed out")
}

func TestWithAuthWaitTimeoutHonorsAlreadyCanceledParent(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.Background())
	cancel()

	authCtx, cancelAuth := WithAuthWaitTimeout(parent, time.Hour)
	defer cancelAuth()
	<-authCtx.Done()
	require.Equal(t, context.Canceled, AuthWaitError(authCtx, time.Hour))
}

func TestWithAuthWaitTimeoutAppliesDefault(t *testing.T) {
	t.Parallel()
	authCtx, cancelAuth := WithAuthWaitTimeout(context.Background(), 20*time.Millisecond)
	defer cancelAuth()

	<-authCtx.Done()
	err := AuthWaitError(authCtx, 20*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Contains(t, err.Error(), "authentication timed out after waiting 20ms")
}

func TestWithAuthWaitTimeoutNegativeDisables(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancel(context.Background())
	authCtx, cancelAuth := WithAuthWaitTimeout(parent, -1)
	defer cancelAuth()

	_, ok := authCtx.Deadline()
	require.False(t, ok)
	select {
	case <-authCtx.Done():
		t.Fatal("negative timeout expired without parent cancellation")
	case <-time.After(20 * time.Millisecond):
	}
	cancelParent()
	<-authCtx.Done()
	require.Equal(t, context.Canceled, AuthWaitError(authCtx, -1))
}

func TestAuthWaitErrorPassthrough(t *testing.T) {
	t.Parallel()
	require.Nil(t, AuthWaitError(context.Background(), time.Minute))

	canceledCtx, cancel := context.WithCancelCause(context.Background())
	err := errors.New("other")
	cancel(err)
	require.ErrorIs(t, context.Cause(canceledCtx), err)
	require.ErrorIs(t, AuthWaitError(canceledCtx, time.Minute), context.Canceled)
}
