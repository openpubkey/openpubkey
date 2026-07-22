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
	"fmt"
	"time"
)

// DefaultAuthWaitTimeout is how long browser-based localhost auth flows wait
// for the user to finish before the library cancels the wait. Matches the
// ~10 minute bound used by public PKCE loopback CLIs such as AWS SSO login.
const DefaultAuthWaitTimeout = 10 * time.Minute

var errAuthWaitTimeout = errors.New("authentication wait timeout")

// ResolveAuthWaitTimeout returns the effective auth-wait duration.
// A zero value means DefaultAuthWaitTimeout. A negative value disables the
// library timeout (only the parent context can cancel the wait).
func ResolveAuthWaitTimeout(timeout time.Duration) time.Duration {
	if timeout < 0 {
		return timeout
	}
	if timeout == 0 {
		return DefaultAuthWaitTimeout
	}
	return timeout
}

// WithAuthWaitTimeout returns a child context that expires when the auth-wait
// timeout elapses, unless timeout is negative (no library timeout) or the
// parent context already has an earlier deadline.
//
// Callers should always defer the returned cancel function.
func WithAuthWaitTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	timeout = ResolveAuthWaitTimeout(timeout)
	if timeout < 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeoutCause(ctx, timeout, errAuthWaitTimeout)
}

// AuthWaitError wraps a context deadline/cancel error from an auth wait with a
// clearer message when the library's auth timeout elapsed. Parent context
// cancellation and deadlines are returned unchanged.
func AuthWaitError(ctx context.Context, timeout time.Duration) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	timeout = ResolveAuthWaitTimeout(timeout)
	if errors.Is(context.Cause(ctx), errAuthWaitTimeout) && timeout > 0 {
		return fmt.Errorf("authentication timed out after waiting %s: %w", timeout, err)
	}
	return err
}
