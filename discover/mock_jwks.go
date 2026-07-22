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

package discover

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// createMockJwks builds the JSON JWKS document that MockGetJwksByIssuer would serve
// for the supplied keys, so that tests can hand it to a MockJwksSource or write
// it straight into a cache.
func createMockJwks(t *testing.T, issuer string, publicKeys []crypto.PublicKey, keyIDs []string, algs []string) []byte {
	t.Helper()

	mockJwks, err := MockGetJwksByIssuer(publicKeys, keyIDs, algs)
	require.NoError(t, err)

	jwksJson, err := mockJwks(context.Background(), issuer)
	require.NoError(t, err)

	return jwksJson
}

// MockJwksSource stands in for a provider's JWKS endpoint. It counts calls so
// tests can tell whether a lookup was served from the cache, and its response
// can be swapped mid-test to simulate key rotation, an outage or a malformed
// response.
type MockJwksSource struct {
	mutex    sync.Mutex
	jwksJson []byte
	err      error
	calls    int
}

func NewMockJwksSource(jwksJson []byte) *MockJwksSource {
	return &MockJwksSource{jwksJson: jwksJson}
}

func (m *MockJwksSource) Fetch(_ context.Context, _ string) ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.jwksJson, nil
}

// SetJwks changes the document served by subsequent calls and clears any error
func (m *MockJwksSource) SetJwks(jwksJson []byte) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.jwksJson = jwksJson
	m.err = nil
}

// Fail makes subsequent calls return the supplied error
func (m *MockJwksSource) Fail(err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.err = err
}

// Calls returns the number of times the source has been asked for a JWKS
func (m *MockJwksSource) Calls() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.calls
}

// MockClock is a manually advanced clock for use with
// NewMapDiscoveryCacheWithClock. Now is safe for concurrent use.
type MockClock struct {
	mutex sync.Mutex
	now   time.Time
}

func NewMockClock() *MockClock {
	return &MockClock{now: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (m *MockClock) Now() time.Time {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.now
}

func (m *MockClock) Advance(d time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.now = m.now.Add(d)
}

// MockWriteErrorCache wraps a DiscoveryCache and fails every write, simulating
// a broken persistent backing store
type MockWriteErrorCache struct {
	inner  DiscoveryCache
	mutex  sync.Mutex
	writes int
}

func NewMockWriteErrorCache(inner DiscoveryCache) *MockWriteErrorCache {
	return &MockWriteErrorCache{inner: inner}
}

func (m *MockWriteErrorCache) Read(ctx context.Context, issuer string, maxAge time.Duration) ([]byte, error) {
	return m.inner.Read(ctx, issuer, maxAge)
}

func (m *MockWriteErrorCache) Write(string, []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.writes++
	return errors.New("cache backend unavailable")
}

// Writes returns the number of attempted writes
func (m *MockWriteErrorCache) Writes() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.writes
}
