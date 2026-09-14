package discover

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DiscoveryCache represents a cache for discovered JWKS documents, keyed by issuer.
// This package provides two implementations, a dummy one that does nothing at all
// and a simple in-memory cache based on a pair of maps.  Real consumers will
// probably want to provide their own implementations that use a persistent backing
// store such as a filesystem or database.
type DiscoveryCache interface {
	// Read takes an issuer and a maximum cache entry age, and retrieves the
	// latest-dated unexpired (i.e. written less than maxAge ago) cache entry
	// for that issuer
	Read(ctx context.Context, issuer string, maxAge time.Duration) ([]byte, error)
	// Write saves the given value in the cache for the given issuer
	Write(issuer string, value []byte) error
	// Invalidate removes all entries from the cache for the given issuer
	Invalidate(ctx context.Context, issuer string) error
}

// DiscoveryCacheConfig is a convenient holder for a cache and a pair of
// "max age" settings, as these will invariably need to be configured
// all together for any OpenIdProvider
type DiscoveryCacheConfig struct {
	// Cache is the discovery cache (if any) used by this provider
	Cache DiscoveryCache
	// StandardMaxAge is the standard maximum age of a cache entry before it
	// is considered expired
	StandardMaxAge time.Duration
	// FallbackMaxAge is the absolute maximum age of a cache entry - entries
	// older than the StandardMaxAge but younger than the FallbackMaxAge may be
	// used if the provider's JWKS endpoint cannot be reached
	FallbackMaxAge time.Duration
}

// ErrCacheMiss is the error returned by DiscoveryCache.Read if no valid entry
// is found for an issuer within the specified maxAge
var ErrCacheMiss = errors.New("DiscoveryCache: issuer not found")

// NoOpCache is a dummy implementation of DiscoveryCache that does nothing.
// Read calls always return a ErrCacheMiss error, Write calls are a no-op.
type NoOpCache struct{}

func (n NoOpCache) Read(context.Context, string, time.Duration) ([]byte, error) {
	return nil, ErrCacheMiss
}

func (n NoOpCache) Write(string, []byte) error {
	return nil
}

func (n NoOpCache) Invalidate(context.Context, string) error {
	return nil
}

// MapDiscoveryCache is a very simple in-memory cache implementation intended for
// testing, or where a persistent cache is not required.  It maintains a map from
// issuer ID to the retrieved JWKS, and the timestamp at which it was stored; a
// call to Read will return the data that was written, unless the write timestamp
// is older than the maxAge parameter in which case it will return a ErrCacheMiss error.
type MapDiscoveryCache struct {
	// now is the function that is called to determine the current time.  Normally
	// this would be time.Now but you may specify a different function for testing
	// purposes via NewMapDiscoveryCacheWithClock
	now func() time.Time
	// cache is the actual mapping from issuer to JWKS content
	cache map[string][]byte
	// timestamp records the time each entry was last written
	timestamp map[string]time.Time
	// mutex is used to avoid interference between read/write operations and calls
	// to Expire
	mutex sync.RWMutex
}

// NewMapDiscoveryCache creates a default empty cache that uses time.Now as its
// "current time" function
func NewMapDiscoveryCache() *MapDiscoveryCache {
	return NewMapDiscoveryCacheWithClock(time.Now)
}

// NewMapDiscoveryCacheWithClock creates an empty cache that uses the specified
// function to retrieve the current time.
func NewMapDiscoveryCacheWithClock(now func() time.Time) *MapDiscoveryCache {
	return &MapDiscoveryCache{
		now:       now,
		cache:     make(map[string][]byte),
		timestamp: make(map[string]time.Time),
		mutex:     sync.RWMutex{},
	}
}

func (m *MapDiscoveryCache) Read(_ context.Context, issuer string, maxAge time.Duration) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if val, ok := m.cache[issuer]; ok {
		if stamp, ok := m.timestamp[issuer]; ok && stamp.Add(maxAge).After(m.now()) {
			return val, nil
		}
	}
	return nil, ErrCacheMiss
}

func (m *MapDiscoveryCache) Write(issuer string, val []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.cache[issuer] = val
	m.timestamp[issuer] = m.now()
	return nil
}

func (m *MapDiscoveryCache) Invalidate(_ context.Context, issuer string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.cache, issuer)
	delete(m.timestamp, issuer)
	return nil
}

// Expire deletes all entries from the cache map that were last written more
// than maxAge time before now()
func (m *MapDiscoveryCache) Expire(maxAge time.Duration) int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	threshold := m.now().Add(-maxAge)
	var expiredIssuers []string
	for iss, ts := range m.timestamp {
		if ts.Before(threshold) {
			expiredIssuers = append(expiredIssuers, iss)
		}
	}

	for _, iss := range expiredIssuers {
		delete(m.cache, iss)
		delete(m.timestamp, iss)
	}

	return len(expiredIssuers)
}
