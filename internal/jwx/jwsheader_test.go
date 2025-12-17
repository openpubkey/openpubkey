// Copyright 2024 OpenPubkey
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

package jwx

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func TestHeadersAsMap(t *testing.T) {
	tests := []struct {
		name          string
		setupHeaders  func() jws.Headers
		expectedMap   map[string]any
		expectedError bool
		errorContains string
	}{
		{
			name: "empty headers",
			setupHeaders: func() jws.Headers {
				return jws.NewHeaders()
			},
			expectedMap:   map[string]any{},
			expectedError: false,
		},
		{
			name: "single header",
			setupHeaders: func() jws.Headers {
				headers := jws.NewHeaders()
				err := headers.Set(jws.AlgorithmKey, "RS256")
				if err != nil {
					t.Fatalf("failed to set header: %v", err)
				}
				return headers
			},
			expectedMap: map[string]any{
				"alg": jwa.RS256(),
			},
			expectedError: false,
		},
		{
			name: "multiple headers",
			setupHeaders: func() jws.Headers {
				headers := jws.NewHeaders()
				err := headers.Set(jws.AlgorithmKey, "ES256")
				if err != nil {
					t.Fatalf("failed to set header: %v", err)
				}
				err = headers.Set(jws.KeyIDKey, "key-id-123")
				if err != nil {
					t.Fatalf("failed to set header: %v", err)
				}
				err = headers.Set(jws.TypeKey, "JWT")
				if err != nil {
					t.Fatalf("failed to set header: %v", err)
				}
				return headers
			},
			expectedMap: map[string]any{
				"alg": jwa.ES256(),
				"kid": "key-id-123",
				"typ": "JWT",
			},
			expectedError: false,
		},
		{
			name: "headers with different value types",
			setupHeaders: func() jws.Headers {
				headers := jws.NewHeaders()
				err := headers.Set(jws.AlgorithmKey, "RS256")
				if err != nil {
					t.Fatalf("failed to set header: %v", err)
				}
				err = headers.Set(jws.KeyIDKey, "key-id-456")
				if err != nil {
					t.Fatalf("failed to set header: %v", err)
				}
				return headers
			},
			expectedMap: map[string]any{
				"alg": jwa.RS256(),
				"kid": "key-id-456",
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.setupHeaders()
			gotMap, err := HeadersAsMap(headers)

			if tt.expectedError {
				require.Error(t, err, "expected error but got none")
				if tt.errorContains != "" {
					require.Contains(t, err.Error(), tt.errorContains, "error message should contain expected text")
				}
				require.Nil(t, gotMap, "map should be nil on error")
			} else {
				require.NoError(t, err, "unexpected error")
				require.NotNil(t, gotMap, "map should not be nil")
				require.Equal(t, len(tt.expectedMap), len(gotMap), "map length should match")

				// Check that all expected keys and values are present
				for key, expectedValue := range tt.expectedMap {
					gotValue, exists := gotMap[key]
					require.True(t, exists, "key %s should exist in map", key)
					require.Equal(t, expectedValue, gotValue, "value for key %s should match", key)
				}

				// Check that no unexpected keys are present
				for key := range gotMap {
					_, exists := tt.expectedMap[key]
					require.True(t, exists, "unexpected key %s in map", key)
				}
			}
		})
	}
}

func TestHeadersAsMapWithAllCommonHeaders(t *testing.T) {
	headers := jws.NewHeaders()

	// Set various common JWT headers
	err := headers.Set(jws.AlgorithmKey, "RS256")
	require.NoError(t, err)

	err = headers.Set(jws.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	err = headers.Set(jws.TypeKey, "JWT")
	require.NoError(t, err)

	err = headers.Set(jws.ContentTypeKey, "application/json")
	require.NoError(t, err)

	headersMap, err := HeadersAsMap(headers)
	require.NoError(t, err)
	require.NotNil(t, headersMap)

	// Verify all headers are present
	// Note: algorithm is stored as jwa.SignatureAlgorithm, not as string
	require.Equal(t, jwa.RS256(), headersMap["alg"])
	require.Equal(t, "test-key-id", headersMap["kid"])
	require.Equal(t, "JWT", headersMap["typ"])
	require.Equal(t, "application/json", headersMap["cty"])
}
