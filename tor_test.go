package udig

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testOnionooExitResponse = `{
  "version": "8.0",
  "relays_published": "2026-03-04 08:00:00",
  "relays": [
    {
      "nickname": "testExit",
      "fingerprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "flags": ["Exit", "Fast", "Running", "Valid"],
      "or_addresses": ["1.2.3.4:443"],
      "exit_addresses": ["1.2.3.4"]
    }
  ],
  "bridges": []
}`

const testOnionooRelayResponse = `{
  "version": "8.0",
  "relays_published": "2026-03-04 08:00:00",
  "relays": [
    {
      "nickname": "testRelay",
      "fingerprint": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "flags": ["Guard", "Fast", "Running", "Valid"],
      "or_addresses": ["1.2.3.4:9001"],
      "exit_addresses": []
    }
  ],
  "bridges": []
}`

const testOnionooEmptyResponse = `{
  "version": "8.0",
  "relays_published": "2026-03-04 08:00:00",
  "relays": [],
  "bridges": []
}`

func newTorTestResolver(handler http.HandlerFunc) (*TorResolver, *httptest.Server) {
	server := httptest.NewServer(handler)
	resolver := &TorResolver{
		Client: &http.Client{Timeout: 5 * time.Second},
	}
	// Override the base URL by monkey-patching is not possible here without
	// refactoring, so we use a custom transport that redirects to the test server.
	resolver.Client.Transport = &rewriteHostTransport{
		base:      server.URL,
		transport: http.DefaultTransport,
	}
	return resolver, server
}

// rewriteHostTransport redirects all requests to a fixed base URL for testing.
type rewriteHostTransport struct {
	base      string
	transport http.RoundTripper
}

func (t *rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = "http"
	req2.URL.Host = req.URL.Host
	// Replace scheme+host with test server base, keep path+query.
	base := t.base
	req2.URL.Scheme = "http"
	// Extract host from base URL.
	req2.URL.Host = base[len("http://"):]
	return t.transport.RoundTrip(req2)
}

// Test_TorResolver_ResolveIP_exitNode verifies that an exit relay produces a
// resolution with the Exit flag set.
func Test_TorResolver_ResolveIP_exitNode_returnsTrue(t *testing.T) {
	resolver, server := newTorTestResolver(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testOnionooExitResponse))
	})
	defer server.Close()

	resolutions := resolver.ResolveIP("1.2.3.4")

	require.Len(t, resolutions, 1)
	assert.Equal(t, TypeTor, resolutions[0].Type())
	assert.Equal(t, "1.2.3.4", resolutions[0].Query())
	assert.Nil(t, resolutions[0].Domains())
	assert.Nil(t, resolutions[0].IPs())

	torRes, ok := resolutions[0].(*TorResolution)
	require.True(t, ok)
	assert.Equal(t, "testExit", torRes.Record.Nickname)
	assert.Equal(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", torRes.Record.Fingerprint)
	assert.Contains(t, torRes.Record.Flags, "Exit")
	assert.True(t, torRes.Record.IsExitNode())
}

// Test_TorResolver_ResolveIP_middleRelay verifies that a non-exit relay is
// returned but IsExitNode() returns false.
func Test_TorResolver_ResolveIP_middleRelay_returnsRelay(t *testing.T) {
	resolver, server := newTorTestResolver(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testOnionooRelayResponse))
	})
	defer server.Close()

	resolutions := resolver.ResolveIP("1.2.3.4")

	require.Len(t, resolutions, 1)
	torRes, ok := resolutions[0].(*TorResolution)
	require.True(t, ok)
	assert.Equal(t, "testRelay", torRes.Record.Nickname)
	assert.False(t, torRes.Record.IsExitNode())
}

// Test_TorResolver_ResolveIP_notListed verifies that an empty relays array
// yields an empty result slice.
func Test_TorResolver_ResolveIP_notListed_returnsEmpty(t *testing.T) {
	resolver, server := newTorTestResolver(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testOnionooEmptyResponse))
	})
	defer server.Close()

	resolutions := resolver.ResolveIP("1.2.3.4")

	assert.Empty(t, resolutions)
}

// Test_TorResolver_ResolveIP_httpError verifies that a non-200 response yields nil.
func Test_TorResolver_ResolveIP_httpError_returnsNil(t *testing.T) {
	resolver, server := newTorTestResolver(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	defer server.Close()

	resolutions := resolver.ResolveIP("1.2.3.4")

	assert.Nil(t, resolutions)
}

// Test_TorResolver_ResolveIP_invalidIP verifies that an invalid IP returns nil
// without panicking.
func Test_TorResolver_ResolveIP_invalidIP_returnsNil(t *testing.T) {
	resolver := NewTorResolver(5 * time.Second)
	resolutions := resolver.ResolveIP("not-an-ip")

	assert.Nil(t, resolutions)
}

// Test_TorRecord_String_exitNode verifies the string representation for an exit node.
func Test_TorRecord_String_exitNode(t *testing.T) {
	r := TorRecord{Nickname: "myExit", Fingerprint: "AAAA", Flags: []string{"Exit", "Fast"}}
	s := r.String()
	assert.Contains(t, s, "exit node")
	assert.Contains(t, s, "myExit")
}

// Test_TorRecord_String_relay verifies the string representation for a non-exit relay.
func Test_TorRecord_String_relay(t *testing.T) {
	r := TorRecord{Nickname: "myRelay", Fingerprint: "BBBB", Flags: []string{"Guard", "Fast"}}
	s := r.String()
	assert.Contains(t, s, "relay")
	assert.NotContains(t, s, "exit node")
	assert.Contains(t, s, "myRelay")
}

// Test_TorResolver_Type verifies the resolver type constant.
func Test_TorResolver_Type_returnsTypeTor(t *testing.T) {
	resolver := NewTorResolver(5 * time.Second)
	assert.Equal(t, TypeTor, resolver.Type())
}

// Test_TorResolution_Type verifies the resolution type constant.
func Test_TorResolution_Type_returnsTypeTor(t *testing.T) {
	resolution := &TorResolution{ResolutionBase: &ResolutionBase{query: "1.2.3.4"}}
	assert.Equal(t, TypeTor, resolution.Type())
}
