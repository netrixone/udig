package udig

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRDAPResponse = `{
  "handle": "NET-192-0-2-0-1",
  "name": "TEST-NET",
  "startAddress": "192.0.2.0",
  "endAddress": "192.0.2.255",
  "type": "DIRECT ALLOCATION",
  "entities": [
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard", [
        ["fn", {}, "text", "Test Org"],
        ["email", {}, "text", "admin@example.com"]
      ]]
    },
    {
      "roles": ["abuse"],
      "vcardArray": ["vcard", [
        ["email", {}, "text", "abuse@example.com"]
      ]]
    }
  ]
}
`

// mockRDAPTransport intercepts IANA bootstrap request for testing; RDAP is served by httptest.
type mockRDAPTransport struct {
	bootstrapBody string
	transport     http.RoundTripper
}

func (m *mockRDAPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() == ianaBootstrapIPv4 {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(m.bootstrapBody)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	}
	return m.transport.RoundTrip(req)
}

func Test_RDAPResolver_ResolveIP_mockedHTTP_returnsRecord(t *testing.T) {
	// Use a test server to serve RDAP so we have a real base URL for the bootstrap to point to.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		if strings.HasSuffix(r.URL.Path, "/ip/192.0.2.1") {
			_, _ = w.Write([]byte(testRDAPResponse))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Bootstrap that points 192.0.2.0/24 to our test server.
	bootstrap := `{"version":"1.0","services":[[["192.0.2.0/24"],["` + server.URL + `/"]]]}`
	transport := &mockRDAPTransport{
		bootstrapBody: bootstrap,
		transport:     http.DefaultTransport,
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	resolver := &RDAPResolver{
		Client:        client,
		cachedResults: map[string][]Resolution{},
	}

	resolutions := resolver.ResolveIP("192.0.2.1")
	require.Len(t, resolutions, 1)
	require.Equal(t, TypeRDAP, resolutions[0].Type())
	require.Equal(t, "192.0.2.1", resolutions[0].Query())

	rdapRes, ok := resolutions[0].(*RDAPResolution)
	require.True(t, ok)
	assert.Equal(t, "NET-192-0-2-0-1", rdapRes.Record.Handle)
	assert.Equal(t, "TEST-NET", rdapRes.Record.Name)
	assert.Equal(t, "192.0.2.0", rdapRes.Record.StartAddress)
	assert.Equal(t, "192.0.2.255", rdapRes.Record.EndAddress)
	assert.Equal(t, "DIRECT ALLOCATION", rdapRes.Record.NetworkType)
	assert.Equal(t, "abuse@example.com", rdapRes.Record.AbuseEmail)
}

func Test_RDAPResolver_ResolveIP_invalidIP_returnsEmpty(t *testing.T) {
	resolver := NewRDAPResolver(5 * time.Second)
	resolutions := resolver.ResolveIP("not-an-ip")
	assert.Empty(t, resolutions)
}

func Test_RDAPResolver_Type_returnsTypeRDAP(t *testing.T) {
	resolver := NewRDAPResolver(time.Second)
	assert.Equal(t, TypeRDAP, resolver.Type())
}

func Test_RDAPResolution_Type_returnsTypeRDAP(t *testing.T) {
	resolution := &RDAPResolution{ResolutionBase: &ResolutionBase{query: "192.0.2.1"}}
	assert.Equal(t, TypeRDAP, resolution.Type())
}

func Test_RDAPRecord_String(t *testing.T) {
	r := &RDAPRecord{
		Handle:     "NET-1",
		Name:       "Example",
		AbuseEmail: "abuse@example.com",
	}
	s := r.String()
	assert.Contains(t, s, "NET-1")
	assert.Contains(t, s, "Example")
	assert.Contains(t, s, "abuse@example.com")
}
