package udig

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_HTTPResolver_Type_returnsTypeHTTP(t *testing.T) {
	r := NewHTTPResolver(10 * time.Second)
	assert.Equal(t, TypeHTTP, r.Type())
}

func Test_HTTPResolver_ResolveDomain_mockServer_returnsHeadersWithDomains(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://api.example.com")
		w.Header().Set("Content-Security-Policy", "default-src https://cdn.example.com")
	}))
	defer server.Close()

	resolver := NewHTTPResolver(10 * time.Second)
	resolver.Client = server.Client()
	// Domain is host:port so that "https://"+domain == server.URL
	domain := server.URL[8:] // strip "https://"
	resolution := resolver.ResolveDomain(domain)
	assert.Equal(t, TypeHTTP, resolution.Type())
	hr, ok := resolution.(*HTTPResolution)
	assert.True(t, ok)
	assert.NotNil(t, hr)
	if len(hr.Headers) > 0 {
		domains := hr.Domains()
		assert.NotEmpty(t, domains)
	}
}

func Test_HTTPResolution_Domains_extractsDomainsFromHeaders(t *testing.T) {
	res := &HTTPResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Headers: []HTTPHeader{
			{Name: "access-control-allow-origin", Value: []string{"https://api.foo.com"}},
		},
	}
	domains := res.Domains()
	assert.Contains(t, domains, "api.foo.com")
}

func Test_HTTPHeader_String(t *testing.T) {
	h := HTTPHeader{Name: "x-custom", Value: []string{"a", "b"}}
	assert.Contains(t, h.String(), "x-custom")
	assert.Contains(t, h.String(), "a")
}
