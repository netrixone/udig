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

func Test_HTTPResolver_ResolveDomain_mockServer_securityTxtAndRobotsTxt(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/security.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Contact: https://vendor.com/security\nPolicy: https://vendor.com/policy\n"))
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Sitemap: https://cdn.example.com/sitemap.xml\nDisallow: /admin\n"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	resolver := NewHTTPResolver(10 * time.Second)
	resolver.Client = server.Client()
	domain := server.URL[8:]
	resolution := resolver.ResolveDomain(domain).(*HTTPResolution)

	assert.Contains(t, resolution.SecurityTxtDomains, "vendor.com")
	assert.Contains(t, resolution.RobotsTxtDomains, "cdn.example.com")
	allDomains := resolution.Domains()
	assert.Contains(t, allDomains, "vendor.com")
	assert.Contains(t, allDomains, "cdn.example.com")
}

func Test_HTTPResolver_ResolveDomain_mockServer_securityTxt404_ignored(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resolver := NewHTTPResolver(10 * time.Second)
	resolver.Client = server.Client()
	domain := server.URL[8:]
	resolution := resolver.ResolveDomain(domain).(*HTTPResolution)

	assert.Empty(t, resolution.SecurityTxtDomains)
	assert.Empty(t, resolution.RobotsTxtDomains)
}

func Test_HTTPResolution_Domains_deduplicatesAcrossSources(t *testing.T) {
	res := &HTTPResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Headers: []HTTPHeader{
			{Name: "access-control-allow-origin", Value: []string{"https://shared.example.com"}},
		},
		SecurityTxtDomains: []string{"shared.example.com", "vendor.com"},
		RobotsTxtDomains:   []string{"shared.example.com", "cdn.example.com"},
	}
	domains := res.Domains()
	assert.Contains(t, domains, "shared.example.com")
	assert.Contains(t, domains, "vendor.com")
	assert.Contains(t, domains, "cdn.example.com")
	// Count occurrences of shared.example.com — should be exactly 1.
	count := 0
	for _, d := range domains {
		if d == "shared.example.com" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func Test_HTTPHeader_String(t *testing.T) {
	h := HTTPHeader{Name: "x-custom", Value: []string{"a", "b"}}
	assert.Contains(t, h.String(), "x-custom")
	assert.Contains(t, h.String(), "a")
}
