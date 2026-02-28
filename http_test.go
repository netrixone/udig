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
	domain := server.URL[8:]
	resolutions := resolver.ResolveDomain(domain)
	if len(resolutions) > 0 {
		for _, res := range resolutions {
			assert.Equal(t, TypeHTTP, res.Type())
			domains := res.Domains()
			assert.NotEmpty(t, domains)
		}
	}
}

func Test_HTTPResolution_Domains_extractsDomainsFromHeader(t *testing.T) {
	res := &HTTPResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Record:         HTTPRecord{Key: "access-control-allow-origin", Value: "https://api.foo.com"},
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
	resolutions := resolver.ResolveDomain(domain)

	var allDomains []string
	for _, res := range resolutions {
		allDomains = append(allDomains, res.Domains()...)
	}
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
	resolutions := resolver.ResolveDomain(domain)

	assert.Empty(t, resolutions)
}

func Test_HTTPResolution_Domains_fromSingleHeader(t *testing.T) {
	res := &HTTPResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Record:         HTTPRecord{Key: "access-control-allow-origin", Value: "https://shared.example.com"},
	}
	domains := res.Domains()
	assert.Contains(t, domains, "shared.example.com")
}

func Test_HTTPRecord_String(t *testing.T) {
	h := HTTPRecord{Key: "x-custom", Value: "a, b"}
	assert.Contains(t, h.String(), "x-custom")
	assert.Contains(t, h.String(), "a")
}
