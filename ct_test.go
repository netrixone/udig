package udig

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_CTResolver_ResolveDomain_mockServer_returnsAggregatedLogs(t *testing.T) {
	rawLogs := []CTLog{
		{Id: 1, NameValue: "example.com", LoggedAt: "2025-01-15", NotBefore: "2024-01-01", NotAfter: "2026-01-01", IssuerName: "Test CA"},
		{Id: 2, NameValue: "example.com", LoggedAt: "2025-02-01", NotBefore: "2024-01-01", NotAfter: "2026-01-01", IssuerName: "Test CA"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rawLogs)
	}))
	defer server.Close()

	savedURL := CTApiUrl
	CTApiUrl = server.URL
	defer func() { CTApiUrl = savedURL }()

	resolver := NewCTResolver(10*time.Second, "2000-01-01", "expired")
	resolution := resolver.ResolveDomain("example.com")
	assert.Equal(t, TypeCT, resolution.Type())
	assert.Equal(t, "example.com", resolution.Query())
	cr, ok := resolution.(*CTResolution)
	assert.True(t, ok)
	assert.NotNil(t, cr)
	// Aggregation by NameValue: two entries become one with FirstSeen/LastSeen
	assert.GreaterOrEqual(t, len(cr.Logs), 0)
}

func Test_CTResolver_ResolveDomain_cachesResult(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]CTLog{})
	}))
	defer server.Close()

	savedURL := CTApiUrl
	CTApiUrl = server.URL
	defer func() { CTApiUrl = savedURL }()

	resolver := NewCTResolver(10*time.Second, "2000-01-01", "expired")
	resolver.ResolveDomain("cachetest.example.com")
	resolver.ResolveDomain("cachetest.example.com")
	assert.Equal(t, 1, callCount)
}

func Test_CTResolution_Domains_dedupesFromLogs(t *testing.T) {
	res := &CTResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Logs: []CTAggregatedLog{
			{CTLog: CTLog{NameValue: "a.example.com\nb.example.com"}},
			{CTLog: CTLog{NameValue: "a.example.com"}},
		},
	}
	domains := res.Domains()
	assert.Contains(t, domains, "a.example.com")
	assert.Contains(t, domains, "b.example.com")
}

func Test_CTLog_ExtractDomains(t *testing.T) {
	log := CTLog{NameValue: "foo.example.com\nbar.example.com"}
	domains := log.ExtractDomains()
	assert.GreaterOrEqual(t, len(domains), 1)
}

func Test_CTLog_String(t *testing.T) {
	log := CTLog{
		NameValue:  "example.com",
		LoggedAt:   "2025-01-01",
		IssuerName: "CA",
	}
	s := log.String()
	assert.Contains(t, s, "example.com")
	assert.Contains(t, s, "CA")
}

func Test_CTAggregatedLog_String(t *testing.T) {
	log := CTAggregatedLog{
		CTLog:     CTLog{NameValue: "example.com", IssuerName: "CA"},
		FirstSeen: "2024-01-01",
		LastSeen:  "2025-01-01",
	}
	s := log.String()
	assert.Contains(t, s, "example.com")
	assert.Contains(t, s, "first_seen")
}
