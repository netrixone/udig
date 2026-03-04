package udig

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test that when pgConnStr is set but the connection fails, the resolver falls
// back to the JSON API and returns its results.
func Test_CTResolver_fetchLogs_pgFails_fallsBackToAPI(t *testing.T) {
	rawLogs := []CTLog{
		{Id: 1, NameValue: "sub.example.com", LoggedAt: "2025-01-15", NotBefore: "2024-01-01", NotAfter: "2030-01-01", IssuerName: "Test CA"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rawLogs)
	}))
	defer server.Close()

	savedURL := CTApiUrl
	CTApiUrl = server.URL
	defer func() { CTApiUrl = savedURL }()

	// Use a connection string that will fail immediately (unreachable host, no retry).
	badConnStr := "host=127.0.0.1 port=1 dbname=certwatch user=guest sslmode=disable connect_timeout=1"
	resolver := NewCTResolver(10*time.Second, "2000-01-01", "", badConnStr)

	logs := resolver.fetchLogs("example.com")

	// Fallback to JSON API should have returned the mocked log.
	require.Len(t, logs, 1)
	assert.Equal(t, "sub.example.com", logs[0].NameValue)
}

// Test that aggregateCTLogs correctly maps raw CTLog entries into CTAggregatedLog
// structs with proper FirstSeen/LastSeen tracking and NotAfterTime/Active fields.
func Test_aggregateCTLogs_mapsCorrectly(t *testing.T) {
	rawLogs := []CTLog{
		{Id: 1, NameValue: "a.example.com", LoggedAt: "2025-01-01", IssuerName: "CA", NotBefore: "2024-01-01", NotAfter: "2030-06-01"},
		{Id: 2, NameValue: "a.example.com", LoggedAt: "2025-06-01", IssuerName: "CA", NotBefore: "2024-01-01", NotAfter: "2030-06-01"},
		{Id: 3, NameValue: "b.example.com", LoggedAt: "2025-03-01", IssuerName: "CA", NotBefore: "2024-01-01", NotAfter: "2020-01-01"},
	}

	logs := aggregateCTLogs(rawLogs)

	require.Len(t, logs, 2)

	byName := make(map[string]CTAggregatedLog)
	for _, l := range logs {
		byName[l.NameValue] = l
	}

	// a.example.com: two entries, should be aggregated
	a := byName["a.example.com"]
	assert.Equal(t, "2025-01-01", a.FirstSeen)
	assert.Equal(t, "2025-06-01", a.LastSeen)
	assert.Equal(t, int64(2), a.Id) // latest entry wins for the embedded CTLog
	assert.True(t, a.Active)        // NotAfter 2030 is in the future

	// b.example.com: single entry, expired certificate
	b := byName["b.example.com"]
	assert.Equal(t, "2025-03-01", b.FirstSeen)
	assert.Equal(t, "2025-03-01", b.LastSeen)
	assert.False(t, b.Active) // NotAfter 2020 is in the past
}

// Integration test: queries crt.sh PostgreSQL directly for a well-known domain.
// Skipped by default; enable with: UDIG_TEST_CRTSH_PG=1 go test -run Integration ./...
func Test_CTResolver_fetchLogsFromPG_integration(t *testing.T) {
	if os.Getenv("UDIG_TEST_CRTSH_PG") != "1" {
		t.Skip("Set UDIG_TEST_CRTSH_PG=1 to run CT PostgreSQL integration tests")
	}

	connStr := "host=crt.sh port=5432 dbname=certwatch user=guest sslmode=prefer connect_timeout=10"
	resolver := NewCTResolver(30*time.Second, "2024-01-01", "expired", connStr)

	logs, err := resolver.fetchLogsFromPG("google.com")
	require.NoError(t, err)
	require.NotEmpty(t, logs, "expected at least one CT log for google.com")

	for _, l := range logs {
		assert.NotEmpty(t, l.NameValue, "NameValue should be set")
		assert.NotEmpty(t, l.LoggedAt, "LoggedAt should be set")
		assert.NotEmpty(t, l.FirstSeen, "FirstSeen should be set")
	}
}
