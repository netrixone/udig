package udig

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

/////////////////////////////////////////
// CT RESOLVER
/////////////////////////////////////////

const DefaultCTApiUrl = "https://crt.sh"

// DefaultCTPGConnStr is the public read-only crt.sh PostgreSQL endpoint.
// const DefaultCTPGConnStr = "host=crt.sh port=5432 dbname=certwatch user=guest sslmode=prefer connect_timeout=10"
const DefaultCTPGConnStr = "postgresql://guest@crt.sh:5432/certwatch"

var CTApiUrl = DefaultCTApiUrl

// crt.sh not_after formats seen in API responses and PostgreSQL to_char output
var notAfterLayouts = []string{"2006-01-02", "2006-01-02 15:04:05", time.RFC3339}

// CTResolver is a Resolver responsible for resolution of a given domain
// to a list of CT logs. It queries the crt.sh PostgreSQL database directly
// and falls back to the JSON HTTP API if the database is unavailable.
type CTResolver struct {
	Client        *http.Client
	cachedDomains map[string]bool
	ctSince       string // YYYY-MM-DD
	ctExclude     string // e.g. "expired"
	pgConnStr     string // PostgreSQL DSN; empty = skip PG, use API only
	pgDB          *sql.DB
}

// NewCTResolver creates a new CTResolver with sensible defaults.
// since is the minimum log date in YYYY-MM-DD format; exclude is the crt.sh
// exclude parameter (e.g. "expired"); pgConnStr is a PostgreSQL connection
// string (use DefaultCTPGConnStr for the public crt.sh DB, or "" to disable).
func NewCTResolver(timeout time.Duration, since, exclude, pgConnStr string) *CTResolver {
	if since == "" {
		since = time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &CTResolver{
		Client:        client,
		cachedDomains: make(map[string]bool),
		ctSince:       since,
		ctExclude:     exclude,
		pgConnStr:     pgConnStr,
	}
}

// Type returns "CT".
func (r *CTResolver) Type() ResolutionType {
	return TypeCT
}

// ResolveDomain resolves a given domain to CT log results (one resolution per log entry).
func (r *CTResolver) ResolveDomain(domain string) []Resolution {
	if r.isCached(domain) {
		return nil
	}

	logs := r.fetchLogs(domain)
	r.cachedDomains[domain] = true

	var results []Resolution
	for _, log := range logs {
		results = append(results, &CTResolution{
			ResolutionBase: &ResolutionBase{query: domain},
			Record:         log,
		})
	}
	return results
}

func (r *CTResolver) isCached(domain string) bool {
	if r.cachedDomains[domain] {
		return true
	}
	for d := domain; d != ""; d = ParentDomainOf(d) {
		if r.cachedDomains[d] {
			return true
		}
	}
	return false
}

// fetchLogs tries PostgreSQL first; falls back to the HTTP JSON API on any error.
func (r *CTResolver) fetchLogs(domain string) []CTAggregatedLog {
	if r.pgConnStr != "" {
		if logs, err := r.fetchLogsFromPG(domain); err == nil {
			return logs
		} else {
			LogWarn("%s: PG query failed for %s (%s), falling back to HTTP API", TypeCT, domain, err)
		}
	}

	rawLogs := r.fetchLogsFromAPI(domain)
	var filtered []CTLog
	for _, log := range rawLogs {
		if log.LoggedAt >= r.ctSince {
			filtered = append(filtered, log)
		}
	}
	return aggregateCTLogs(filtered)
}

// fetchLogsFromPG queries the crt.sh certwatch PostgreSQL database directly.
// One row per certificate is returned, with SANs joined by newline in NAME_VALUE.
func (r *CTResolver) fetchLogsFromPG(domain string) ([]CTAggregatedLog, error) {
	if r.pgDB == nil {
		cfg, err := pgx.ParseConfig(r.pgConnStr)
		if err != nil {
			return nil, err
		}

		// crt.sh uses PgBouncer in transaction pooling mode, which does not
		// support the extended query protocol (prepared statements). Simple
		// protocol sends queries as plain text without server-side preparation.
		cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		r.pgDB = stdlib.OpenDB(*cfg)
	}

	// When ctExclude == "expired", filter to active certificates only (matching
	// the crt.sh HTTP API behaviour). Otherwise include expired certs too.
	expiredFilter := ""
	if r.ctExclude == "expired" {
		expiredFilter = `
		                  AND coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
		                  AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'`
	}

	// ctSince limits results to certificates first logged on or after that date.
	sinceFilter := ""
	args := []any{domain}
	if r.ctSince != "" {
		sinceFilter = "\n\t\t    AND le.ENTRY_TIMESTAMP >= $2::timestamptz"
		args = append(args, r.ctSince)
	}

	query := `
		WITH ci AS (
		    SELECT min(sub.CERTIFICATE_ID)                        AS ID,
		           min(sub.ISSUER_CA_ID)                         AS ISSUER_CA_ID,
		           string_agg(DISTINCT sub.NAME_VALUE, chr(10))  AS NAME_VALUE,
		           x509_notBefore(sub.CERTIFICATE)               AS NOT_BEFORE,
		           x509_notAfter(sub.CERTIFICATE)                AS NOT_AFTER
		        FROM (SELECT cai.*
		                  FROM certificate_and_identities cai
		                  WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
		                      AND cai.NAME_VALUE LIKE ('%' || $1 || '%')
		                      AND cai.NAME_TYPE IN ('2.5.4.3', 'dNSName')` + expiredFilter + `
		                  LIMIT 10000
		             ) sub
		        GROUP BY sub.CERTIFICATE
		)
		SELECT ca.NAME          AS ISSUER_NAME,
		       ci.NAME_VALUE,
		       ci.ID,
		       le.ENTRY_TIMESTAMP,
		       ci.NOT_BEFORE,
		       ci.NOT_AFTER
		    FROM ci
		            LEFT JOIN LATERAL (
		                SELECT min(ctle.ENTRY_TIMESTAMP) AS ENTRY_TIMESTAMP
		                    FROM ct_log_entry ctle
		                    WHERE ctle.CERTIFICATE_ID = ci.ID
		            ) le ON TRUE,
		         ca
		    WHERE ci.ISSUER_CA_ID = ca.ID` + sinceFilter + `
		    ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST`

	rows, err := r.pgDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []CTAggregatedLog
	for rows.Next() {
		var (
			issuerName string
			nameValue  string
			id         int64
			entryTS    *time.Time
			notBefore  *time.Time
			notAfter   *time.Time
		)

		if err = rows.Scan(
			&issuerName, &nameValue, &id,
			&entryTS, &notBefore, &notAfter,
		); err != nil {
			return nil, err
		}

		var log CTAggregatedLog
		log.Id = id
		log.IssuerName = issuerName
		log.NameValue = nameValue
		if entryTS != nil {
			ts := entryTS.UTC().Format("2006-01-02 15:04:05")
			log.LoggedAt = ts
			log.FirstSeen = ts
			log.LastSeen = ts
		}

		if notBefore != nil {
			log.NotBefore = notBefore.UTC().Format("2006-01-02")
		}

		if notAfter != nil {
			log.NotAfter = notAfter.UTC().Format("2006-01-02")
			log.NotAfterTime, log.Active = parseNotAfter(log.NotAfter)
		}

		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// fetchLogsFromAPI fetches raw CT logs from the crt.sh JSON HTTP API.
func (r *CTResolver) fetchLogsFromAPI(domain string) []CTLog {
	url := fmt.Sprintf("%s/?match=LIKE&exclude=%s&CN=%s&output=json", CTApiUrl, r.ctExclude, domain)
	res, err := r.Client.Get(url)
	if err != nil {
		LogErr("%s: %s -> %s", TypeCT, domain, err.Error())
		return nil
	}
	defer res.Body.Close()

	var rawBody []byte
	if rawBody, err = io.ReadAll(res.Body); err != nil {
		LogErr("%s: %s -> %s", TypeCT, domain, err.Error())
		return nil
	}

	rawLogs := make([]CTLog, 0)
	if err = json.Unmarshal(rawBody, &rawLogs); err != nil {
		LogErr("%s: %s -> %s", TypeCT, domain, err.Error())
		return nil
	}
	return rawLogs
}

// aggregateCTLogs groups raw CT log entries by name_value, keeping first/last
// seen timestamps and the embedded CTLog from the most recent entry.
func aggregateCTLogs(rawLogs []CTLog) []CTAggregatedLog {
	aggregated := make(map[string]*CTAggregatedLog)
	for _, log := range rawLogs {
		if aggregated[log.NameValue] == nil {
			aggregated[log.NameValue] = &CTAggregatedLog{
				CTLog:     log,
				FirstSeen: log.LoggedAt,
				LastSeen:  log.LoggedAt,
			}
		} else {
			if aggregated[log.NameValue].FirstSeen > log.LoggedAt {
				aggregated[log.NameValue].FirstSeen = log.LoggedAt
			}
			if aggregated[log.NameValue].LastSeen < log.LoggedAt {
				aggregated[log.NameValue].LastSeen = log.LoggedAt
				aggregated[log.NameValue].CTLog = log
			}
		}
	}

	var logs []CTAggregatedLog
	for _, log := range aggregated {
		log.NotAfterTime, log.Active = parseNotAfter(log.NotAfter)
		logs = append(logs, *log)
	}
	return logs
}

func parseNotAfter(s string) (t time.Time, active bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range notAfterLayouts {
		if parsed, err := time.Parse(layout, s); err == nil {
			return parsed, !parsed.Before(time.Now())
		}
	}
	return time.Time{}, false
}
