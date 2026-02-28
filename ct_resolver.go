package udig

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

/////////////////////////////////////////
// CT RESOLVER
/////////////////////////////////////////

const DefaultCTApiUrl = "https://crt.sh"

var CTApiUrl = DefaultCTApiUrl

// crt.sh not_after formats seen in API responses
var notAfterLayouts = []string{"2006-01-02", "2006-01-02 15:04:05", time.RFC3339}

// CTResolver is a Resolver responsible for resolution of a given domain
// to a list of CT logs.
type CTResolver struct {
	Client        *http.Client
	cachedDomains map[string]bool
	ctSince       string // YYYY-MM-DD
	ctExclude     string // e.g. "expired"
}

// NewCTResolver creates a new CTResolver with sensible defaults.
// since is the minimum log date in YYYY-MM-DD format; exclude is the crt.sh exclude parameter (e.g. "expired").
func NewCTResolver(timeout time.Duration, since, exclude string) *CTResolver {
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

func (r *CTResolver) fetchLogs(domain string) (logs []CTAggregatedLog) {
	url := fmt.Sprintf("%s/?match=LIKE&exclude=%s&CN=%s&output=json", CTApiUrl, r.ctExclude, domain)
	res, err := r.Client.Get(url)
	if err != nil {
		LogErr("%s: %s -> %s", TypeCT, domain, err.Error())
		return logs
	}
	defer res.Body.Close()

	var rawBody []byte
	if rawBody, err = io.ReadAll(res.Body); err != nil {
		LogErr("%s: %s -> %s", TypeCT, domain, err.Error())
		return logs
	}

	rawLogs := make([]CTLog, 0)
	if err = json.Unmarshal(rawBody, &rawLogs); err != nil {
		LogErr("%s: %s -> %s", TypeCT, domain, err.Error())
		return logs
	}

	// Aggregate the Logs by CN (domain), while keeping min/max log time.
	aggregatedLogs := make(map[string]*CTAggregatedLog)
	for _, log := range rawLogs {

		// Skip logs outside of our time scope.
		// @todo: maybe use a DB to query CRT.sh and filter the logs directly
		if log.LoggedAt < r.ctSince {
			continue
		}

		// Save every unique name record and keep the last known record.
		if aggregatedLogs[log.NameValue] == nil {
			aggregatedLogs[log.NameValue] = &CTAggregatedLog{
				CTLog:     log,
				FirstSeen: log.LoggedAt,
				LastSeen:  log.LoggedAt,
			}
		} else {
			// Update log.
			if aggregatedLogs[log.NameValue].FirstSeen > log.LoggedAt {
				aggregatedLogs[log.NameValue].FirstSeen = log.LoggedAt
			}
			if aggregatedLogs[log.NameValue].LastSeen < log.LoggedAt {
				aggregatedLogs[log.NameValue].LastSeen = log.LoggedAt
				aggregatedLogs[log.NameValue].CTLog = log
			}
		}
	}

	for _, log := range aggregatedLogs {
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
