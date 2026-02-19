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

// NewCTResolver creates a new CTResolver with sensible defaults.
// since is the minimum log date in YYYY-MM-DD format; exclude is the crt.sh exclude parameter (e.g. "expired").
func NewCTResolver(timeout time.Duration, since, exclude string) *CTResolver {
	if since == "" {
		since = time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	}
	if exclude == "" {
		exclude = "expired" // default: exclude expired logs
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
		cachedResults: make(map[string]*CTResolution),
		ctSince:       since,
		ctExclude:     exclude,
	}
}

// Type returns "CT".
func (r *CTResolver) Type() ResolutionType {
	return TypeCT
}

// ResolveDomain resolves a given domain to a list of TLS certificates.
func (r *CTResolver) ResolveDomain(domain string) Resolution {
	resolution := &CTResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	if cached := r.cacheLookup(domain); cached != nil {
		// Ignore, otherwise the output would burn without adding no/little value.
		return resolution
	}

	resolution.Logs = r.fetchLogs(domain)
	r.cachedResults[domain] = resolution

	return resolution
}

func (r *CTResolver) cacheLookup(domain string) *CTResolution {
	resolution := r.cachedResults[domain]
	if resolution != nil {
		return resolution
	}

	// Try parent domain as well (unless it is a 2nd order domain).
	for ; domain != ""; domain = ParentDomainOf(domain) {
		resolution = r.cachedResults[domain]
		if resolution != nil {
			return resolution
		}
	}

	return nil
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
		logs = append(logs, *log)
	}

	return logs
}

/////////////////////////////////////////
// CT RESOLUTION
/////////////////////////////////////////

// Type returns "CT".
func (r *CTResolution) Type() ResolutionType {
	return TypeCT
}

// Domains returns a list of domains discovered in records within this Resolution.
func (r *CTResolution) Domains() (domains []string) {
	seen := make(map[string]bool, 0)

	for _, log := range r.Logs {
		logDomains := log.ExtractDomains()
		for _, domain := range logDomains {
			if !seen[domain] {
				domains = append(domains, domain)
				seen[domain] = true
			}
		}
	}

	return domains
}

/////////////////////////////////////////
// CT AGGREGATED LOG
/////////////////////////////////////////

func (l *CTAggregatedLog) String() string {
	return fmt.Sprintf(
		"name: %s, first_seen: %s, last_seen: %s, not_before: %s, not_after: %s, issuer: %s",
		l.NameValue, l.FirstSeen, l.LastSeen, l.NotBefore, l.NotAfter, l.IssuerName,
	)
}

/////////////////////////////////////////
// CT LOG
/////////////////////////////////////////

func (l *CTLog) ExtractDomains() (domains []string) {
	domains = append(domains, DissectDomainsFromString(l.NameValue)...)
	return domains
}

func (l *CTLog) String() string {
	return fmt.Sprintf(
		"name: %s, logged_at: %s, not_before: %s, not_after: %s, issuer: %s",
		l.NameValue, l.LoggedAt, l.NotBefore, l.NotAfter, l.IssuerName,
	)
}
