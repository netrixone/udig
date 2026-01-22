package udig

import (
	"crypto/tls"
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
var ctSince = time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
var ctExclude = "expired"

// NewCTResolver creates a new CTResolver with sensible defaults.
func NewCTResolver() *CTResolver {
	transport := http.DefaultTransport.(*http.Transport)

	transport.DialContext = (&net.Dialer{
		Timeout:   DefaultTimeout,
		KeepAlive: DefaultTimeout,
	}).DialContext

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.TLSHandshakeTimeout = DefaultTimeout

	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}

	return &CTResolver{
		Client:        client,
		cachedResults: make(map[string]*CTResolution),
	}
}

// Type returns "CT".
func (resolver *CTResolver) Type() ResolutionType {
	return TypeCT
}

// ResolveDomain resolves a given domain to a list of TLS certificates.
func (resolver *CTResolver) ResolveDomain(domain string) Resolution {
	resolution := &CTResolution{
		ResolutionBase: &ResolutionBase{query: domain},
	}

	if cached := resolver.cacheLookup(domain); cached != nil {
		// Ignore, otherwise the output would burn without adding no/little value.
		return resolution
	}

	resolution.Logs = resolver.fetchLogs(domain)
	resolver.cachedResults[domain] = resolution

	return resolution
}

func (resolver *CTResolver) cacheLookup(domain string) *CTResolution {
	resolution := resolver.cachedResults[domain]
	if resolution != nil {
		return resolution
	}

	// Try parent domain as well (unless it is a 2nd order domain).
	for ; domain != ""; domain = ParentDomainOf(domain) {
		resolution = resolver.cachedResults[domain]
		if resolution != nil {
			return resolution
		}
	}

	return nil
}

func (resolver *CTResolver) fetchLogs(domain string) (logs []CTAggregatedLog) {
	url := fmt.Sprintf("%s/?match=LIKE&exclude=%s&CN=%s&output=json", CTApiUrl, ctExclude, domain)
	res, err := resolver.Client.Get(url)
	if err != nil {
		LogErr("%s: %s -> %s", TypeCT, domain, err.Error())
		return logs
	}

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
		if log.LoggedAt < ctSince {
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
func (res *CTResolution) Type() ResolutionType {
	return TypeCT
}

// Domains returns a list of domains discovered in records within this Resolution.
func (res *CTResolution) Domains() (domains []string) {
	seen := make(map[string]bool, 0)

	for _, log := range res.Logs {
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

func (log *CTAggregatedLog) String() string {
	return fmt.Sprintf(
		"name: %s, first_seen: %s, last_seen: %s, not_before: %s, not_after: %s, issuer: %s",
		log.NameValue, log.FirstSeen, log.LastSeen, log.NotBefore, log.NotAfter, log.IssuerName,
	)
}

/////////////////////////////////////////
// CT LOG
/////////////////////////////////////////

func (log *CTLog) ExtractDomains() (domains []string) {
	domains = append(domains, DissectDomainsFromString(log.NameValue)...)
	return domains
}

func (log *CTLog) String() string {
	return fmt.Sprintf(
		"name: %s, logged_at: %s, not_before: %s, not_after: %s, issuer: %s",
		log.NameValue, log.LoggedAt, log.NotBefore, log.NotAfter, log.IssuerName,
	)
}
