package udig

import (
	"fmt"
	"time"
)

/////////////////////////////////////////
// CT RESOLUTION
/////////////////////////////////////////

// CTResolution is a single CT log result (denormalized: one log per resolution).
type CTResolution struct {
	*ResolutionBase
	Record CTAggregatedLog
}

// Type returns "CT".
func (r *CTResolution) Type() ResolutionType {
	return TypeCT
}

// Domains returns domains discovered in this single CT log entry.
func (r *CTResolution) Domains() (domains []string) {
	return r.Record.ExtractDomains()
}

/////////////////////////////////////////
// CT AGGREGATED LOG
/////////////////////////////////////////

// CTAggregatedLog is a wrapper of a CT log that is aggregated over all logs
// with the same CN in time. NotAfterTime and Active are set when logs are fetched.
type CTAggregatedLog struct {
	CTLog
	FirstSeen    string    // earliest log entry timestamp for this CN
	LastSeen     string    // latest log entry timestamp for this CN
	NotAfterTime time.Time // parsed from NotAfter
	Active       bool      // true if certificate is still valid (NotAfterTime >= now)
}

func (l *CTAggregatedLog) String() string {
	return fmt.Sprintf(
		"name: %s, first_seen: %s, last_seen: %s, not_before: %s, not_after: %s, issuer: %s",
		l.NameValue, l.FirstSeen, l.LastSeen, l.NotBefore, l.NotAfter, l.IssuerName,
	)
}

/////////////////////////////////////////
// CT LOG
/////////////////////////////////////////

// CTLog is a wrapper for attributes of interest that appear in the CT log.
// The json mapping comes from crt.sh API schema.
type CTLog struct {
	Id         int64  `json:"id"`
	IssuerName string `json:"issuer_name"`
	NameValue  string `json:"name_value"`
	LoggedAt   string `json:"entry_timestamp"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

func (l *CTLog) ExtractDomains() (domains []string) {
	domains = append(domains, DissectDomainsFromString(l.NameValue)...)
	return domains
}

func (l CTLog) String() string {
	return fmt.Sprintf(
		"name: %s, logged_at: %s, not_before: %s, not_after: %s, issuer: %s",
		l.NameValue, l.LoggedAt, l.NotBefore, l.NotAfter, l.IssuerName,
	)
}
