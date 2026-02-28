package udig

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

/////////////////////////////////////////
// DNS RESOLUTION
/////////////////////////////////////////

// DNSResolution is a single DNS record result (denormalized: one record per resolution).
type DNSResolution struct {
	*ResolutionBase
	Record DNSRecord
}

// Type returns "DNS".
func (r *DNSResolution) Type() ResolutionType {
	return TypeDNS
}

// Domains returns domains discovered in this single DNS record.
func (r *DNSResolution) Domains() (domains []string) {
	if r.Record.RR != nil {
		domains = append(domains, dissectDomainsFromRecord(r.Record.RR)...)
	}
	return domains
}

// IPs returns IP addresses discovered in this single DNS record.
func (r *DNSResolution) IPs() (ips []string) {
	if r.Record.RR != nil {
		ips = append(ips, dissectIPsFromRecord(r.Record.RR)...)
	}
	return ips
}

/////////////////////////////////////////
// DNS RECORD
/////////////////////////////////////////

// DNSRecord is a wrapper for the actual DNS resource record.
type DNSRecord struct {
	dns.RR
	QueryType uint16 // DNS query type used to get this record
	Signed    bool   // true when DS or DNSKEY records are present in the zone
}

func (r *DNSRecord) String() string {
	return fmt.Sprintf("%s %s",
		dns.TypeToString[r.RR.Header().Rrtype],
		strings.Replace(r.RR.String(), r.RR.Header().String(), "", 1),
	)
}
