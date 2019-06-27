package udig

import (
	"crypto/x509"
	"github.com/domainr/whois"
	"github.com/miekg/dns"
	"net/http"
	"time"
)

/////////////////////////////////////////
// COMMON
/////////////////////////////////////////

const (
	// DefaultTimeout is a default timeout used in all network clients.
	DefaultTimeout = 5 * time.Second
)

// ResolutionType is an enumeration type for resolutions types.
type ResolutionType string

const (
	// TypeDNS is a type of all DNS resolutions.
	TypeDNS ResolutionType = "DNS"

	// TypeWHOIS is a type of all WHOIS resolutions.
	TypeWHOIS ResolutionType = "WHOIS"

	// TypeTLS is a type of all TLS resolutions.
	TypeTLS ResolutionType = "TLS"
)

// Udig is a high-level facade for domain resolution which:
// 	1. delegates work to specific resolvers
//  2. deals with domain crawling
//  3. caches intermediate results and summarizes the outputs
type Udig interface {
	Resolve(domain string) []Resolution
}

// Resolver is an API contract for all Resolvers (i.e. modules that resolve domains).
type Resolver interface {
	Type() ResolutionType             // Returns a type of resolution that this resolver supports.
	Resolve(domain string) Resolution // Resolves a given domain.
}

// Resolution is an API contract for all Resolutions (i.e. results).
type Resolution interface {
	Type() ResolutionType // Returns a type of this resolution.
	Query() string        // Returns the queried domain.
	Domains() []string    // Returns a list of domains discovered in this resolution.
}

// ResolutionBase is a shared implementation for all Resolutions (i.e. results).
type ResolutionBase struct {
	Resolution `json:"-"`
	query      string
}

// Query getter.
func (res *ResolutionBase) Query() string {
	return res.query
}

/////////////////////////////////////////
// DNS
/////////////////////////////////////////

// DNSResolver is a Resolver which is able to resolve a domain
// to a bunch of the most interesting DNS records.
//
// You can configure which query types are actually used
// and you can also supply a custom name server.
// If you don't a name server for each domain is discovered
// using NS record query, falling back to a local NS
// (e.g. the one in /etc/resolv.conf).
type DNSResolver struct {
	Resolver
	QueryTypes      []uint16
	NameServer      string
	Client          *dns.Client
	nameServerCache map[string]string
	resolvedDomains map[string]bool
}

// DNSResolution is a DNS multi-query resolution yielding many DNS records
// in a form of query-answer pairs.
type DNSResolution struct {
	*ResolutionBase
	Records    []DNSRecordPair
	nameServer string
}

// DNSRecordPair is a pair of DNS record type used in the query
// and a corresponding record found in the answer.
type DNSRecordPair struct {
	QueryType uint16
	Record    dns.RR
}

/////////////////////////////////////////
// WHOIS
/////////////////////////////////////////

// WhoisResolver is a Resolver responsible for resolution of a given
// domain to a list of WHOIS contacts.
type WhoisResolver struct {
	Resolver
	Client *whois.Client
}

// WhoisResolution is a WHOIS query resolution yielding many contacts.
type WhoisResolution struct {
	*ResolutionBase
	Contacts []WhoisContact
}

// WhoisContact is just a set of key/value pairs.
//
// Note that all map keys are lowercase intentionally.
// For a default list of supported properties refer to `udig.SupportedWhoisProperties`.
type WhoisContact map[string]string

/////////////////////////////////////////
// TLS
/////////////////////////////////////////

// TLSResolver is a Resolver responsible for resolution of a given domain
// to a list of TLS certificates.
type TLSResolver struct {
	Resolver
	Client *http.Client
}

// TLSResolution is a TLS handshake resolution, which yields a certificate chain.
type TLSResolution struct {
	*ResolutionBase
	Certificates []x509.Certificate
}
