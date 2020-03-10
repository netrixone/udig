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
	DefaultTimeout = 3 * time.Second
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

	// TypeHTTP is a type of all HTTP resolutions.
	TypeHTTP ResolutionType = "HTTP"

	// TypeBGP is a type of all BGP resolutions.
	TypeBGP ResolutionType = "BGP"

	// TypeGEO is a type of all GeoIP resolutions.
	TypeGEO ResolutionType = "GEO"
)

// Udig is a high-level facade for domain resolution which:
// 	1. delegates work to specific resolvers
//  2. deals with domain crawling
//  3. caches intermediate results and summarizes the outputs
type Udig interface {
	Resolve(domain string) []Resolution
	AddDomainResolver(resolver DomainResolver)
	AddIPResolver(resolver IPResolver)
}

// DomainResolver is an API contract for all Resolver modules that resolve domains.
// Discovered domains that relate to the original query are recursively resolved.
type DomainResolver interface {
	ResolveDomain(domain string) Resolution // Resolves a given domain.
}

// IPResolver is an API contract for all Resolver modules that resolve IPs.
type IPResolver interface {
	ResolveIP(ip string) Resolution // Resolves a given IP.
}

// Resolution is an API contract for all Resolutions (i.e. results).
type Resolution interface {
	Type() ResolutionType // Returns a type of this resolution.
	Query() string        // Returns the queried domain or IP.
	Domains() []string    // Returns a list of domains discovered in this resolution.
	IPs() []string        // Returns a list of IP addresses discovered in this resolution.
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

// Domains returns a list of domains discovered in this resolution.
func (res *ResolutionBase) Domains() (domains []string) {
	// Not supported by default.
	return domains
}

// IPs returns a list of IP addresses discovered in this resolution.
func (res *ResolutionBase) IPs() (ips []string) {
	// Not supported by default.
	return ips
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
	DomainResolver
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
	Record    *DNSRecord
}

// DNSRecord is a wrapper for the actual DNS resource record.
type DNSRecord struct {
	dns.RR
}

/////////////////////////////////////////
// WHOIS
/////////////////////////////////////////

// WhoisResolver is a Resolver responsible for resolution of a given
// domain to a list of WHOIS contacts.
type WhoisResolver struct {
	DomainResolver
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
	DomainResolver
	Client *http.Client
}

// TLSResolution is a TLS handshake resolution, which yields a certificate chain.
type TLSResolution struct {
	*ResolutionBase
	Certificates []TLSCertificate
}

// TLSCertificate is a wrapper for the actual x509.Certificate.
type TLSCertificate struct {
	x509.Certificate
}

/////////////////////////////////////////
// HTTP
/////////////////////////////////////////

// HTTPResolver is a Resolver responsible for resolution of a given domain
// to a list of corresponding HTTP headers.
type HTTPResolver struct {
	DomainResolver
	Headers []string
	Client  *http.Client
}

// HTTPResolution is a HTTP header resolution yielding many HTTP protocol headers.
type HTTPResolution struct {
	*ResolutionBase
	Headers []HTTPHeader
}

// HTTPHeader is a pair of HTTP header name and corresponding value(s).
type HTTPHeader struct {
	Name  string
	Value []string
}

/////////////////////////////////////////
// BGP
/////////////////////////////////////////

// BGPResolver is a Resolver which is able to resolve an IP
// to AS name and ASN.
//
// Internally this resolver is leveraging a DNS interface of
// IP-to-ASN lookup service by Team Cymru.
type BGPResolver struct {
	IPResolver
	Client        *dns.Client
	cachedResults map[string]*BGPResolution
}

// BGPResolution is a BGP resolution of a given IP yielding AS records.
type BGPResolution struct {
	*ResolutionBase
	Records []ASRecord
}

// ASRecord contains information about an Autonomous System (AS).
type ASRecord struct {
	Name      string
	ASN       uint32
	BGPPrefix string
	Registry  string
	Allocated string
}

/////////////////////////////////////////
// GEO
/////////////////////////////////////////

// GeoResolver is a Resolver which is able to resolve an IP to a geographical location.
type GeoResolver struct {
	IPResolver
	enabled       bool
	cachedResults map[string]*GeoResolution
}

// GeoResolution is a GeoIP resolution of a given IP yielding geographical records.
type GeoResolution struct {
	*ResolutionBase
	Record *GeoRecord
}

// GeoRecord contains information about a geographical location.
type GeoRecord struct {
	CountryCode string
}
