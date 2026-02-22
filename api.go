package udig

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/domainr/whois"
	"github.com/ip2location/ip2location-go"
	"github.com/miekg/dns"
)

/////////////////////////////////////////
// COMMON
/////////////////////////////////////////

const (
	// DefaultTimeout is a default timeout used in all network clients.
	DefaultTimeout = 10 * time.Second
)

// ResolutionType is an enumeration type for resolutions types.
type ResolutionType string

const (
	// TypeDNS is a type of all DNS resolutions.
	TypeDNS ResolutionType = "DNS"

	// TypePTR is a type of all PTR (reverse DNS) resolutions.
	TypePTR ResolutionType = "PTR"

	// TypeWHOIS is a type of all WHOIS resolutions.
	TypeWHOIS ResolutionType = "WHOIS"

	// TypeTLS is a type of all TLS resolutions.
	TypeTLS ResolutionType = "TLS"

	// TypeHTTP is a type of all HTTP resolutions.
	TypeHTTP ResolutionType = "HTTP"

	// TypeCT is a type of all CT resolutions.
	TypeCT ResolutionType = "CT"

	// TypeBGP is a type of all BGP resolutions.
	TypeBGP ResolutionType = "BGP"

	// TypeGEO is a type of all GeoIP resolutions.
	TypeGEO ResolutionType = "GEO"
)

// Udig is a high-level facade for domain resolution which:
//  1. delegates work to specific resolvers
//  2. deals with domain crawling
//  3. caches intermediate results and summarizes the outputs
type Udig interface {
	// Resolve runs resolution and recursive discovery for the given domain;
	// it returns a channel that is closed when done.
	// Context cancellation stops the crawl and closes the channel.
	Resolve(ctx context.Context, domain string) <-chan Resolution
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

// Option is a Udig configuration option pattern.
type Option interface {
	apply(*udigImpl)
}

// WithDebugLogging activates debug logging.
func WithDebugLogging() Option {
	return WithLoggingLevel(LogLevelDebug)
}

// WithLoggingLevel sets the log level used for logging.
func WithLoggingLevel(logLevel int) Option {
	return newUdigOption(func(opt *udigImpl) {
		LogLevel = logLevel
	})
}

// WithStrictMode activates strict mode domain relation (TLD match).
func WithStrictMode() Option {
	return WithDomainRelation(StrictDomainRelation)
}

// WithDomainRelation supplies a given domain relation func for domain heuristic.
func WithDomainRelation(rel DomainRelationFn) Option {
	return newUdigOption(func(udig *udigImpl) {
		if rel != nil {
			udig.isDomainRelated = rel
		}
	})
}

// WithTimeout changes a default timeout to the supplied value.
func WithTimeout(timeout time.Duration) Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.timeout = timeout
	})
}

// WithCTExpired includes expired Certificate Transparency logs in the results (slower).
func WithCTExpired() Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.ctExclude = ""
	})
}

// WithCTSince ignores Certificate Transparency logs older than a given time.
func WithCTSince(t time.Time) Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.ctSince = t.Format("2006-01-02")
	})
}

// WithMaxDepth limits recursive domain discovery depth.
// Depth 0 = seed only, 1 = seed + one hop, etc.
// Default: unlimited (-1).
func WithMaxDepth(n int) Option {
	return newUdigOption(func(udig *udigImpl) {
		udig.maxDepth = n
	})
}

/////////////////////////////////////////
// DNS
/////////////////////////////////////////

// DNSResolver is a Resolver which is able to resolve a domain
// to a bunch of the most interesting DNS records.
//
// You can configure which query types are actually used,
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

// WhoisContact is a wrapper for any item of interest from a WHOIS banner.
type WhoisContact struct {
	RegistryDomainId        string
	Registrant              string
	RegistrantOrganization  string
	RegistrantStateProvince string
	RegistrantCountry       string
	Registrar               string
	RegistrarIanaId         string
	RegistrarWhoisServer    string
	RegistrarUrl            string
	CreationDate            string
	UpdatedDate             string
	Registered              string
	Changed                 string
	Expire                  string
	NSSet                   string
	Contact                 string
	Name                    string
	Address                 string
}

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
// CT
/////////////////////////////////////////

// CTResolver is a Resolver responsible for resolution of a given domain
// to a list of CT logs.
type CTResolver struct {
	DomainResolver
	Client        *http.Client
	cachedResults map[string]*CTResolution
	ctSince       string // YYYY-MM-DD
	ctExclude     string // e.g. "expired"
}

// CTResolution is a certificate transparency project resolution, which yields a CT log.
type CTResolution struct {
	*ResolutionBase
	Logs []CTAggregatedLog
}

// CTAggregatedLog is a wrapper of a CT log that is aggregated over all logs
// with the same CN in time.
type CTAggregatedLog struct {
	CTLog
	FirstSeen string
	LastSeen  string
}

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
	db            *ip2location.DB
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

/////////////////////////////////////////
// PTR (reverse DNS)
/////////////////////////////////////////

// PTRResolver performs reverse DNS (PTR) lookups on discovered IPs.
type PTRResolver struct {
	IPResolver
	Client *dns.Client
}

// PTRResolution is a PTR lookup result yielding hostnames.
type PTRResolution struct {
	*ResolutionBase
	Hostnames []string
}
