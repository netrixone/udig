package udig

import (
	"context"
	"time"
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

	// TypeDMARC is a type of all DMARC resolutions.
	TypeDMARC ResolutionType = "DMARC"

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

	// TypeRDAP is a type of all RDAP (Registration Data Access Protocol) resolutions.
	TypeRDAP ResolutionType = "RDAP"

	// TypeDNSBL is a type of all DNSBL (DNS Blocklist) resolutions.
	TypeDNSBL ResolutionType = "DNSBL"

	// TypeTor is a type of all Tor exit-node resolutions.
	TypeTor ResolutionType = "TOR"
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
// Each returned Resolution carries exactly one result (1 type, 1 query, 1 value).
type DomainResolver interface {
	ResolveDomain(domain string) []Resolution
}

// IPResolver is an API contract for all Resolver modules that resolve IPs.
// Each returned Resolution carries exactly one result (1 type, 1 query, 1 value).
type IPResolver interface {
	ResolveIP(ip string) []Resolution
}

// Resolution is an API contract for all Resolutions (i.e. results).
type Resolution interface {
	Type() ResolutionType // Returns a type of this resolution.
	Query() string        // Returns the queried domain or IP.
	Domains() []string    // Returns a list of domains discovered in this resolution.
	IPs() []string        // Returns a list of IP addresses discovered in this resolution.
}

// ResolutionBase provides default implementations for the Resolution interface.
// All resolution types embed this to inherit Query(), Domains(), and IPs().
type ResolutionBase struct {
	query string
}

func (r *ResolutionBase) Query() string     { return r.query }
func (r *ResolutionBase) Domains() []string { return nil }
func (r *ResolutionBase) IPs() []string     { return nil }
