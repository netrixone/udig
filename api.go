package udig

import (
	"crypto/x509"
	"fmt"
	"github.com/domainr/whois"
	"github.com/miekg/dns"
	"net/http"
	"strings"
	"time"
)

/////////////////////////////////////////
// COMMON
/////////////////////////////////////////

const (
	DefaultTimeout = 5 * time.Second // Default timeout used in all network clients.
)

// Enum of resolution kinds (types).
type ResolutionType string

const (
	TypeDNS   ResolutionType = "DNS"
	TypeWHOIS ResolutionType = "WHOIS"
	KindTLS   ResolutionType = "TLS"
)

// Base contract for all Resolutions (i.e. results).
type Resolution interface {
	Type() ResolutionType // Returns a type of this resolution.
}

type StringStringMap map[string]string

func (ssMap *StringStringMap) String() string {
	strb := strings.Builder{}
	for key, val := range *ssMap {
		strb.WriteString(fmt.Sprintf("%s -> %s\n", key, val))
	}
	return strb.String()
}

/////////////////////////////////////////
// DNS
/////////////////////////////////////////

// Resolver which is able to resolve a given domain
// to a bunch of the most interesting DNS records.
// You can configure which query types are actually used
// and you can also supply a custom name server.
type DnsResolver struct {
	DnsResolvable
	QueryTypes      []uint16
	NameServer      string
	Client          *dns.Client
	nameServerCache map[string]string
	resolvedDomains map[string]bool
}

type DnsResolvable interface {
	Resolve(domain string) []DnsResolution
}

// Resolution of a single DNS query, naturally each DNS answer
// can contain many records.
type DnsResolution struct {
	Resolution
	Query   DnsQuery
	Answers []dns.RR
}

func (res *DnsResolution) Type() ResolutionType {
	return TypeDNS
}

// DNS query for bookkeeping.
type DnsQuery struct {
	Domain     string
	Type       string
	NameServer string
}

/////////////////////////////////////////
// WHOIS
/////////////////////////////////////////

// Resolver responsible for resolution of a given domain
// to a list of WHOIS contacts.
type WhoisResolver struct {
	WhoisResolvable
	Client *whois.Client
}

type WhoisResolvable interface {
	Resolve(domain string) *WhoisResolution
}

// Resolution of a single WHOIS query, each WHOIS query can correspond
// to many contacts.
type WhoisResolution struct {
	Resolution
	Query   WhoisQuery
	Answers []WhoisContact
}

func (res *WhoisResolution) Type() ResolutionType {
	return TypeWHOIS
}

// WHOIS query for bookkeeping.
type WhoisQuery struct {
	Domain string
}

// Every WHOIS contact is just a set of key/value pairs.
// Note that all map keys are lowercase intentionally.
// For a default list of supported properties refer to `udig.SupportedWhoisProperties`.
type WhoisContact StringStringMap

/////////////////////////////////////////
// TLS
/////////////////////////////////////////

// Resolver responsible for resolution of a given domain
// to a list of TLS certificates.
type TlsResolver struct {
	TlsResolvable
	Client *http.Client
}

type TlsResolvable interface {
	Resolve(domain string) *TlsResolution
}

// Resolution of a single TLS query, which yields a certificate chain.
type TlsResolution struct {
	Resolution
	Query   TlsQuery
	Answers []x509.Certificate
}

func (res *TlsResolution) Type() ResolutionType {
	return KindTLS
}

// TLS query for bookkeeping.
type TlsQuery struct {
	Domain string
}
