package udig

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
)

var (
	// DefaultDNSQueryTypes is a list of default DNS RR types that we query.
	DefaultDNSQueryTypes = [...]uint16{
		dns.TypeA,
		dns.TypeNS,
		dns.TypeSOA,
		dns.TypeMX,
		dns.TypeTXT,
		dns.TypeSIG,
		dns.TypeKEY,
		dns.TypeAAAA,
		dns.TypeSRV,
		dns.TypeCERT,
		dns.TypeDNAME,
		dns.TypeOPT,
		dns.TypeKX,
		dns.TypeDS,
		dns.TypeRRSIG,
		dns.TypeNSEC,
		dns.TypeDNSKEY,
		dns.TypeNSEC3,
		dns.TypeNSEC3PARAM,
		dns.TypeTKEY,
		dns.TypeTSIG,
		dns.TypeIXFR,
		dns.TypeAXFR,
		dns.TypeMAILB,
		dns.TypeANY,
	}

	localNameServer  string     // A name server resolved using resolv.conf.
	queryOneCallback = queryOne // Callback reference which performs the actual DNS query (monkey patch).
)

func init() {
	localNameServer = findLocalNameServer()
}

func findLocalNameServer() string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || config == nil {
		LogPanic("Cannot initialize the local resolver: %s", err)
	} else if len(config.Servers) == 0 {
		LogPanic("No local name server found")
	}
	return config.Servers[0] + ":53"
}

func queryOne(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), qType)

	res, _, err := client.Exchange(msg, nameServer)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && ne.Timeout() {
			return nil, fmt.Errorf("timeout")
		} else if _, ok := err.(*net.OpError); ok {
			return nil, fmt.Errorf("network error")
		}
		return nil, err
	} else if res.Rcode != dns.RcodeSuccess {
		// If the rCode wasn't successful, return an error with the rCode as the string.
		return nil, errors.New(dns.RcodeToString[res.Rcode])
	}

	return res, nil
}

// @todo: support multiple results here (e.g. SOA, TXT)
func dissectDomainFromRecord(record dns.RR) (domain string) {
	switch record.Header().Rrtype {
	case dns.TypeNS:
		domain = (record).(*dns.NS).Ns
		break

	case dns.TypeCNAME:
		domain = (record).(*dns.CNAME).Target
		break

	case dns.TypeSOA:
		domain = (record).(*dns.SOA).Mbox
		break

	case dns.TypeMX:
		domain = (record).(*dns.MX).Mx
		break

	case dns.TypeTXT:
		// @todo: scrape IP from SPF
		domains := dissectDomainsFromStrings((record).(*dns.TXT).Txt)
		if len(domains) > 0 {
			domain = domains[0]
		}
		break

	case dns.TypeRRSIG:
		domain = (record).(*dns.RRSIG).SignerName
		break

	case dns.TypeNSEC:
		domain = (record).(*dns.NSEC).NextDomain
		break

	case dns.TypeKX:
		domain = (record).(*dns.KX).Exchanger
		break
	}

	if domain != "" {
		// Clean this.
		domain = cleanDomain(domain)
	}

	return domain
}

/////////////////////////////////////////
// DNS RESOLVER
/////////////////////////////////////////

// NewDNSResolver creates a new DNS resolver instance pre-populated
// with sensible defaults.
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		QueryTypes:      DefaultDNSQueryTypes[:],
		Client:          &dns.Client{ReadTimeout: DefaultTimeout},
		nameServerCache: map[string]string{},
		resolvedDomains: map[string]bool{},
	}
}

// Type returns "DNS".
func (resolver *DNSResolver) Type() ResolutionType {
	return TypeDNS
}

// Resolve attempts to resolve a given domain for every DNS record
// type defined in resolver.QueryTypes using either a user-supplied
// name-server or dynamically resolved one for this domain.
func (resolver *DNSResolver) Resolve(domain string) Resolution {
	// First find a name server for this domain (if not pre-defined).
	nameServer := resolver.findNameServerFor(domain)
	LogDebug("%s: Using NS %s for domain %s.", TypeDNS, nameServer, domain)

	resolution := &DNSResolution{
		ResolutionBase: &ResolutionBase{query: domain},
		nameServer:     nameServer,
	}

	// Now do a DNS query for each record type, collecting the results.
	for _, qType := range resolver.QueryTypes {
		answers := resolver.resolveOne(domain, qType, nameServer)
		resolution.Records = append(resolution.Records, answers...)
	}

	return resolution
}

func (resolver *DNSResolver) resolveOne(domain string, qType uint16, nameServer string) (answers []DNSRecordPair) {
	msg, err := queryOneCallback(domain, qType, nameServer, resolver.Client)
	if err != nil {
		LogErr("%s: %s %s -> %s", TypeDNS, dns.TypeToString[qType], domain, err.Error())
		return answers
	}

	for _, rr := range msg.Answer {
		answers = append(answers, DNSRecordPair{
			QueryType: qType,
			Record:    rr,
		})
	}

	return answers
}

func (resolver *DNSResolver) findNameServerFor(domain string) string {
	// Use user-supplied NS if available.
	if resolver.NameServer != "" {
		return resolver.NameServer
	}

	// Check NS cache.
	if resolver.nameServerCache[domain] != "" {
		return resolver.nameServerCache[domain]
	}

	// Use DNS NS lookup.
	nameServer := resolver.getNameServerFor(domain)

	if nameServer != "" {
		// OK, NS found.
	} else if isSubdomain(domain) {
		// This is a subdomain -> try the parent.
		LogDebug("%s: No NS found for subdomain %s -> trying parent domain.", TypeDNS, domain)
		nameServer = resolver.findNameServerFor(parentDomainOf(domain))
	} else {
		// Fallback to local NS.
		LogErr("%s: Could not resolve NS for domain %s -> falling back to local.", TypeDNS, domain)
		nameServer = localNameServer
	}

	// Cache the result.
	resolver.nameServerCache[domain] = nameServer

	return nameServer
}

func (resolver *DNSResolver) getNameServerFor(domain string) string {
	var nsRecord *dns.NS

	// Do a NS query.
	msg, err := queryOneCallback(domain, dns.TypeNS, localNameServer, resolver.Client)
	if err != nil {
		LogErr("%s: %s %s -> %s", TypeDNS, "NS", domain, err.Error())
	} else {
		// Try to find a NS record.
		for _, record := range msg.Answer {
			if record.Header().Rrtype == dns.TypeNS {
				nsRecord = record.(*dns.NS)
				break
			}
		}
	}

	if nsRecord != nil {
		// NS record found -> take the NS name.
		nameServerFqdn := nsRecord.Ns
		return nameServerFqdn[:len(nameServerFqdn)-1] + ":53"
	}

	// No record found.
	return ""
}

/////////////////////////////////////////
// DNS RESOLUTION
/////////////////////////////////////////

// Type returns "DNS".
func (res *DNSResolution) Type() ResolutionType {
	return TypeDNS
}

// Domains returns a list of domains discovered in records within this Resolution.
func (res *DNSResolution) Domains() (domains []string) {
	for _, answer := range res.Records {
		if domain := dissectDomainFromRecord(answer.Record); domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}
