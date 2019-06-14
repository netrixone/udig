package udig

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
)

var (
	// DefaultDNSQueryTypes is a list of default DNS RR types that we query.
	DefaultDNSQueryTypes = [...]uint16{
		dns.TypeA,
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
		rcodeStr := dns.RcodeToString[res.Rcode]
		return nil, errors.New(rcodeStr)
	}

	return res, nil
}

func isSubdomain(domain string) bool {
	return dns.CountLabel(domain) >= 3
}

func parentDomainOf(domain string) string {
	labels := strings.Split(domain, ".")
	if len(labels) <= 2 {
		// We don't want a TLD.
		return ""
	}
	return strings.Join(labels[1:], ".")
}

func dissectDomain(record dns.RR) (domain string) {
	switch record.Header().Rrtype {
	case dns.TypeCNAME:
		domain = (record).(*dns.CNAME).Target
		break
	case dns.TypeMX:
		domain = (record).(*dns.MX).Mx
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
		if strings.HasSuffix(domain, ".") {
			domain = strings.TrimSuffix(domain, ".")
		}
		if strings.HasPrefix(domain, "*.") {
			domain = strings.TrimPrefix(domain, "*.")
		}

		LogDebug("%s: Found related domain for %s -> %s using %s.", TypeDNS, record.Header().Name, domain, dns.TypeToString[record.Header().Rrtype])
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

// Resolve attempts to resolve a given domain for every DNS record
// type defined in resolver.QueryTypes using either a user-supplied
// name-server or dynamically resolved one for this domain.
// Also attempts to resolve all related domains.
func (resolver *DNSResolver) Resolve(domain string) []DNSResolution {
	var resolutions []DNSResolution

	// Make sure we don't repeat ourselves.
	if resolver.isProcessed(domain) {
		return resolutions
	}
	resolver.addProcessed(domain)

	// First find a name server for this domain (if not pre-defined).
	nameServer := resolver.findNameServerFor(domain)
	LogDebug("%s: Using NS %s for domain %s.", TypeDNS, nameServer, domain)

	// Now do a DNS query for each record type, collecting the results.
	for _, qType := range resolver.QueryTypes {
		resolution := resolver.resolveOne(domain, qType, nameServer)
		resolutions = append(resolutions, *resolution)

		// Attempt to harvest and resolve related domains.
		relResolutions := resolver.resolveRelated(resolution)
		resolutions = append(resolutions, relResolutions...)
	}

	return resolutions
}

func (resolver *DNSResolver) resolveOne(domain string, qType uint16, nameServer string) *DNSResolution {
	resolution := &DNSResolution{
		Query: DNSQuery{Domain: domain, Type: dns.TypeToString[qType], NameServer: nameServer},
	}

	msg, err := queryOneCallback(domain, qType, nameServer, resolver.Client)
	if err != nil {
		LogErr("%s: %s %s -> %s", TypeDNS, resolution.Query.Type, domain, err.Error())
		return resolution
	}

	for _, rr := range msg.Answer {
		resolution.Answers = append(resolution.Answers, rr)
	}

	return resolution
}

func (resolver *DNSResolver) resolveRelated(resolution *DNSResolution) (resolutions []DNSResolution) {
	relatedDomains := resolution.dissectDomains()

	for _, relDomain := range relatedDomains {
		// Have we met this domain before?
		if resolver.isProcessed(relDomain) {
			// Skip.
			continue
		}

		relResolutions := resolver.Resolve(relDomain)
		resolutions = append(resolutions, relResolutions...)
	}

	return resolutions
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

func (resolver *DNSResolver) isProcessed(domain string) bool {
	return resolver.resolvedDomains[domain]
}

func (resolver *DNSResolver) addProcessed(domain string) {
	resolver.resolvedDomains[domain] = true
}

/////////////////////////////////////////
// DNS RESOLUTION
/////////////////////////////////////////

func (res *DNSResolution) dissectDomains() (domains []string) {
	for _, answer := range res.Answers {
		if domain := dissectDomain(answer); domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}
