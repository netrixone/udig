package udig

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
)

var (
	DefaultDnsQueryTypes = [...]uint16{ // List of default DNS RR types that we query.
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
	if len(labels) == 1 {
		return ""
	}
	return strings.Join(labels[1:], ".")
}

/////////////////////////////////////////
// DNS RESOLVER
/////////////////////////////////////////

func NewDnsResolver() *DnsResolver {
	return &DnsResolver{
		QueryTypes: DefaultDnsQueryTypes[:],
		Client:     &dns.Client{ReadTimeout: DefaultTimeout},
	}
}

func (resolver *DnsResolver) Resolve(domain string) []DnsResolution {
	var resolutions []DnsResolution

	// First find a name server for this domain (if not pre-defined).
	if resolver.NameServer == "" {
		resolver.NameServer = resolver.findNameServerFor(domain)
		defer resolver.resetNameServer()
	}
	LogDebug("%s: Using NS %s for domain %s.", TypeDNS, resolver.NameServer, domain)

	// Now do a DNS query for each record type, collecting the results.
	for _, qType := range resolver.QueryTypes {
		resolution := resolver.resolveOne(domain, qType)
		resolutions = append(resolutions, *resolution)

		// If this is just a CNAME record -> recurse with resolution.
		if resolution.resolvesToCname() {
			cnameRR := resolution.Answers[0].(*dns.CNAME)
			resolution = resolver.resolveOne(cnameRR.Target, qType)
			resolutions = append(resolutions, *resolution)
		}
	}

	return resolutions
}

func (resolver *DnsResolver) resolveOne(domain string, qType uint16) *DnsResolution {
	resolution := &DnsResolution{
		Query: DnsQuery{Domain: domain, Type: dns.TypeToString[qType]},
	}

	msg, err := queryOneCallback(domain, qType, resolver.NameServer, resolver.Client)
	if err != nil {
		LogErr("%s: %s %s -> %s", TypeDNS, resolution.Query.Type, domain, err.Error())
		return resolution
	}

	resolution.Query.NameServer = resolver.NameServer
	for _, rr := range msg.Answer {
		resolution.Answers = append(resolution.Answers, rr)
	}

	return resolution
}

func (resolver *DnsResolver) findNameServerFor(domain string) string {
	nameServer := resolver.getNameServerFor(domain)

	if nameServer != "" {
		return nameServer
	} else if isSubdomain(domain) {
		// This is a subdomain -> try the parent.
		return resolver.findNameServerFor(parentDomainOf(domain))
	} else {
		// Fallback to local NS.
		LogErr("%s: Could not resolve NS for domain %s -> falling back to local.", TypeDNS, domain)
		nameServer = localNameServer
	}

	return nameServer
}

func (resolver *DnsResolver) getNameServerFor(domain string) string {
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
		nameServerFqdn := msg.Answer[0].(*dns.NS).Ns
		return nameServerFqdn[:len(nameServerFqdn)-1] + ":53"
	} else {
		// No record found.
		return ""
	}
}

func (resolver *DnsResolver) resetNameServer() {
	resolver.NameServer = ""
}

/////////////////////////////////////////
// DNS RESOLUTION
/////////////////////////////////////////

func (res *DnsResolution) resolvesToCname() bool {
	return len(res.Answers) != 0 && res.Answers[0].Header().Rrtype == dns.TypeCNAME
}
