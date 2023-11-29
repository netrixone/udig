package udig

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
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

func dissectDomainsFromRecord(record dns.RR) (domains []string) {
	switch record.Header().Rrtype {
	case dns.TypeNS:
		domains = append(domains, (record).(*dns.NS).Ns)
		break

	case dns.TypeCNAME:
		domains = append(domains, (record).(*dns.CNAME).Target)
		break

	case dns.TypeSOA:
		domains = append(domains, (record).(*dns.SOA).Mbox)
		break

	case dns.TypeMX:
		domains = append(domains, (record).(*dns.MX).Mx)
		break

	case dns.TypeTXT:
		domains = DissectDomainsFromStrings((record).(*dns.TXT).Txt)
		break

	case dns.TypeRRSIG:
		domains = append(domains, (record).(*dns.RRSIG).SignerName)
		break

	case dns.TypeNSEC:
		domains = append(domains, (record).(*dns.NSEC).NextDomain)
		break

	case dns.TypeKX:
		domains = append(domains, (record).(*dns.KX).Exchanger)
		break
	}

	for i := range domains {
		domains[i] = CleanDomain(domains[i])
	}

	return domains
}

func dissectIPsFromRecord(record dns.RR) (ips []string) {
	switch record.Header().Rrtype {
	case dns.TypeA:
		ips = append(ips, (record).(*dns.A).A.String())
		break

	case dns.TypeAAAA:
		ips = append(ips, (record).(*dns.AAAA).AAAA.String())
		break

	case dns.TypeTXT:
		// For SPF typically.
		ips = DissectIpsFromStrings((record).(*dns.TXT).Txt)
		break
	}

	return ips
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

// ResolveDomain attempts to resolve a given domain for every DNS record
// type defined in resolver.QueryTypes using either a user-supplied
// name-server or dynamically resolved one for this domain.
func (resolver *DNSResolver) ResolveDomain(domain string) Resolution {
	// First find a name server for this domain (if not pre-defined).
	nameServer := resolver.findNameServerFor(domain)
	LogDebug("%s: Using NS %s for domain %s.", TypeDNS, nameServer, domain)

	resolution := &DNSResolution{
		ResolutionBase: &ResolutionBase{query: domain},
		nameServer:     nameServer,
	}

	// Now do a DNS query for each record type (in parallel).
	recordChannel := make(chan []DNSRecordPair, 128)
	var wg sync.WaitGroup
	wg.Add(len(resolver.QueryTypes))

	for _, qType := range resolver.QueryTypes {
		go func(qType uint16) {
			recordChannel <- resolver.resolveOne(domain, qType, nameServer)
			wg.Done()
		}(qType)
	}
	wg.Wait()

	// Collect the records.
	for len(recordChannel) > 0 {
		resolution.Records = append(resolution.Records, <-recordChannel...)
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
			Record:    &DNSRecord{rr},
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
	} else if IsSubdomain(domain) {
		// This is a subdomain -> try the parent.
		LogDebug("%s: No NS found for subdomain %s -> trying parent domain.", TypeDNS, domain)
		nameServer = resolver.findNameServerFor(ParentDomainOf(domain))
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
		domains = append(domains, dissectDomainsFromRecord(answer.Record.RR)...)
	}
	return domains
}

// IPs returns a list of IP addresses discovered in this resolution.
func (res *DNSResolution) IPs() (ips []string) {
	for _, answer := range res.Records {
		ips = append(ips, dissectIPsFromRecord(answer.Record.RR)...)
	}
	return ips
}

/////////////////////////////////////////
// DNS RECORD
/////////////////////////////////////////

func (record *DNSRecord) String() string {
	return fmt.Sprintf("%s %s",
		dns.TypeToString[record.RR.Header().Rrtype],
		strings.Replace(record.RR.String(), record.RR.Header().String(), "", 1),
	)
}
