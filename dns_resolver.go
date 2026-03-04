package udig

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	// DefaultDNSQueryTypes is a list of default DNS RR types that we query.
	// Excluded: OPT (EDNS0 pseudo-RR, not a question type), TKEY/TSIG
	// (protocol authentication mechanisms), AXFR/IXFR (zone transfer
	// operations requiring special handling), MAILB (obsolete meta-type).
	DefaultDNSQueryTypes = [...]uint16{
		dns.TypeA,
		dns.TypeNS,
		dns.TypeSOA,
		dns.TypeMX,
		dns.TypeTXT,
		dns.TypeCAA,
		dns.TypeSIG,
		dns.TypeKEY,
		dns.TypeAAAA,
		dns.TypeSRV,
		dns.TypeCERT,
		dns.TypeDNAME,
		dns.TypeKX,
		dns.TypeDS,
		dns.TypeRRSIG,
		dns.TypeNSEC,
		dns.TypeDNSKEY,
		dns.TypeNSEC3,
		dns.TypeNSEC3PARAM,
		dns.TypeANY,
	}

	localNameServer  string     // A name server resolved using resolv.conf.
	queryOneCallback = queryOne // Callback reference which performs the actual DNS query (monkey patch).
)

func init() {
	localNameServer = findLocalNameServer()
}

// defaultLocalNameServer is used when /etc/resolv.conf is missing or has no servers.
const defaultLocalNameServer = "127.0.0.1:53"

func findLocalNameServer() string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || config == nil {
		LogErr("Cannot read resolv.conf: %v -> using %s", err, defaultLocalNameServer)
		return defaultLocalNameServer
	}
	if len(config.Servers) == 0 {
		LogErr("No name server in resolv.conf -> using %s", defaultLocalNameServer)
		return defaultLocalNameServer
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

	case dns.TypeCNAME:
		domains = append(domains, (record).(*dns.CNAME).Target)

	case dns.TypeSOA:
		domains = append(domains, (record).(*dns.SOA).Mbox)

	case dns.TypeMX:
		domains = append(domains, (record).(*dns.MX).Mx)

	case dns.TypeTXT:
		domains = DissectDomainsFromStrings((record).(*dns.TXT).Txt)

	case dns.TypeRRSIG:
		domains = append(domains, (record).(*dns.RRSIG).SignerName)

	case dns.TypeNSEC:
		domains = append(domains, (record).(*dns.NSEC).NextDomain)

	case dns.TypeKX:
		domains = append(domains, (record).(*dns.KX).Exchanger)

	case dns.TypeCAA:
		caa := (record).(*dns.CAA)
		if strings.EqualFold(caa.Tag, "iodef") {
			domains = append(domains, DissectDomainsFromString(caa.Value)...)
		}
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

	case dns.TypeAAAA:
		ips = append(ips, (record).(*dns.AAAA).AAAA.String())

	case dns.TypeTXT:
		// For SPF typically.
		ips = DissectIpsFromStrings((record).(*dns.TXT).Txt)
	}

	return ips
}

/////////////////////////////////////////
// DNS RESOLVER
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
	QueryTypes      []uint16          // DNS RR types to query (e.g. A, AAAA, MX, TXT, ...)
	NameServer      string            // custom name server; empty = auto-discover via NS lookup
	Client          *dns.Client       // DNS client used for all queries
	nameServerCache map[string]string // domain -> resolved NS address cache
	resolvedDomains map[string]bool   // dedup set of already-resolved domains
}

// NewDNSResolver creates a new DNS resolver instance pre-populated
// with sensible defaults.
func NewDNSResolver(timeout time.Duration) *DNSResolver {
	return &DNSResolver{
		QueryTypes:      DefaultDNSQueryTypes[:],
		Client:          &dns.Client{ReadTimeout: timeout},
		nameServerCache: map[string]string{},
		resolvedDomains: map[string]bool{},
	}
}

// Type returns "DNS".
func (r *DNSResolver) Type() ResolutionType {
	return TypeDNS
}

// ResolveDomain attempts to resolve a given domain for every DNS record
// type defined in resolver.QueryTypes using either a user-supplied
// name-server or dynamically resolved one for this domain.
// Returns one Resolution per DNS record found (denormalized).
func (r *DNSResolver) ResolveDomain(domain string) []Resolution {
	nameServer := r.findNameServerFor(domain)
	LogDebug("%s: Using NS %s for domain %s.", TypeDNS, nameServer, domain)

	recordChannel := make(chan []DNSRecord, 128)
	var wg sync.WaitGroup
	wg.Add(len(r.QueryTypes))

	for _, qType := range r.QueryTypes {
		go func(qType uint16) {
			recordChannel <- r.resolveOne(domain, qType, nameServer)
			wg.Done()
		}(qType)
	}
	wg.Wait()

	var allRecords []DNSRecord
	for len(recordChannel) > 0 {
		allRecords = append(allRecords, <-recordChannel...)
	}

	signed := false
	for _, rec := range allRecords {
		rt := rec.RR.Header().Rrtype
		if rt == dns.TypeDS || rt == dns.TypeDNSKEY {
			signed = true
			break
		}
	}

	var results []Resolution
	for _, rec := range allRecords {
		rec.Signed = signed
		results = append(results, &DNSResolution{
			ResolutionBase: &ResolutionBase{query: domain},
			Record:         rec,
		})
	}

	return results
}

func (r *DNSResolver) resolveOne(domain string, qType uint16, nameServer string) (answers []DNSRecord) {
	msg, err := queryOneCallback(domain, qType, nameServer, r.Client)
	if err != nil {
		LogErr("%s: %s %s -> %s", TypeDNS, dns.TypeToString[qType], domain, err.Error())
		return answers
	}

	for _, rr := range msg.Answer {
		answers = append(answers, DNSRecord{
			RR:        rr,
			QueryType: qType,
		})
	}

	return answers
}

func (r *DNSResolver) findNameServerFor(domain string) string {
	// Use user-supplied NS if available.
	if r.NameServer != "" {
		return r.NameServer
	}

	// Check NS cache.
	if r.nameServerCache[domain] != "" {
		return r.nameServerCache[domain]
	}

	// Use DNS NS lookup.
	nameServer := r.getNameServerFor(domain)

	if nameServer != "" {
		// OK, NS found.
	} else if IsSubdomain(domain) {
		// This is a subdomain -> try the parent.
		LogDebug("%s: No NS found for subdomain %s -> trying parent domain.", TypeDNS, domain)
		nameServer = r.findNameServerFor(ParentDomainOf(domain))
	} else {
		// Fallback to local NS.
		LogErr("%s: Could not resolve NS for domain %s -> falling back to local.", TypeDNS, domain)
		nameServer = localNameServer
	}

	// Cache the result.
	r.nameServerCache[domain] = nameServer

	return nameServer
}

func (r *DNSResolver) getNameServerFor(domain string) string {
	var nsRecord *dns.NS

	// Do a NS query.
	msg, err := queryOneCallback(domain, dns.TypeNS, localNameServer, r.Client)
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
