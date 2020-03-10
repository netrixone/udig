package udig

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

func Test_When_DnsResolver_Resolve_completes_Then_all_records_are_picked(t *testing.T) {
	// Mock.
	const recordsAvailable = 5

	counterMux := sync.Mutex{}
	invocationCount := 0
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		count := recordsAvailable - invocationCount

		// We need to count with a mutex, because DNS queries are run concurrently.
		counterMux.Lock()
		invocationCount++
		counterMux.Unlock()

		if count > 0 {
			count = 1
		} else {
			count = 0
		}

		msg := mockDNSResponse(dns.TypeA, count)
		return msg, nil
	}

	// Setup.
	resolver := NewDNSResolver()

	// Execute.
	resolution := resolver.ResolveDomain("all.tens.ten").(*DNSResolution)

	// Assert.

	// There should have been 1 invocation per DNS query type and additional 2 spent on NS queries for all.tens.ten + tens.ten.
	assert.Equal(t, len(DefaultDNSQueryTypes)+2, invocationCount)

	// There should be a record for each mocked response.
	assert.Len(t, resolution.Records, recordsAvailable-2)
}

func Test_When_DnsResolver_Resolve_completes_Then_custom_NameServer_was_used(t *testing.T) {
	// Mock.
	var usedNameServer string
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		usedNameServer = nameServer
		return &dns.Msg{}, nil
	}

	// Setup.
	resolver := NewDNSResolver()
	resolver.NameServer = "1.1.1.1"

	// Execute.
	resolver.ResolveDomain("example.com")

	// Assert.
	assert.Equal(t, resolver.NameServer, usedNameServer)
}

func Test_When_queryOne_returns_error_Then_empty_response(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		var msg *dns.Msg
		return msg, errors.New("something silly happened")
	}

	// Setup.
	resolver := NewDNSResolver()
	resolver.QueryTypes = []uint16{dns.TypeA}

	// Execute.
	resolution := resolver.ResolveDomain("example.com")

	// Assert.
	assert.Len(t, resolution.Domains(), 0)
}

func Test_That_findNameServerFor_dissects_NS_records(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		msg := mockDNSResponse(dns.TypeNS, 1)
		rr := &msg.Answer[0]
		(*rr).(*dns.NS).Ns = "ns.example.com."

		return msg, nil
	}

	// Setup.
	resolver := NewDNSResolver()

	// Execute.
	nameServer := resolver.findNameServerFor("example.com")

	// Assert.
	assert.Equal(t, "ns.example.com:53", nameServer)
}

func Test_That_findNameServerFor_caches_results(t *testing.T) {
	// Mock.
	counterMux := sync.Mutex{}
	var invocationCount int
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		// We need to count with a mutex, because DNS queries are run concurrently.
		counterMux.Lock()
		invocationCount++
		counterMux.Unlock()

		msg := mockDNSResponse(dns.TypeNS, 1)
		rr := &msg.Answer[0]
		(*rr).(*dns.NS).Ns = "ns.example.com."

		return msg, nil
	}

	// Setup.
	resolver := NewDNSResolver()

	// Execute.
	_ = resolver.findNameServerFor("example.com")
	_ = resolver.findNameServerFor("example.com")

	// Assert.
	assert.Equal(t, 1, invocationCount)
}

func Test_dissectDomain_By_NS_record(t *testing.T) {
	// Setup.
	record := &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com", Rrtype: dns.TypeNS},
		Ns:  "ns1.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "ns1.example.com", domains[0])
}

func Test_dissectDomain_By_TXT_record(t *testing.T) {
	// Setup.
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com", Rrtype: dns.TypeTXT},
		Txt: []string{
			"foo; bar; baz=1029umadmcald;1205+%!$ 0",
			"foo; bar; baz=related.example.com;afasf=asd123 1",
		},
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "related.example.com", domains[0])
}

func Test_dissectDomain_By_RRSIG_record(t *testing.T) {
	// Setup.
	record := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.com", Rrtype: dns.TypeRRSIG},
		SignerName: "related.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "related.example.com", domains[0])
}

func Test_dissectDomain_By_CNAME_record(t *testing.T) {
	// Setup.
	record := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "example.com", Rrtype: dns.TypeCNAME},
		Target: "related.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "related.example.com", domains[0])
}

func Test_dissectDomain_By_SOA_record(t *testing.T) {
	// Setup.
	record := &dns.SOA{
		Hdr:  dns.RR_Header{Name: "example.com", Rrtype: dns.TypeSOA},
		Mbox: "related.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "related.example.com", domains[0])
}

func Test_dissectDomain_By_MX_record(t *testing.T) {
	// Setup.
	record := &dns.MX{
		Hdr: dns.RR_Header{Name: "example.com", Rrtype: dns.TypeMX},
		Mx:  "related.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "related.example.com", domains[0])
}

func Test_dissectDomain_By_NSEC_record(t *testing.T) {
	// Setup.
	record := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.com", Rrtype: dns.TypeNSEC},
		NextDomain: "*.related.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "related.example.com", domains[0])
}

func Test_dissectDomain_By_KX_record(t *testing.T) {
	// Setup.
	record := &dns.KX{
		Hdr:       dns.RR_Header{Name: "example.com", Rrtype: dns.TypeKX},
		Exchanger: "related.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Equal(t, "related.example.com", domains[0])
}

func Test_dissectDomain_By_unsupported_record(t *testing.T) {
	// Setup.
	record := &dns.MB{
		Hdr: dns.RR_Header{Name: "example.com", Rrtype: dns.TypeMB},
		Mb:  "related.example.com.",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Empty(t, domains)
}

func Test_parentDomainOf_By_subdomain(t *testing.T) {
	// Setup.
	domain := "sub.example.com"

	// Execute.
	parent := parentDomainOf(domain)

	// Assert.
	assert.Equal(t, "example.com", parent)
}

func Test_parentDomainOf_By_domain(t *testing.T) {
	// Setup.
	domain := "example.com"

	// Execute.
	parent := parentDomainOf(domain)

	// Assert.
	assert.Empty(t, parent)
}

func Test_parentDomainOf_By_TLD(t *testing.T) {
	// Setup.
	domain := "com"

	// Execute.
	parent := parentDomainOf(domain)

	// Assert.
	assert.Empty(t, parent)
}

func Test_isDomainRelated_By_same_domain(t *testing.T) {
	// Setup.
	domainA := "example.com"
	domainB := domainA

	// Execute.
	res1 := isDomainRelated(domainA, domainB)
	res2 := isDomainRelated(domainB, domainA)

	// Assert.
	assert.Equal(t, true, res1)
	assert.Equal(t, true, res2)
}

func Test_isDomainRelated_By_subdomain(t *testing.T) {
	// Setup.
	domainA := "example.com"
	domainB := "sub.example.com"

	// Execute.
	res1 := isDomainRelated(domainA, domainB)
	res2 := isDomainRelated(domainB, domainA)

	// Assert.
	assert.Equal(t, true, res1)
	assert.Equal(t, true, res2)
}

func Test_isDomainRelated_By_domain_with_different_TLD(t *testing.T) {
	// Setup.
	domainA := "example.com"
	domainB := "sub.example.net"

	// Execute.
	res1 := isDomainRelated(domainA, domainB)
	res2 := isDomainRelated(domainB, domainA)

	// Assert.
	assert.Equal(t, true, res1)
	assert.Equal(t, true, res2)
}

func Test_isDomainRelated_By_TLDs(t *testing.T) {
	// Setup.
	domainA := "com"
	domainB := "com"

	// Execute.
	res := isDomainRelated(domainA, domainB)

	// Assert.
	assert.Equal(t, false, res)
}

func Test_isDomainRelated_By_invalid_domain(t *testing.T) {
	// Setup.
	domainA := "."
	domainB := "example.com"

	// Execute.
	res1 := isDomainRelated(domainA, domainB)
	res2 := isDomainRelated(domainB, domainA)

	// Assert.
	assert.Equal(t, false, res1)
	assert.Equal(t, false, res2)
}

func mockDNSResponse(qType uint16, numRecords int) *dns.Msg {
	msg := &dns.Msg{}

	for i := 0; i < numRecords; i++ {
		rrNewFun := dns.TypeToRR[qType]
		rr := rrNewFun()
		rr.Header().Rrtype = qType
		msg.Answer = append(msg.Answer, rr)
	}

	return msg
}
