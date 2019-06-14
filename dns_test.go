package udig

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func Test_When_DnsResolver_Resolve_completes_Then_all_records_are_picked(t *testing.T) {
	// Mock.
	const recordsAvailable = 5
	recordsCounter := 0
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		count := recordsAvailable - recordsCounter
		recordsCounter++
		if count > 0 {
			count = 1
		} else {
			count = 0
		}

		msg := mockDnsResponse(dns.TypeA, count)
		return msg, nil
	}

	// Setup.
	resolver := NewDnsResolver()

	// Execute.
	resolutions := resolver.Resolve("all.tens.ten")

	// Assert.
	assert.Len(t, resolutions, len(DefaultDnsQueryTypes))

	// Count resolutions with a record (2 are spent on NS queries for all.tens.ten + tens.ten).
	resolutionsWithRecord := 0
	for _, res := range resolutions {
		if len(res.Answers) != 0 {
			resolutionsWithRecord++
		}
	}
	assert.Equal(t, recordsAvailable-2, resolutionsWithRecord)
}

func Test_When_DnsResolver_Resolve_completes_Then_custom_NameServer_was_used(t *testing.T) {
	// Mock.
	var usedNameServer string
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		usedNameServer = nameServer
		return &dns.Msg{}, nil
	}

	// Setup.
	resolver := NewDnsResolver()
	resolver.NameServer = "1.1.1.1"

	// Execute.
	resolver.Resolve("example.com")

	// Assert.
	assert.Equal(t, resolver.NameServer, usedNameServer)
}

func Test_When_DnsResolver_Resolve_finds_CNAME_Then_it_follows_target(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		var msg *dns.Msg

		LogDebug("QueryOne: %s '%s'.", dns.TypeToString[qType], domain)

		if domain == "all.tens.ten" {
			// This is a CNAME pointer to all.twenties.twenty.
			msg = mockDnsResponse(dns.TypeCNAME, 1)
			rr := &msg.Answer[0]
			(*rr).(*dns.CNAME).Target = "all.twenties.twenty"
		} else if domain == "tens.ten" && qType == dns.TypeNS {
			// This is a NS record.
			msg = mockDnsResponse(dns.TypeNS, 1)
			rr := &msg.Answer[0]
			(*rr).(*dns.NS).Ns = "ns.tens.ten."
		} else if domain == "all.twenties.twenty" && qType == dns.TypeA {
			// This is actually an A record.
			msg = mockDnsResponse(dns.TypeA, 1)
			rr := &msg.Answer[0]
			(*rr).(*dns.A).A = net.IPv4(20, 20, 20, 20)
		} else {
			msg = mockDnsResponse(qType, 0)
		}

		return msg, nil
	}

	// Setup.
	resolver := NewDnsResolver()
	resolver.QueryTypes = []uint16{dns.TypeA}

	// Execute.
	resolutions := resolver.Resolve("all.tens.ten")

	// Assert.
	assert.Len(t, resolutions, 2)

	// The first resolution leads to CNAME(all.twenties.twenty).
	resolution := resolutions[0]
	assert.Len(t, resolution.Answers, 1)
	assert.Equal(t, dns.TypeCNAME, resolution.Answers[0].Header().Rrtype)
	assert.Equal(t, "all.twenties.twenty", (resolution.Answers[0]).(*dns.CNAME).Target)

	// The second resolution leads to A(20.20.20.20).
	resolution = resolutions[1]
	assert.Len(t, resolution.Answers, 1)
	assert.Equal(t, dns.TypeA, resolution.Answers[0].Header().Rrtype)
	assert.Equal(t, "20.20.20.20", (resolution.Answers[0]).(*dns.A).A.String())
}

func Test_When_queryOne_returns_error_Then_empty_response(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		var msg *dns.Msg
		return msg, errors.New("something silly happened")
	}

	// Setup.
	resolver := NewDnsResolver()
	resolver.QueryTypes = []uint16{dns.TypeA}

	// Execute.
	resolutions := resolver.Resolve("example.com")

	// Assert.
	assert.Len(t, resolutions, 1)
	assert.Len(t, resolutions[0].Answers, 0)
}

func Test_That_findNameServerFor_dissects_NS_records(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		msg := mockDnsResponse(dns.TypeNS, 1)
		rr := &msg.Answer[0]
		(*rr).(*dns.NS).Ns = "ns.example.com."

		return msg, nil
	}

	// Setup.
	resolver := NewDnsResolver()

	// Execute.
	nameServer := resolver.findNameServerFor("example.com")

	// Assert.
	assert.Equal(t, "ns.example.com:53", nameServer)
}

func Test_That_findNameServerFor_caches_results(t *testing.T) {
	// Mock.
	var queryOneInvocations int
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		queryOneInvocations++

		msg := mockDnsResponse(dns.TypeNS, 1)
		rr := &msg.Answer[0]
		(*rr).(*dns.NS).Ns = "ns.example.com."

		return msg, nil
	}

	// Setup.
	resolver := NewDnsResolver()

	// Execute.
	_ = resolver.findNameServerFor("example.com")
	_ = resolver.findNameServerFor("example.com")

	// Assert.
	assert.Equal(t, 1, queryOneInvocations)
}

func Test_dissectDomain_By_CNAME_record(t *testing.T) {
	// Setup.
	record := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "example.com", Rrtype: dns.TypeCNAME},
		Target: "related.example.com.",
	}

	// Execute.
	domain := dissectDomain(record)

	// Assert.
	assert.Equal(t, "related.example.com", domain)
}

func Test_dissectDomain_By_MX_record(t *testing.T) {
	// Setup.
	record := &dns.MX{
		Hdr:    dns.RR_Header{Name: "example.com", Rrtype: dns.TypeMX},
		Mx: "related.example.com.",
	}

	// Execute.
	domain := dissectDomain(record)

	// Assert.
	assert.Equal(t, "related.example.com", domain)
}

func Test_dissectDomain_By_NSEC_record(t *testing.T) {
	// Setup.
	record := &dns.NSEC{
		Hdr:    dns.RR_Header{Name: "example.com", Rrtype: dns.TypeNSEC},
		NextDomain: "*.related.example.com.",
	}

	// Execute.
	domain := dissectDomain(record)

	// Assert.
	assert.Equal(t, "related.example.com", domain)
}

func Test_dissectDomain_By_KX_record(t *testing.T) {
	// Setup.
	record := &dns.KX{
		Hdr:    dns.RR_Header{Name: "example.com", Rrtype: dns.TypeKX},
		Exchanger: "related.example.com.",
	}

	// Execute.
	domain := dissectDomain(record)

	// Assert.
	assert.Equal(t, "related.example.com", domain)
}

func Test_dissectDomain_By_unsupported_record(t *testing.T) {
	// Setup.
	record := &dns.MB{
		Hdr:    dns.RR_Header{Name: "example.com", Rrtype: dns.TypeMB},
		Mb: "related.example.com.",
	}

	// Execute.
	domain := dissectDomain(record)

	// Assert.
	assert.Empty(t, domain)
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

func mockDnsResponse(qType uint16, numRecords int) *dns.Msg {
	msg := &dns.Msg{}

	for i := 0; i < numRecords; i++ {
		rrNewFun := dns.TypeToRR[qType]
		rr := rrNewFun()
		rr.Header().Rrtype = qType
		msg.Answer = append(msg.Answer, rr)
	}

	return msg
}
