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

func Test_When_DnsResolver_Resolve_completes_Then_NameServer_is_reset(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		return &dns.Msg{}, nil
	}

	// Setup.
	resolver := NewDnsResolver()
	assert.Empty(t, resolver.NameServer)

	// Execute.
	resolver.Resolve("example.com")

	// Assert.
	assert.Empty(t, resolver.NameServer)
}

func Test_When_DnsResolver_Resolve_completes_Then_custom_NameServer_is_kept(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		return &dns.Msg{}, nil
	}

	// Setup.
	resolver := NewDnsResolver()
	resolver.NameServer = "1.1.1.1"

	// Execute.
	resolver.Resolve("example.com")

	// Assert.
	assert.Equal(t, resolver.NameServer, "1.1.1.1")
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
			t.Error("Not mocked.")
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
