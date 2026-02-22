package udig

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
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
	resolver := NewDNSResolver(DefaultTimeout)

	// Execute.
	resolution := resolver.ResolveDomain("all.tens.ten").(*DNSResolution)

	// Assert.

	// 1 invocation per DNS query type + 1 DMARC query + 2 NS queries for all.tens.ten + tens.ten.
	assert.Equal(t, len(DefaultDNSQueryTypes)+3, invocationCount)

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
	resolver := NewDNSResolver(DefaultTimeout)
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
	resolver := NewDNSResolver(DefaultTimeout)
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
	resolver := NewDNSResolver(DefaultTimeout)

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
	resolver := NewDNSResolver(DefaultTimeout)

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

func Test_dissectDomain_By_CAA_iodef_record(t *testing.T) {
	// Setup.
	record := &dns.CAA{
		Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA},
		Flag:  0,
		Tag:   "iodef",
		Value: "mailto:security@reporting.example.com",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert.
	assert.Contains(t, domains, "reporting.example.com")
}

func Test_dissectDomain_By_CAA_issue_record_yields_no_domains(t *testing.T) {
	// Setup.
	record := &dns.CAA{
		Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA},
		Flag:  0,
		Tag:   "issue",
		Value: "letsencrypt.org",
	}

	// Execute.
	domains := dissectDomainsFromRecord(record)

	// Assert: issue tag values are CA names, not crawl targets.
	assert.Empty(t, domains)
}

func Test_DnssecSigned_true_when_DNSKEY_present(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		if qType == dns.TypeDNSKEY {
			return mockDNSResponse(dns.TypeDNSKEY, 1), nil
		}
		return &dns.Msg{}, nil
	}

	// Setup.
	resolver := NewDNSResolver(DefaultTimeout)
	resolver.NameServer = "1.1.1.1"

	// Execute.
	resolution := resolver.ResolveDomain("example.com").(*DNSResolution)

	// Assert.
	assert.True(t, resolution.DnssecSigned)
}

func Test_DMARC_fields_parsed_from_dmarc_TXT(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		if strings.HasPrefix(domain, "_dmarc.") && qType == dns.TypeTXT {
			msg := &dns.Msg{}
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: "_dmarc.example.com.", Rrtype: dns.TypeTXT},
				Txt: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@vendor.com; ruf=mailto:forensic@vendor.com"},
			})
			return msg, nil
		}
		return &dns.Msg{}, nil
	}

	// Setup.
	resolver := NewDNSResolver(DefaultTimeout)
	resolver.NameServer = "1.1.1.1"

	// Execute.
	resolution := resolver.ResolveDomain("example.com").(*DNSResolution)

	// Assert.
	assert.Equal(t, "reject", resolution.DMARCPolicy)
	assert.Contains(t, resolution.DMARCRua, "mailto:dmarc@vendor.com")
	assert.Contains(t, resolution.DMARCRuf, "mailto:forensic@vendor.com")
	assert.Contains(t, resolution.Domains(), "vendor.com")
}

func Test_DnssecSigned_false_when_no_DS_or_DNSKEY(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		if qType == dns.TypeA {
			return mockDNSResponse(dns.TypeA, 1), nil
		}
		return &dns.Msg{}, nil
	}

	// Setup.
	resolver := NewDNSResolver(DefaultTimeout)
	resolver.NameServer = "1.1.1.1"

	// Execute.
	resolution := resolver.ResolveDomain("example.com").(*DNSResolution)

	// Assert.
	assert.False(t, resolution.DnssecSigned)
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
	parent := ParentDomainOf(domain)

	// Assert.
	assert.Equal(t, "example.com", parent)
}

func Test_parentDomainOf_By_domain(t *testing.T) {
	// Setup.
	domain := "example.com"

	// Execute.
	parent := ParentDomainOf(domain)

	// Assert.
	assert.Empty(t, parent)
}

func Test_parentDomainOf_By_TLD(t *testing.T) {
	// Setup.
	domain := "com"

	// Execute.
	parent := ParentDomainOf(domain)

	// Assert.
	assert.Empty(t, parent)
}

func Test_dissectIPsFromRecord_By_A_record(t *testing.T) {
	record := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
		A:   net.ParseIP("192.0.2.1"),
	}
	ips := dissectIPsFromRecord(record)
	assert.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.1", ips[0])
}

func Test_dissectIPsFromRecord_By_AAAA_record(t *testing.T) {
	record := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA},
		AAAA: net.ParseIP("2001:db8::1"),
	}
	ips := dissectIPsFromRecord(record)
	assert.Len(t, ips, 1)
	assert.Equal(t, "2001:db8::1", ips[0])
}

func Test_dissectIPsFromRecord_By_TXT_record_with_IPs(t *testing.T) {
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT},
		Txt: []string{"v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.1 -all"},
	}
	ips := dissectIPsFromRecord(record)
	assert.GreaterOrEqual(t, len(ips), 1)
	assert.Contains(t, ips, "198.51.100.1")
}

func Test_DNSResolution_IPs_aggregatesFromRecords(t *testing.T) {
	res := &DNSResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Records: []DNSRecordPair{
			{QueryType: dns.TypeA, Record: &DNSRecord{RR: &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
				A:   net.ParseIP("192.0.2.1"),
			}}},
		},
	}
	ips := res.IPs()
	assert.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.1", ips[0])
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
