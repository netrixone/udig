package udig

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Test_DNSBLResolver_ResolveIP_nxdomain verifies that NXDOMAIN responses
// yield an empty results slice (IP is not listed).
func Test_DNSBLResolver_ResolveIP_nxdomain_returnsNotListed(t *testing.T) {
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		return nil, fmt.Errorf("NXDOMAIN")
	}
	defer func() { queryOneCallback = queryOne }()

	resolver := NewDNSBLResolver(5 * time.Second)
	resolutions := resolver.ResolveIP("1.2.3.4")

	assert.Empty(t, resolutions)
}

// Test_DNSBLResolver_ResolveIP_invalidIP verifies that an invalid IP returns
// nil without panicking.
func Test_DNSBLResolver_ResolveIP_invalidIP_returnsEmpty(t *testing.T) {
	resolver := NewDNSBLResolver(5 * time.Second)
	resolutions := resolver.ResolveIP("not-an-ip")

	assert.Nil(t, resolutions)
}

// Test_DNSBLResolver_ResolveIP_allZonesQueried verifies all default zones are
// queried in parallel; shared callback state is protected by a mutex.
func Test_DNSBLResolver_ResolveIP_allZonesQueried(t *testing.T) {
	var mu sync.Mutex
	calledZones := make(map[string]bool)

	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		mu.Lock()
		for _, zone := range defaultDNSBLZones {
			if strings.Contains(domain, zone) {
				calledZones[zone] = true
			}
		}
		mu.Unlock()
		return nil, fmt.Errorf("NXDOMAIN")
	}
	defer func() { queryOneCallback = queryOne }()

	resolver := NewDNSBLResolver(5 * time.Second)
	resolver.ResolveIP("5.6.7.8")

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, calledZones, len(defaultDNSBLZones), "all zones should be queried")
	for _, zone := range defaultDNSBLZones {
		assert.True(t, calledZones[zone], "zone %s should have been queried", zone)
	}
}

// Test_isDNSBLMetaCode verifies that service error/quota codes are detected
// and that normal listing codes are not mis-classified.
func Test_isDNSBLMetaCode(t *testing.T) {
	// Meta codes — should NOT become listings.
	assert.True(t, isDNSBLMetaCode("127.255.255.254"), "query limit exceeded")
	assert.True(t, isDNSBLMetaCode("127.255.255.255"), "unknown/error")
	assert.True(t, isDNSBLMetaCode("127.255.255.253"), "internal error")
	assert.True(t, isDNSBLMetaCode("127.255.255.252"), "timeout")

	// Real listing codes — must NOT be filtered.
	assert.False(t, isDNSBLMetaCode("127.0.0.2"))
	assert.False(t, isDNSBLMetaCode("127.0.0.9"))
	assert.False(t, isDNSBLMetaCode("127.0.0.10"))
}

// Test_DNSBLResolver_ResolveIP_metaCode verifies that a meta return code
// (e.g. query limit exceeded) does not produce a listing resolution.
func Test_DNSBLResolver_ResolveIP_metaCode_returnsEmpty(t *testing.T) {
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP("127.255.255.254"),
		})
		return msg, nil
	}
	defer func() { queryOneCallback = queryOne }()

	resolver := NewDNSBLResolver(5 * time.Second)
	resolutions := resolver.ResolveIP("1.2.3.4")

	assert.Empty(t, resolutions)
}

// Test_DNSBLRecord_String verifies the string representation of a record.
func Test_DNSBLRecord_String(t *testing.T) {
	r := DNSBLRecord{
		Zone:       "zen.spamhaus.org",
		ReturnCode: "127.0.0.2",
		Listed:     true,
		Meaning:    "SBL",
	}
	s := r.String()
	assert.Contains(t, s, "zen.spamhaus.org")
	assert.Contains(t, s, "127.0.0.2")
	assert.Contains(t, s, "SBL")
}

// Test_DNSBLResolver_ResolveIP_knownListed_integration verifies that the
// standard DNSBL test address 127.0.0.2 is listed in at least one configured
// zone using the real system resolver.
func Test_DNSBLResolver_ResolveIP_knownListed_integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	resolver := NewDNSBLResolver(5 * time.Second)
	resolutions := resolver.ResolveIP("127.0.0.2")

	assert.NotEmpty(t, resolutions, "127.0.0.2 should be listed in at least one DNSBL zone")
}

// Test_DNSBLResolver_Type verifies the resolver type constant.
func Test_DNSBLResolver_Type_returnsTypeDNSBL(t *testing.T) {
	resolver := NewDNSBLResolver(5 * time.Second)
	assert.Equal(t, TypeDNSBL, resolver.Type())
}

// Test_DNSBLResolution_Type verifies the resolution type constant.
func Test_DNSBLResolution_Type_returnsTypeDNSBL(t *testing.T) {
	resolution := &DNSBLResolution{ResolutionBase: &ResolutionBase{query: "1.2.3.4"}}
	assert.Equal(t, TypeDNSBL, resolution.Type())
}
