package udig

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_PTRResolver_ResolveIP_mockedCallback_returnsHostnames(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: domain + ".", Rrtype: dns.TypePTR},
			Ptr: "mail.example.com.",
		})
		return msg, nil
	}

	// Setup.
	resolver := NewPTRResolver(DefaultTimeout)

	// Execute.
	resolution := resolver.ResolveIP("104.18.26.120").(*PTRResolution)

	// Assert.
	assert.Len(t, resolution.Hostnames, 1)
	assert.Equal(t, "mail.example.com", resolution.Hostnames[0])
	assert.Contains(t, resolution.Domains(), "mail.example.com")
}

func Test_PTRResolver_ResolveIP_invalidIP_returnsEmpty(t *testing.T) {
	// Setup.
	resolver := NewPTRResolver(DefaultTimeout)

	// Execute.
	resolution := resolver.ResolveIP("not-an-ip").(*PTRResolution)

	// Assert.
	assert.Empty(t, resolution.Hostnames)
}

func Test_PTRResolver_ResolveIP_nxdomain_returnsEmpty(t *testing.T) {
	// Mock.
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		return nil, dns.ErrId
	}

	// Setup.
	resolver := NewPTRResolver(DefaultTimeout)

	// Execute.
	resolution := resolver.ResolveIP("192.0.2.1").(*PTRResolution)

	// Assert.
	assert.Empty(t, resolution.Hostnames)
}

func Test_PTRResolver_Type_returnsTypePTR(t *testing.T) {
	resolver := NewPTRResolver(DefaultTimeout)
	assert.Equal(t, TypePTR, resolver.Type())
}

func Test_PTRResolution_Type_returnsTypePTR(t *testing.T) {
	resolution := &PTRResolution{ResolutionBase: &ResolutionBase{query: "1.2.3.4"}}
	assert.Equal(t, TypePTR, resolution.Type())
}
