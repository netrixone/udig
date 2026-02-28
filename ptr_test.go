package udig

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_PTRResolver_ResolveIP_mockedCallback_returnsHostnames(t *testing.T) {
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: domain + ".", Rrtype: dns.TypePTR},
			Ptr: "mail.example.com.",
		})
		return msg, nil
	}

	resolver := NewPTRResolver(DefaultTimeout)
	resolutions := resolver.ResolveIP("104.18.26.120")

	assert.Len(t, resolutions, 1)
	ptrRes := resolutions[0].(*PTRResolution)
	assert.Equal(t, "mail.example.com", ptrRes.Record.Hostname)
	assert.Contains(t, ptrRes.Domains(), "mail.example.com")
}

func Test_PTRResolver_ResolveIP_invalidIP_returnsEmpty(t *testing.T) {
	resolver := NewPTRResolver(DefaultTimeout)
	resolutions := resolver.ResolveIP("not-an-ip")
	assert.Empty(t, resolutions)
}

func Test_PTRResolver_ResolveIP_nxdomain_returnsEmpty(t *testing.T) {
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		return nil, dns.ErrId
	}

	resolver := NewPTRResolver(DefaultTimeout)
	resolutions := resolver.ResolveIP("192.0.2.1")
	assert.Empty(t, resolutions)
}

func Test_PTRResolver_Type_returnsTypePTR(t *testing.T) {
	resolver := NewPTRResolver(DefaultTimeout)
	assert.Equal(t, TypePTR, resolver.Type())
}

func Test_PTRResolution_Type_returnsTypePTR(t *testing.T) {
	resolution := &PTRResolution{ResolutionBase: &ResolutionBase{query: "1.2.3.4"}, Record: PTRRecord{Hostname: "host.example.com"}}
	assert.Equal(t, TypePTR, resolution.Type())
}
