package udig

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_DMARCResolver_ResolveDomain_returnsParsedDMARC(t *testing.T) {
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "_dmarc.example.com.", Rrtype: dns.TypeTXT},
			Txt: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@vendor.com; ruf=mailto:forensic@vendor.com"},
		})
		return msg, nil
	}
	defer func() { queryOneCallback = queryOne }()

	resolver := NewDMARCResolver(DefaultTimeout)
	resolutions := resolver.ResolveDomain("example.com")

	assert.Len(t, resolutions, 1)
	dmarcRes := resolutions[0].(*DMARCResolution)
	assert.Equal(t, TypeDMARC, dmarcRes.Type())
	assert.Equal(t, "example.com", dmarcRes.Query())
	assert.Equal(t, "reject", dmarcRes.Record.DMARCPolicy)
	assert.Contains(t, dmarcRes.Record.DMARCRua, "mailto:dmarc@vendor.com")
	assert.Contains(t, dmarcRes.Record.DMARCRuf, "mailto:forensic@vendor.com")
	assert.Contains(t, dmarcRes.Domains(), "vendor.com")
}

func Test_DMARCResolver_ResolveDomain_noDMARC_returnsEmpty(t *testing.T) {
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		return &dns.Msg{}, nil
	}
	defer func() { queryOneCallback = queryOne }()

	resolver := NewDMARCResolver(DefaultTimeout)
	resolutions := resolver.ResolveDomain("example.com")
	assert.Empty(t, resolutions)
}

func Test_DMARCResolver_Type_returnsTypeDMARC(t *testing.T) {
	resolver := NewDMARCResolver(DefaultTimeout)
	assert.Equal(t, TypeDMARC, resolver.Type())
}

func Test_parseDMARC_multipleRua(t *testing.T) {
	policy, rua, ruf := parseDMARC("v=DMARC1; p=quarantine; rua=mailto:a@x.com,mailto:b@y.com")
	assert.Equal(t, "quarantine", policy)
	assert.Len(t, rua, 2)
	assert.Empty(t, ruf)
}

func Test_parseDMARC_empty(t *testing.T) {
	policy, rua, ruf := parseDMARC("")
	assert.Empty(t, policy)
	assert.Empty(t, rua)
	assert.Empty(t, ruf)
}

func Test_DMARCRecord_String(t *testing.T) {
	r := DMARCRecord{
		DMARCPolicy: "reject",
		DMARCRua:    []string{"mailto:a@example.com"},
	}
	s := r.String()
	assert.Contains(t, s, "p=reject")
	assert.Contains(t, s, "rua=")
}
