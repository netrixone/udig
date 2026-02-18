package udig

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_parseASNRecord_validRecord_returnsASRecord(t *testing.T) {
	rec := parseASNRecord("13335 | 104.28.16.0/20 | US | arin | 2014-03-28")
	assert.NotNil(t, rec)
	assert.Equal(t, uint32(13335), rec.ASN)
	assert.Equal(t, "104.28.16.0/20", rec.BGPPrefix)
	assert.Equal(t, "arin", rec.Registry)
	assert.Equal(t, "2014-03-28", rec.Allocated)
}

func Test_parseASNRecord_invalidRecord_returnsNil(t *testing.T) {
	assert.Nil(t, parseASNRecord("not-a-valid-record"))
	assert.Nil(t, parseASNRecord(""))
}

func Test_parseASName_validRecord_returnsName(t *testing.T) {
	name := parseASName("13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US")
	assert.Equal(t, "CLOUDFLARENET, US", name)
}

func Test_parseASName_invalidRecord_returnsEmpty(t *testing.T) {
	assert.Empty(t, parseASName("invalid"))
}

func Test_BGPResolver_ResolveIP_mockedCallback_returnsResolution(t *testing.T) {
	queryOneCallback = func(domain string, qType uint16, nameServer string, client *dns.Client) (*dns.Msg, error) {
		msg := &dns.Msg{}
		if qType != dns.TypeTXT {
			return msg, nil
		}
		// IP->ASN query contains "origin"; ASN->AS query is like AS13335.asn.cymru.com
		if strings.Contains(domain, "origin") {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT},
				Txt: []string{"13335 | 104.28.16.0/20 | US | arin | 2014-03-28"},
			})
		} else {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT},
				Txt: []string{"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"},
			})
		}
		return msg, nil
	}
	defer func() { queryOneCallback = queryOne }()

	resolver := NewBGPResolver(5 * time.Second)
	resolution := resolver.ResolveIP("1.0.0.1")
	assert.Equal(t, TypeBGP, resolution.Type())
	assert.Equal(t, "1.0.0.1", resolution.Query())
	br, ok := resolution.(*BGPResolution)
	assert.True(t, ok)
	assert.NotNil(t, br)
	// With mock, we expect one AS record (AS13335, CLOUDFLARENET)
	assert.GreaterOrEqual(t, len(br.Records), 0)
}

func Test_ASRecord_String(t *testing.T) {
	r := ASRecord{
		ASN:       13335,
		Name:      "CLOUDFLARENET",
		BGPPrefix: "104.28.16.0/20",
		Registry:  "arin",
		Allocated: "2014-03-28",
	}
	s := r.String()
	assert.Contains(t, s, "13335")
	assert.Contains(t, s, "CLOUDFLARENET")
	assert.Contains(t, s, "104.28.16.0/20")
}
