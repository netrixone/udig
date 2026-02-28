package udig

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_TLSResolver_Type_returnsTypeTLS(t *testing.T) {
	r := NewTLSResolver(10 * time.Second)
	assert.Equal(t, TypeTLS, r.Type())
}

func Test_TLSResolver_ResolveDomain_invalidDomain_returnsEmpty(t *testing.T) {
	r := NewTLSResolver(5 * time.Second)
	resolutions := r.ResolveDomain("invalid.domain.invalid.example.invalid")
	assert.Empty(t, resolutions)
}

func Test_TLSResolution_Domains_fromCertWithDNSNames(t *testing.T) {
	cert := TLSCertificate{}
	cert.DNSNames = []string{"example.com", "www.example.com"}
	res := &TLSResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Record:         cert,
	}
	domains := res.Domains()
	assert.Contains(t, domains, "example.com")
	assert.GreaterOrEqual(t, len(domains), 1)
}

func Test_TLSCertificate_String(t *testing.T) {
	cert := TLSCertificate{}
	cert.Subject = pkix.Name{CommonName: "cn.example.com"}
	cert.Issuer = pkix.Name{CommonName: "CA"}
	cert.DNSNames = []string{"cn.example.com"}
	s := cert.String()
	assert.Contains(t, s, "cn.example.com")
	assert.Contains(t, s, "CA")
}
