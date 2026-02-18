package udig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// stubResolution implements Resolution for testing.
type stubResolution struct {
	query   string
	typ     ResolutionType
	domains []string
	ips     []string
}

func (s *stubResolution) Query() string        { return s.query }
func (s *stubResolution) Type() ResolutionType { return s.typ }
func (s *stubResolution) Domains() []string   { return s.domains }
func (s *stubResolution) IPs() []string      { return s.ips }

// stubDomainResolver returns a fixed resolution for any domain.
type stubDomainResolver struct {
	res *stubResolution
}

func (r *stubDomainResolver) ResolveDomain(domain string) Resolution {
	out := *r.res
	out.query = domain
	return &out
}

// stubIPResolver returns a fixed resolution for any IP.
type stubIPResolver struct {
	typ ResolutionType
}

func (r *stubIPResolver) ResolveIP(ip string) Resolution {
	return &stubResolution{query: ip, typ: r.typ, domains: nil, ips: nil}
}

func Test_NewEmptyUdig_ApplyOptions_ThenResolve_returnsResolverResults(t *testing.T) {
	udig := NewEmptyUdig(
		WithTimeout(5*time.Second),
		WithStrictMode(),
	)
	udig.(*udigImpl).AddDomainResolver(&stubDomainResolver{
		res: &stubResolution{typ: TypeHTTP, domains: nil, ips: nil},
	})
	resolutions := udig.Resolve("example.com")
	assert.Len(t, resolutions, 1)
	assert.Equal(t, TypeHTTP, resolutions[0].Type())
	assert.Equal(t, "example.com", resolutions[0].Query())
}

func Test_NewEmptyUdig_WithRelatedDomains_enqueuesAndResolvesRelated(t *testing.T) {
	udig := NewEmptyUdig(WithTimeout(5 * time.Second))
	udig.(*udigImpl).AddDomainResolver(&stubDomainResolver{
		res: &stubResolution{
			typ:     TypeHTTP,
			domains: []string{"sub.example.com"},
			ips:     nil,
		},
	})
	resolutions := udig.Resolve("example.com")
	// Initial domain + related sub.example.com
	assert.GreaterOrEqual(t, len(resolutions), 1)
	queries := make(map[string]bool)
	for _, r := range resolutions {
		queries[r.Query()] = true
	}
	assert.True(t, queries["example.com"])
	assert.True(t, queries["sub.example.com"])
}

func Test_NewEmptyUdig_WithIPsFromDomain_enqueuesAndResolvesIPs(t *testing.T) {
	udig := NewEmptyUdig(WithTimeout(5 * time.Second))
	udig.(*udigImpl).AddDomainResolver(&stubDomainResolver{
		res: &stubResolution{
			typ:     TypeHTTP,
			domains: nil,
			ips:     []string{"192.0.2.1"},
		},
	})
	udig.(*udigImpl).AddIPResolver(&stubIPResolver{typ: TypeBGP})
	resolutions := udig.Resolve("example.com")
	// At least domain resolution + one IP resolution (BGP)
	assert.GreaterOrEqual(t, len(resolutions), 2)
	var foundIP bool
	for _, r := range resolutions {
		if r.Query() == "192.0.2.1" {
			foundIP = true
			break
		}
	}
	assert.True(t, foundIP)
}

func Test_NewUdig_returnsNonEmptyResolvers(t *testing.T) {
	udig := NewUdig(WithTimeout(100 * time.Millisecond))
	impl := udig.(*udigImpl)
	assert.NotEmpty(t, impl.domainResolvers)
	assert.NotEmpty(t, impl.ipResolvers)
}
