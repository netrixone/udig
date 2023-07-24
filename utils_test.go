package udig

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_DissectDomainsFrom_By_simple_domain(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("example.com")

	// Assert.
	assert.Len(t, domains, 1)
	assert.Equal(t, "example.com", domains[0])
}

func Test_DissectDomainsFrom_By_subdomain(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("example.domain-hyphen.com")

	// Assert.
	assert.Len(t, domains, 1)
	assert.Equal(t, "example.domain-hyphen.com", domains[0])
}

func Test_DissectDomainsFrom_By_www_subdomain(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("www.example.domain-hyphen.com")

	// Assert.
	assert.Len(t, domains, 1)
	assert.Equal(t, "example.domain-hyphen.com", domains[0])
}

func Test_DissectDomainsFrom_By_exotic_tld(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("www.example.domain-hyphen.museum")

	// Assert.
	assert.Len(t, domains, 1)
	assert.Equal(t, "example.domain-hyphen.museum", domains[0])
}

func Test_DissectDomainsFrom_By_complex_domain(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("external.asd1230-123.asd_internal.asd.gm-_ail.aero")

	// Assert.
	assert.Len(t, domains, 1)
	assert.Equal(t, "external.asd1230-123.asd_internal.asd.gm-_ail.aero", domains[0])
}

func Test_DissectDomainsFrom_By_complex_url_in_text(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("Hello world: https://user:password@external.asd1230-123.asd_internal.asd.gm-_ail.aero:8080/foo/bar.html is really cool\nURL")

	// Assert.
	assert.Len(t, domains, 1)
	assert.Equal(t, "external.asd1230-123.asd_internal.asd.gm-_ail.aero", domains[0])
}

func Test_DissectDomainsFrom_By_multiple_urls(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("Hello world: https://user:password@external.asd1230-123.asd_internal.asd.gm-_ail.aero:8080/foo/bar.html is really cool\nURL and this is another one http://www.foo-bar_baz.co")

	// Assert.
	assert.Len(t, domains, 2)
	assert.Equal(t, "external.asd1230-123.asd_internal.asd.gm-_ail.aero", domains[0])
	assert.Equal(t, "foo-bar_baz.co", domains[1])
}

func Test_DissectDomainsFrom_By_invalid_domain(t *testing.T) {
	// Execute.
	domains := dissectDomainsFromString("bad.-example.com")

	// Assert.
	assert.Len(t, domains, 1)
	assert.Equal(t, "example.com", domains[0])
}

func Test_isDomainRelated_By_same_domain(t *testing.T) {
	// Setup.
	domainA := "example.com"
	domainB := domainA

	// Execute.
	res1 := isDomainRelated(domainA, domainB, false)
	res2 := isDomainRelated(domainB, domainA, false)

	// Assert.
	assert.Equal(t, true, res1)
	assert.Equal(t, true, res2)
}

func Test_isDomainRelated_By_subdomain(t *testing.T) {
	// Setup.
	domainA := "example.com"
	domainB := "sub.example.com"

	// Execute.
	res1 := isDomainRelated(domainA, domainB, false)
	res2 := isDomainRelated(domainB, domainA, false)

	// Assert.
	assert.Equal(t, true, res1)
	assert.Equal(t, true, res2)
}

func Test_isDomainRelated_By_domain_with_different_TLD(t *testing.T) {
	// Setup.
	domainA := "example.com"
	domainB := "sub.example.net"

	// Execute.
	res1 := isDomainRelated(domainA, domainB, false)
	res2 := isDomainRelated(domainB, domainA, false)

	// Assert.
	assert.Equal(t, true, res1)
	assert.Equal(t, true, res2)
}

func Test_isDomainRelated_By_domain_with_different_TLD_strict(t *testing.T) {
	// Setup.
	domainA := "example.com"
	domainB := "sub.example.net"

	// Execute.
	res1 := isDomainRelated(domainA, domainB, true)
	res2 := isDomainRelated(domainB, domainA, true)

	// Assert.
	assert.Equal(t, false, res1)
	assert.Equal(t, false, res2)
}

func Test_isDomainRelated_By_TLDs(t *testing.T) {
	// Setup.
	domainA := "com"
	domainB := "com"

	// Execute.
	res := isDomainRelated(domainA, domainB, false)

	// Assert.
	assert.Equal(t, false, res)
}

func Test_isDomainRelated_By_invalid_domain(t *testing.T) {
	// Setup.
	domainA := "."
	domainB := "example.com"

	// Execute.
	res1 := isDomainRelated(domainA, domainB, false)
	res2 := isDomainRelated(domainB, domainA, false)

	// Assert.
	assert.Equal(t, false, res1)
	assert.Equal(t, false, res2)
}
