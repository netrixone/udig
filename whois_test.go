package udig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseWhoisResponse_emptyInput_returnsNoContacts(t *testing.T) {
	contacts := parseWhoisResponse(strings.NewReader(""))
	assert.Empty(t, contacts)
}

func Test_parseWhoisResponse_stopsAtLastUpdateLine(t *testing.T) {
	input := "domain: example.com\nregistrar: foobar\n>>> Last update of WHOIS database: 2020-01-01 <<<\n\nlegal text"
	contacts := parseWhoisResponse(strings.NewReader(input))
	assert.Len(t, contacts, 1)
	assert.Equal(t, "foobar", contacts[0].Registrar)
}

func Test_parseWhoisResponse_parsesKeyValuePairs(t *testing.T) {
	input := "registry domain id: RID-1\nregistrant: Acme Inc\nregistrant country: US\n>>> Last update of WHOIS database: 2020-01-01 <<<"
	contacts := parseWhoisResponse(strings.NewReader(input))
	assert.Len(t, contacts, 1)
	// Parser lowercases keys and values
	assert.Equal(t, "rid-1", contacts[0].RegistryDomainId)
	assert.Equal(t, "acme inc", contacts[0].Registrant)
	assert.Equal(t, "us", contacts[0].RegistrantCountry)
}

func Test_parseWhoisResponse_skipsCommentLines(t *testing.T) {
	input := "% Comment line\nregistrar: test\n>>> Last update of WHOIS database: 2020-01-01 <<<"
	contacts := parseWhoisResponse(strings.NewReader(input))
	assert.Len(t, contacts, 1)
	assert.Equal(t, "test", contacts[0].Registrar)
}

func Test_parseWhoisResponse_emptyLineStartsNewContact(t *testing.T) {
	input := "registrar: first\n\nregistrar: second\n>>> Last update of WHOIS database: 2020-01-01 <<<"
	contacts := parseWhoisResponse(strings.NewReader(input))
	assert.Len(t, contacts, 2)
	assert.Equal(t, "first", contacts[0].Registrar)
	assert.Equal(t, "second", contacts[1].Registrar)
}

func Test_WhoisContact_IsEmpty(t *testing.T) {
	var c WhoisContact
	assert.True(t, c.IsEmpty())
	c.Registrar = "x"
	assert.False(t, c.IsEmpty())
}

func Test_WhoisContact_String(t *testing.T) {
	c := WhoisContact{
		Registrar:  "TestReg",
		Registrant: "Acme",
		Expire:     "2025-01-01",
	}
	s := c.String()
	assert.Contains(t, s, "TestReg")
	assert.Contains(t, s, "Acme")
	assert.Contains(t, s, "2025-01-01")
}

func Test_WhoisResolution_Domains_extractsFromContacts(t *testing.T) {
	res := &WhoisResolution{
		ResolutionBase: &ResolutionBase{query: "example.com"},
		Contacts: []WhoisContact{
			{RegistrarWhoisServer: "whois.example.com", RegistrarUrl: "https://reg.example.com"},
		},
	}
	domains := res.Domains()
	assert.NotEmpty(t, domains)
	assert.Contains(t, domains, "whois.example.com")
	assert.Contains(t, domains, "reg.example.com")
}
