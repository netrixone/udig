package udig

import (
	"strings"
)

/////////////////////////////////////////
// WHOIS RESOLUTION
/////////////////////////////////////////

// WhoisResolution is a single WHOIS contact result (denormalized: one contact per resolution).
type WhoisResolution struct {
	*ResolutionBase
	Record WhoisContact
}

// Type returns "WHOIS".
func (r *WhoisResolution) Type() ResolutionType {
	return TypeWHOIS
}

// Domains returns domains discovered in this single WHOIS contact.
func (r *WhoisResolution) Domains() (domains []string) {
	c := r.Record
	domains = append(domains, DissectDomainsFromString(c.RegistryDomainId)...)
	domains = append(domains, DissectDomainsFromString(c.Registrant)...)
	domains = append(domains, DissectDomainsFromString(c.RegistrantOrganization)...)
	domains = append(domains, DissectDomainsFromString(c.RegistrantStateProvince)...)
	domains = append(domains, DissectDomainsFromString(c.RegistrantCountry)...)
	domains = append(domains, DissectDomainsFromString(c.Registrar)...)
	domains = append(domains, DissectDomainsFromString(c.RegistrarIanaId)...)
	domains = append(domains, DissectDomainsFromString(c.RegistrarWhoisServer)...)
	domains = append(domains, DissectDomainsFromString(c.RegistrarUrl)...)
	domains = append(domains, DissectDomainsFromString(c.CreationDate)...)
	domains = append(domains, DissectDomainsFromString(c.UpdatedDate)...)
	domains = append(domains, DissectDomainsFromString(c.Registered)...)
	domains = append(domains, DissectDomainsFromString(c.Changed)...)
	domains = append(domains, DissectDomainsFromString(c.Expire)...)
	domains = append(domains, DissectDomainsFromString(c.NSSet)...)
	domains = append(domains, DissectDomainsFromString(c.Contact)...)
	domains = append(domains, DissectDomainsFromString(c.Name)...)
	domains = append(domains, DissectDomainsFromString(c.Address)...)
	return domains
}

/////////////////////////////////////////
// WHOIS CONTACT
/////////////////////////////////////////

// WhoisContact is a wrapper for any item of interest from a WHOIS banner.
type WhoisContact struct {
	RegistryDomainId        string
	Registrant              string
	RegistrantOrganization  string
	RegistrantStateProvince string
	RegistrantCountry       string
	Registrar               string
	RegistrarIanaId         string
	RegistrarWhoisServer    string
	RegistrarUrl            string
	CreationDate            string
	UpdatedDate             string
	Registered              string
	Changed                 string
	Expire                  string
	NSSet                   string
	Contact                 string
	Name                    string
	Address                 string
}

func (c *WhoisContact) IsEmpty() bool {
	return c.RegistryDomainId == "" &&
		c.Registrant == "" &&
		c.RegistrantOrganization == "" &&
		c.RegistrantStateProvince == "" &&
		c.RegistrantCountry == "" &&
		c.Registrar == "" &&
		c.RegistrarIanaId == "" &&
		c.RegistrarWhoisServer == "" &&
		c.RegistrarUrl == "" &&
		c.CreationDate == "" &&
		c.UpdatedDate == "" &&
		c.Registered == "" &&
		c.Changed == "" &&
		c.Expire == "" &&
		c.NSSet == "" &&
		c.Contact == "" &&
		c.Name == "" &&
		c.Address == ""
}

func (c WhoisContact) String() string {
	var entries []string

	if c.RegistryDomainId != "" {
		entries = append(entries, "registry domain id: "+c.RegistryDomainId)
	}
	if c.Registrant != "" {
		entries = append(entries, "registrant: "+c.Registrant)
	}
	if c.RegistrantOrganization != "" {
		entries = append(entries, "registrant organization: "+c.RegistrantOrganization)
	}
	if c.RegistrantStateProvince != "" {
		entries = append(entries, "registrant state/province: "+c.RegistrantStateProvince)
	}
	if c.RegistrantCountry != "" {
		entries = append(entries, "registrant country: "+c.RegistrantCountry)
	}
	if c.Registrar != "" {
		entries = append(entries, "registrar: "+c.Registrar)
	}
	if c.RegistrarIanaId != "" {
		entries = append(entries, "registrar iana id: "+c.RegistrarIanaId)
	}
	if c.RegistrarWhoisServer != "" {
		entries = append(entries, "registrar whois server: "+c.RegistrarWhoisServer)
	}
	if c.RegistrarUrl != "" {
		entries = append(entries, "registrar url: "+c.RegistrarUrl)
	}
	if c.CreationDate != "" {
		entries = append(entries, "creation date: "+c.CreationDate)
	}
	if c.UpdatedDate != "" {
		entries = append(entries, "updated date: "+c.UpdatedDate)
	}
	if c.Registered != "" {
		entries = append(entries, "registered: "+c.Registered)
	}
	if c.Changed != "" {
		entries = append(entries, "changed: "+c.Changed)
	}
	if c.Expire != "" {
		entries = append(entries, "expire: "+c.Expire)
	}
	if c.NSSet != "" {
		entries = append(entries, "nsset: "+c.NSSet)
	}
	if c.Contact != "" {
		entries = append(entries, "c: "+c.Contact)
	}
	if c.Name != "" {
		entries = append(entries, "name: "+c.Name)
	}
	if c.Address != "" {
		entries = append(entries, "address: "+c.Address)
	}

	return strings.Join(entries, ", ")
}
